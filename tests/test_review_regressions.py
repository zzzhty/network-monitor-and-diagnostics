"""Independent review regressions; temporary files and loopback traffic only."""
import http.server
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import nmd_monitor


class ReviewRegressions(unittest.TestCase):
    @unittest.skipUnless(Path('/usr/bin/curl').exists(), 'curl unavailable')
    def test_http_target_is_literal_not_curl_url_glob(self):
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(nmd_monitor.nmd_platform, 'sample_local', return_value={'status': 'unknown', 'error': 'fixture_only'}):
                result = nmd_monitor.sample_probe({'probes': [dict(
                    id='literal', type='http',
                    target=f'http://127.0.0.1:{server.server_port}/{{a,b}}')]})
            self.assertEqual(requests, ['/{a,b}'])
            self.assertEqual(result[-1]['status'], 'success')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_symlink_ancestor_cannot_redirect_state(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'real').mkdir(mode=0o700)
            (base / 'alias').symlink_to(base / 'real', target_is_directory=True)
            with self.assertRaises(ValueError):
                nmd_monitor.Store(base / 'alias' / 'new-state', {})
            self.assertFalse((base / 'real' / 'new-state').exists())

    def test_mkdir_substitution_cannot_redirect_database(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state, foreign = base / 'state', base / 'foreign'
            foreign.mkdir(mode=0o700)
            mkdir = os.mkdir
            def substitute(path, *args, **kwargs):
                result = mkdir(path, *args, **kwargs)
                if path == 'state':
                    state.rename(base / 'original')
                    state.symlink_to(foreign, target_is_directory=True)
                return result
            with patch.object(nmd_monitor.os, 'mkdir', side_effect=substitute):
                with self.assertRaises(ValueError):
                    nmd_monitor.Store(state, {})
            self.assertEqual(list(foreign.iterdir()), [])
            self.assertEqual(list((base / 'original').iterdir()), [])

    def test_opened_ancestor_remains_pinned_during_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            ancestor, foreign = base / 'ancestor', base / 'foreign'
            ancestor.mkdir(mode=0o700)
            foreign.mkdir(mode=0o700)
            open_file = os.open
            swapped = False
            def substitute(path, *args, **kwargs):
                nonlocal swapped
                fd = open_file(path, *args, **kwargs)
                if path == 'ancestor' and not swapped:
                    swapped = True
                    ancestor.rename(base / 'original')
                    ancestor.symlink_to(foreign, target_is_directory=True)
                return fd
            with patch.object(nmd_monitor.os, 'open', side_effect=substitute):
                store = nmd_monitor.Store(ancestor / 'state', {})
            store.close()
            self.assertTrue(swapped)
            self.assertTrue((base / 'original/state/monitor.sqlite3').is_file())
            self.assertEqual(list(foreign.iterdir()), [])

    def test_sqlite_connect_uses_verified_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state, foreign = base / 'state', base / 'foreign'
            foreign.mkdir(mode=0o700)
            connect = nmd_monitor.sqlite3.connect
            def substitute(*args, **kwargs):
                state.rename(base / 'original')
                state.symlink_to(foreign, target_is_directory=True)
                return connect(*args, **kwargs)
            with patch.object(nmd_monitor.sqlite3, 'connect', side_effect=substitute):
                store = nmd_monitor.Store(state, {})
            store.close()
            self.assertTrue((base / 'original/monitor.sqlite3').is_file())
            self.assertEqual(list(foreign.iterdir()), [])

    def test_collect_reuses_locked_directory_after_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state, foreign = base / 'state', base / 'foreign'
            foreign.mkdir(mode=0o700)
            with nmd_monitor.collector_lock(state) as pinned:
                state.rename(base / 'original')
                state.symlink_to(foreign, target_is_directory=True)
                store = nmd_monitor.Store(pinned, {})
                store.close()
                with self.assertRaises(RuntimeError):
                    with nmd_monitor.collector_lock(base / 'original'):
                        pass
            self.assertEqual(list(foreign.iterdir()), [])
            self.assertTrue((base / 'original/monitor.sqlite3').is_file())

    def test_reader_connect_uses_verified_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state, foreign = base / 'state', base / 'foreign'
            store = nmd_monitor.Store(state, {})
            store.close()
            foreign.mkdir(mode=0o700)
            connect = nmd_monitor.sqlite3.connect
            def substitute(*args, **kwargs):
                self.assertIn('mode=ro', args[0])
                state.rename(base / 'original')
                state.symlink_to(foreign, target_is_directory=True)
                return connect(*args, **kwargs)
            with patch.object(nmd_monitor.sqlite3, 'connect', side_effect=substitute):
                snapshot = nmd_monitor.read_snapshot(state)
            self.assertEqual(snapshot['collector']['state'], 'stale')
            self.assertEqual(list(foreign.iterdir()), [])

    def test_group_or_world_writable_ancestor_rejected(self):
        for mode in (0o770, 0o777):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                ancestor = Path(directory) / 'shared'
                ancestor.mkdir(mode=0o700)
                ancestor.chmod(mode)
                with self.assertRaisesRegex(ValueError, 'unsafe_state_directory_ancestor'):
                    nmd_monitor.Store(ancestor / 'state', {})
                self.assertFalse((ancestor / 'state').exists())

    def test_sqlite_sidecar_symlinks_rejected_for_writer_and_reader(self):
        for suffix in ('-wal', '-shm', '-journal'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                state, foreign = base / 'state', base / 'foreign'
                store = nmd_monitor.Store(state, {})
                store.close()
                foreign.write_bytes(b'unchanged')
                (state / ('monitor.sqlite3' + suffix)).symlink_to(foreign)
                for operation in (lambda: nmd_monitor.Store(state, {}),
                                  lambda: nmd_monitor.read_snapshot(state)):
                    with self.assertRaises(ValueError):
                        operation()
                self.assertEqual(foreign.read_bytes(), b'unchanged')

    def test_database_and_lock_symlinks_rejected(self):
        for name in ('monitor.sqlite3', 'collector.lock'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                state, foreign = base / 'state', base / 'foreign'
                state.mkdir(mode=0o700)
                foreign.write_bytes(b'unchanged')
                (state / name).symlink_to(foreign)
                with self.assertRaises(ValueError):
                    if name == 'monitor.sqlite3':
                        nmd_monitor.Store(state, {})
                    else:
                        with nmd_monitor.collector_lock(state):
                            pass
                self.assertEqual(foreign.read_bytes(), b'unchanged')

    def test_rejected_state_does_not_leak_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            state.mkdir(mode=0o700)
            (state / 'monitor.sqlite3').symlink_to(Path(directory) / 'missing')
            fd_directory = '/dev/fd' if sys.platform == 'darwin' else '/proc/self/fd'
            before = len(os.listdir(fd_directory))
            for _ in range(10):
                with self.assertRaises(ValueError):
                    nmd_monitor.Store(state, {})
            self.assertEqual(len(os.listdir(fd_directory)), before)

    def test_bash32_parameter_names_stop_before_utf8(self):
        # Darwin bash 3.2.57 keeps a UTF-8 lead byte that isalnum() accepts.
        # U+FF08 / U+FF0C start with EF, so unbraced `$was_active（` is the name
        # was_active plus 0xEF and `set -u` exits before the echo. glibc does
        # not classify 0xEF as alnum; Linux reproduces that ctype with LD_PRELOAD.
        scripts = _setup_shell_scripts()
        hits = [hit for path in scripts for hit in _expansions_before_non_ascii(path)]
        unbraced = [hit for hit in hits if not hit.braced]
        self.assertEqual(unbraced, [], unbraced)
        braced = {(hit.name, hit.lead) for hit in hits if hit.braced}
        self.assertIn(('was_active', 0xEF), braced)
        self.assertIn(('stage', 0xEF), braced)
        lines = _braced_source_lines(hits)
        locales, utf8_locales = _shell_locales()
        self.assertTrue(utf8_locales, 'UTF-8 locale required to match the Darwin failure')
        for locale in locales:
            completed = _run_bash(_positive_script(lines), locale)
            self._assert_expanded(completed, locale, preload=False)
        if sys.platform == 'linux':
            with tempfile.TemporaryDirectory() as tmp:
                preload = _darwin_ctype_preload(Path(tmp))
                for locale in locales:
                    bad = _run_bash(_UNBRACED_BANNER, locale, preload=preload)
                    self.assertNotEqual(bad.returncode, 0, bad.stdout)
                    self.assertIn(b'was_active\xef', bad.stderr)
                    good = _run_bash(_positive_script(lines), locale, preload=preload)
                    self._assert_expanded(good, locale, preload=True)
        elif sys.platform == 'darwin':
            for locale in utf8_locales:
                bad = _run_bash(_UNBRACED_BANNER, locale)
                self.assertNotEqual(bad.returncode, 0, bad.stdout)
                self.assertIn(b'was_active\xef', bad.stderr)

    def _assert_expanded(self, completed, locale, preload):
        label = f'locale={locale} preload={preload} stderr={completed.stderr!r}'
        self.assertEqual(completed.returncode, 0, label)
        stdout = completed.stdout.decode('utf-8')
        stderr = completed.stderr.decode('utf-8')
        self.assertIn('原运行状态=0（1=运行，0=停止）。', stdout)
        self.assertIn('原文件备份保留在 stage-marker，请先恢复后再删除。', stderr)
        self.assertNotIn('unbound variable', stderr)


_UNBRACED_BANNER = (
    'set -u\n'
    'was_active=0\n'
    'echo "配置已部署；原运行状态=$was_active（1=运行，0=停止）。"\n'
)

_CTYPE_EF = r"""
#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <string.h>
const unsigned short **__ctype_b_loc(void) {
  static const unsigned short **(*real)(void);
  static unsigned short table[384];
  static const unsigned short *mid;
  static int ready;
  if (!real)
    real = (const unsigned short **(*)(void))dlsym(RTLD_NEXT, "__ctype_b_loc");
  if (!ready) {
    const unsigned short *orig = *real();
    memcpy(table, orig - 128, sizeof table);
    table[128 + 0xEF] = (unsigned short)(table[128 + 0xEF] | _ISalnum | _ISalpha);
    mid = table + 128;
    ready = 1;
  }
  return &mid;
}
"""


class _Expansion:
    def __init__(self, path, line, name, braced, lead, source):
        self.path = path
        self.line = line
        self.name = name
        self.braced = braced
        self.lead = lead
        self.source = source

    def __repr__(self):
        kind = "braced" if self.braced else "unbraced"
        return f"{self.path.name}:{self.line} {kind} ${{{self.name}}} lead=0x{self.lead:02x}"


def _setup_shell_scripts():
    paths = [
        ROOT / "local-setup.sh",
        ROOT / "vps-setup.sh",
        ROOT / "install.sh",
        ROOT / "fetch-assets.sh",
        ROOT / "nmd",
    ]
    paths.extend(sorted((ROOT / "scripts").rglob("*.sh")))
    return [path for path in paths if path.is_file()]


def _name_start(value):
    return 65 <= value <= 90 or 97 <= value <= 122 or value == 95


def _name_byte(value):
    return _name_start(value) or 48 <= value <= 57


def _expansions_before_non_ascii(path):
    data = path.read_bytes()
    hits = []
    line = 1
    index = 0
    while index < len(data):
        if data[index] == 10:
            line += 1
            index += 1
            continue
        if data[index] == ord("$") and index + 1 < len(data):
            nxt = data[index + 1]
            if nxt == ord("{") and index + 2 < len(data) and _name_start(data[index + 2]):
                cursor = index + 3
                while cursor < len(data) and _name_byte(data[cursor]):
                    cursor += 1
                if (cursor + 1 < len(data) and data[cursor] == ord("}")
                        and data[cursor + 1] >= 0x80):
                    name = data[index + 2:cursor].decode("ascii")
                    hits.append(_hit(path, data, line, name, True, data[cursor + 1]))
            elif _name_start(nxt):
                cursor = index + 2
                while cursor < len(data) and _name_byte(data[cursor]):
                    cursor += 1
                if cursor < len(data) and data[cursor] >= 0x80:
                    name = data[index + 1:cursor].decode("ascii")
                    hits.append(_hit(path, data, line, name, False, data[cursor]))
        index += 1
    return hits


def _hit(path, data, line, name, braced, lead):
    source = data.splitlines()[line - 1].decode("utf-8")
    return _Expansion(path, line, name, braced, lead, source)


def _braced_source_lines(hits):
    seen = []
    for hit in hits:
        if hit.braced and hit.source not in seen:
            seen.append(hit.source)
    return seen


def _positive_script(lines):
    names = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", "\n".join(lines)))
    assignments = []
    for name in sorted(names):
        if name == "was_active":
            assignments.append("was_active=0")
        elif name == "stage":
            assignments.append("stage=stage-marker")
        else:
            assignments.append(f"{name}=marker")
    body = "\n".join(assignments + [line.strip() for line in lines])
    return "set -u\n" + body + "\n"


def _shell_locales():
    raw = subprocess.check_output(["locale", "-a"], text=True, errors="replace")
    have = [line.strip() for line in raw.splitlines() if line.strip()]
    present = set(have)
    utf8 = [name for name in ("C.UTF-8", "C.utf8", "en_US.UTF-8", "en_US.utf8") if name in present]
    if not utf8:
        for name in have:
            if "utf8" in name.lower().replace("-", ""):
                utf8.append(name)
                break
    return ["C", *utf8], utf8


def _bash_executable():
    if sys.platform == "darwin" and Path("/bin/bash").is_file():
        return "/bin/bash"
    return "bash"


def _run_bash(script, locale, preload=None):
    env = os.environ.copy()
    for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "POSIXLY_CORRECT", "LD_PRELOAD"):
        env.pop(key, None)
    env["LC_ALL"] = locale
    env["LANG"] = locale
    if preload is not None:
        env["LD_PRELOAD"] = str(preload)
    return subprocess.run(
        [_bash_executable(), "-c", script],
        capture_output=True, env=env, timeout=10)


def _darwin_ctype_preload(directory):
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        raise AssertionError("linux needs gcc or cc to simulate Darwin isalnum(0xEF)")
    source = directory / "ctype-ef.c"
    library = directory / "ctype-ef.so"
    source.write_text(_CTYPE_EF, encoding="ascii")
    compiled = subprocess.run(
        [compiler, "-shared", "-fPIC", "-o", str(library), str(source), "-ldl"],
        capture_output=True, text=True, timeout=30)
    if compiled.returncode != 0:
        raise AssertionError(compiled.stderr)
    return library


if __name__ == '__main__':
    unittest.main()
