"""Independent review regressions; temporary files and loopback traffic only."""
import http.server
import os
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
