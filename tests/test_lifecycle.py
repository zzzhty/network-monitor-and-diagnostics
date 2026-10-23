"""Real Git integration; assets, network setup, and monitor services are fixtures."""
from pathlib import Path
import fcntl
import json
import os
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]


class LifecycleFixture:
    """Isolated HOME/XDG and no external service or download execution."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "source with spaces"
        self.root = self.base / ".nmd"
        self.bin = self.base / "bin"
        self.events = self.base / "events"
        self.remote = self.base / "origin.git"
        self.env = dict(os.environ, NMD_TEST_EVENTS=str(self.events),
                        HOME=str(self.base), XDG_CONFIG_HOME=str(self.base / "config"),
                        XDG_STATE_HOME=str(self.base / "state"),
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        # A developer invoking tests with sudo must not change the fixture scope.
        for key in ("SUDO_USER", "SUDO_UID", "SUDO_GID"):
            self.env.pop(key, None)
        self.source.mkdir()
        (self.source / "scripts").mkdir()
        for name in ("install.sh", "nmd", ".gitignore", "scripts/manager.py"):
            shutil.copy2(SOURCE / name, self.source / name)
        # Model Linux for these lifecycle fixtures even on a macOS test host.
        # The production dispatcher has no environment override for this guard.
        (self.source / "scripts/nmd_platform.py").write_text('def name(): return "linux"\n')
        # Never copy the real service installer into these executable fixtures.
        # The manager still uses its real import and scope-dispatch logic.
        (self.source / "scripts/install_scope.py").write_text('''
import json
import os
from pathlib import Path

class ScopeError(Exception):
    pass

def paths(scope):
    if scope == "system":
        return {"home": Path("/opt/nmd"), "bin_dir": Path("/usr/local/bin"),
                "config_dir": Path("/etc/nmd"), "state_dir": Path("/var/lib/nmd-monitor")}
    home = Path.home()
    return {"home": home / ".nmd", "bin_dir": home / ".local/bin",
            "config_dir": Path(os.environ["XDG_CONFIG_HOME"]) / "nmd",
            "state_dir": Path(os.environ["XDG_STATE_HOME"]) / "nmd"}

def record(action, scope, **details):
    with Path(os.environ["NMD_TEST_EVENTS"]).open("a") as stream:
        stream.write(json.dumps(dict(action=action, scope=scope, **details)) + "\\n")

def install_monitor(root, scope, config_dir, state_dir):
    record("install", scope, root=str(root), config_dir=str(config_dir), state_dir=str(state_dir))
    if os.environ.get("NMD_TEST_FAIL_MONITOR_INSTALL") == "1":
        raise ScopeError("fixture monitor installation failure")

def uninstall_monitor(root, scope, config_dir, state_dir):
    record("uninstall", scope, root=str(root), config_dir=str(config_dir), state_dir=str(state_dir))

def check_monitor(root, scope, config_dir):
    # Unit-ownership validation is covered by the real installer unit tests.
    pass

def service(scope, action):
    record(action, scope)
''')
        (self.source / "local-setup.sh").write_text('''#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
echo "$1" >> "$NMD_TEST_EVENTS"
if [[ $1 == verify && ${NMD_TEST_FAIL_VERIFY:-0} == 1 ]]; then exit 44; fi
if [[ $1 == deploy || $1 == apply ]]; then
  if [[ ${NMD_TEST_FAIL_DEPLOY:-0} == 1 ]]; then exit 42; fi
fi
''')
        (self.source / "fetch-assets.sh").write_text('''#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")"
echo assets >> "$NMD_TEST_EVENTS"
touch mihomo.deb geoip.metadb GeoSite.dat
''')
        self.git(self.source, "init", "-b", "main")
        self.git(self.source, "config", "user.name", "Test")
        self.git(self.source, "config", "user.email", "test@example.invalid")
        self.commit("initial")
        self.git(self.base, "init", "--bare", str(self.remote))
        self.git(self.source, "remote", "add", "origin", str(self.remote))
        self.git(self.source, "push", "origin", "main")

    def git(self, root, *args):
        return subprocess.check_output(["git", "-C", str(root), *args],
                                       text=True, stderr=subprocess.PIPE, env=self.env).strip()

    def commit(self, message):
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "-m", message)

    def invoke(self, *args, root=None, extra_env=None):
        return subprocess.run([str((root or self.root) / "nmd"), *args],
                              cwd=self.base, env=dict(self.env, **(extra_env or {})),
                              text=True, capture_output=True, timeout=20)

    def install(self, *extra):
        return subprocess.run([str(self.source / "install.sh"), "--home", str(self.root),
                               "--repository", str(self.remote), "--bin-dir", str(self.bin),
                               "--no-path", *extra], cwd=self.base, env=self.env,
                              text=True, capture_output=True, timeout=20)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def advance(self, invalid=None):
        if invalid == "python":
            (self.source / "scripts/invalid_candidate.py").write_text("def broken(:\n")
        elif invalid == "shell":
            (self.source / "local-setup.sh").write_text("#!/bin/bash\nif then\n")
        else:
            (self.source / "release.txt").write_text("next")
        self.commit("next")
        self.git(self.source, "push", "origin", "main")
        return self.git(self.source, "rev-parse", "HEAD")

    def event_lines(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def scope_events(self):
        return [json.loads(line) for line in self.event_lines() if line.startswith("{")]


class LifecycleTests(LifecycleFixture, unittest.TestCase):
    def test_default_repository_uses_renamed_remote(self):
        expected = 'https://github.com/zzzhty/network-monitor-and-diagnostics.git'
        for name in ('install.sh', 'scripts/manager.py'):
            source = (SOURCE / name).read_text()
            self.assertIn(expected, source)
            self.assertNotIn('zzzhty/mihomo-tailscale', source)

    def test_nmd_is_the_only_source_and_installed_entry(self):
        self.assertTrue((SOURCE / 'nmd').is_file())
        self.assertFalse((SOURCE / 'nmd').is_symlink())
        for name in ('mh', 'mihomoctl'):
            self.assertFalse((SOURCE / name).exists())
            self.assertFalse((SOURCE / name).is_symlink())
        self.assert_ok(self.install('--manager-only'))
        self.assertEqual((self.bin / 'nmd').resolve(), self.root / 'nmd')
        for name in ('mh', 'mihomoctl'):
            self.assertFalse((self.bin / name).is_symlink())
            self.assertFalse((self.bin / name).exists())
        result = subprocess.run([str(self.bin / 'nmd'), 'version'],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assert_ok(result)
        self.assertEqual(result.stdout.strip(), self.git(self.root, 'rev-parse', 'HEAD'))

    def test_foreign_nmd_is_not_overwritten_or_partially_installed(self):
        self.bin.mkdir()
        foreign = self.bin / 'nmd'
        foreign.write_text('operator-owned')
        result = self.install('--manager-only')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.read_text(), 'operator-owned')
        self.assertFalse((self.bin / 'mh').exists())
        self.assertFalse(self.root.exists())

    def test_independent_clone_path_migration_and_repeat_bootstrap(self):
        self.bin.mkdir()
        for name in ("mh", "mihomoctl"):
            (self.bin / name).symlink_to(self.source / "mihomoctl")
        self.assert_ok(self.install("--manager-only", "--migrate-from", str(self.source)))
        self.assertFalse(self.root.is_symlink())
        self.assertNotEqual(self.git(self.root, "rev-parse", "--show-toplevel"), str(self.source))
        self.assert_ok(self.install("--manager-only"))
        self.assertFalse(self.events.exists())
        moved = self.base / "renamed source"
        self.source.rename(moved)
        for name in ("mh", "mihomoctl"):
            self.assertFalse((self.bin / name).is_symlink())
        self.assertEqual((self.bin / "nmd").resolve(), self.root / "nmd")
        result = subprocess.run(["nmd", "version"], cwd=self.base, env=self.env,
                                capture_output=True, text=True)
        self.assert_ok(result)
        self.assertEqual(result.stdout.strip(), self.git(self.root, "rev-parse", "HEAD"))
        self.assertNotEqual(self.invoke("status", root=moved).returncode, 0)
        bad = self.invoke("unknown argument")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("未知命令: unknown argument", bad.stderr)

    def test_migration_replaces_old_nmd_and_preserves_checkout_and_data(self):
        self.bin.mkdir()
        (self.source / "history.sqlite3").write_text("historic data")
        for name in ("nmd", "mh", "mihomoctl"):
            (self.bin / name).symlink_to(self.source / "nmd")
        self.assert_ok(self.install("--manager-only", "--migrate-from", str(self.source)))
        self.assertEqual((self.bin / "nmd").resolve(), self.root / "nmd")
        for name in ("mh", "mihomoctl"):
            self.assertFalse((self.bin / name).is_symlink())
        self.assertEqual((self.source / "history.sqlite3").read_text(), "historic data")
        self.assertTrue((self.source / ".git").is_dir())

    def test_legacy_links_are_untouched_without_explicit_migration(self):
        self.bin.mkdir()
        for name in ("mh", "mihomoctl"):
            (self.bin / name).symlink_to(self.source / "mihomoctl")
        self.assert_ok(self.install("--manager-only"))
        for name in ("mh", "mihomoctl"):
            self.assertEqual(os.readlink(self.bin / name), str(self.source / "mihomoctl"))

    def test_migration_preserves_foreign_legacy_commands_and_symlink_chains(self):
        self.bin.mkdir()
        (self.bin / "mh").write_text("operator-owned command")
        indirect = self.base / "foreign link"
        indirect.symlink_to(self.source / "nmd")
        (self.bin / "mihomoctl").symlink_to(indirect)
        self.assert_ok(self.install("--manager-only", "--migrate-from", str(self.source)))
        self.assertEqual((self.bin / "mh").read_text(), "operator-owned command")
        self.assertEqual(os.readlink(self.bin / "mihomoctl"), str(indirect))

    def test_migration_conflicting_nmd_does_not_remove_owned_legacy_links(self):
        self.bin.mkdir()
        (self.bin / "nmd").symlink_to(self.base / "unrelated-command")
        (self.bin / "mh").symlink_to(self.source / "mihomoctl")
        self.assertNotEqual(self.install("--manager-only", "--migrate-from", str(self.source)).returncode, 0)
        self.assertEqual(os.readlink(self.bin / "nmd"), str(self.base / "unrelated-command"))
        self.assertEqual(os.readlink(self.bin / "mh"), str(self.source / "mihomoctl"))
        self.assertFalse(self.root.exists())

    def test_streamed_installer_from_unrelated_directory(self):
        result = subprocess.run(
            ["bash", "-s", "--", "--home", str(self.root), "--bin-dir", str(self.bin),
             "--manager-only", "--no-path"], input=(SOURCE / "install.sh").read_text(),
            cwd=self.base, env=dict(self.env, NMD_REPOSITORY=str(self.remote)),
            text=True, capture_output=True, timeout=20)
        self.assert_ok(result)
        self.assertEqual(self.git(self.root, "remote", "get-url", "origin"), str(self.remote))
        self.assertEqual((self.bin / "nmd").resolve(), self.root / "nmd")

    def test_default_home_and_registry_use_only_nmd_namespace(self):
        result = subprocess.run(
            [str(self.source / "install.sh"), "--bin-dir", str(self.bin),
             "--manager-only", "--no-path"], cwd=self.base,
            env=dict(self.env, HOME=str(self.base), NMD_REPOSITORY=str(self.remote),
                     MIHOMO_REPOSITORY=str(self.base / "must-not-be-used")),
            text=True, capture_output=True, timeout=20)
        self.assert_ok(result)
        self.assertEqual(self.git(self.root, "config", "nmd.home"), str(self.root))
        self.assertTrue((self.root / ".git/nmd.lock").is_file())
        self.assertFalse((self.root / ".git/mh.lock").exists())
        self.assertFalse((self.base / ".mh-ts").exists())
        absent = subprocess.run(["git", "-C", str(self.root), "config", "--get-regexp",
                                 "^mihomo\\."], capture_output=True)
        self.assertEqual(absent.returncode, 1)

    def test_update_is_code_only_and_explicit_apply_is_retryable(self):
        self.assert_ok(self.install())
        source_registry = self.base / "config/nmd/egress/sources.json"
        source_registry.parent.mkdir(parents=True, mode=0o700)
        source_registry.write_text('{"synthetic_private_source":"preserve across code updates"}')
        source_registry.chmod(0o600)
        source_bytes = source_registry.read_bytes()
        self.assert_ok(self.invoke("apply"))
        old = self.git(self.root, "rev-parse", "HEAD")
        target = self.advance()
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "false")
        before = self.event_lines()
        # Removing assets proves update neither fetches nor requires them.
        for name in ("mihomo.deb", "geoip.metadb", "GeoSite.dat"):
            (self.root / name).unlink()
        self.assert_ok(self.invoke("update", "--check"))
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), old)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "false")
        self.assert_ok(self.invoke("update", extra_env={"NMD_TEST_FAIL_DEPLOY": "1"}))
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), target)
        self.assertEqual(source_registry.read_bytes(), source_bytes)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        self.assertEqual(self.git(self.root, "config", "nmd.appliedRevision"), old)
        self.assertEqual(self.event_lines(), before)
        self.assertFalse(any((self.root / name).exists() for name in
                             ("mihomo.deb", "geoip.metadb", "GeoSite.dat")))
        # Updating again never silently retries a failed or pending apply.
        self.assert_ok(self.invoke("update"))
        self.assertEqual(self.event_lines(), before)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        result = self.invoke("apply", extra_env={"NMD_TEST_FAIL_DEPLOY": "1"})
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        self.assertEqual(self.git(self.root, "config", "nmd.appliedRevision"), old)
        self.assertEqual(self.event_lines()[len(before):], ["assets", "apply"])
        self.assert_ok(self.invoke("apply"))
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "false")
        self.assertEqual(self.git(self.root, "config", "nmd.appliedRevision"), target)
        before = self.event_lines()
        self.assert_ok(self.invoke("update"))
        self.assertEqual(self.event_lines(), before)
        self.assertEqual(self.git(self.source, "status", "--porcelain"), "")
        self.assertEqual(source_registry.read_bytes(), source_bytes)
        self.assertEqual(self.git(self.source, "config", "--get-regexp", "^remote.origin.url"),
                         "remote.origin.url " + str(self.remote))

    def test_verification_failure_never_records_applied_revision(self):
        self.assert_ok(self.install("--manager-only"))
        result = self.invoke("apply", extra_env={"NMD_TEST_FAIL_VERIFY": "1"})
        self.assertEqual(result.returncode, 44)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        absent = subprocess.run(["git", "-C", str(self.root), "config", "--get",
                                 "nmd.appliedRevision"], capture_output=True)
        self.assertEqual(absent.returncode, 1)
        self.assert_ok(self.invoke("apply"))
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "false")
        self.assertEqual(self.event_lines(), ["assets", "apply", "verify", "apply", "verify"])

    def test_dirty_or_diverged_installation_is_not_overwritten(self):
        self.assert_ok(self.install())
        old = self.git(self.root, "rev-parse", "HEAD")
        self.advance()
        user_file = self.root / "user-work.txt"
        user_file.write_text("keep this")
        result = self.invoke("update")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(user_file.read_text(), "keep this")
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), old)
        self.git(self.root, "add", "user-work.txt")
        self.git(self.root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-m", "local work")
        diverged = self.git(self.root, "rev-parse", "HEAD")
        self.assertNotEqual(self.invoke("update").returncode, 0)
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), diverged)

    def assert_invalid_candidate_preserves_installation(self, kind):
        self.assert_ok(self.install())
        self.assert_ok(self.invoke("apply"))
        old = self.git(self.root, "rev-parse", "HEAD")
        before = self.event_lines()
        self.advance(invalid=kind)
        result = self.invoke("update")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), old)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "false")
        self.assertEqual(self.git(self.root, "config", "nmd.appliedRevision"), old)
        self.assertEqual(self.event_lines(), before)
        # Failed candidates must not leave attached temporary worktrees behind.
        self.assertEqual(self.git(self.root, "worktree", "list", "--porcelain").count("worktree "), 1)
        self.git(self.root, "remote", "set-url", "origin", str(self.base / "missing.git"))
        self.assertNotEqual(self.invoke("update").returncode, 0)
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), old)
        self.assertEqual(self.event_lines(), before)

    def test_invalid_python_candidate_and_remote_failure_leave_old_installation(self):
        self.assert_invalid_candidate_preserves_installation("python")

    def test_invalid_shell_candidate_and_remote_failure_leave_old_installation(self):
        self.assert_invalid_candidate_preserves_installation("shell")

    def test_foreign_directory_and_command_collisions_are_preserved(self):
        self.root.mkdir()
        (self.root / "user-file").write_text("keep")
        self.assertNotEqual(self.install("--manager-only").returncode, 0)
        self.assertEqual((self.root / "user-file").read_text(), "keep")
        self.assertFalse(self.bin.exists())
        self.root.rename(self.base / "foreign")
        self.bin.mkdir()
        (self.bin / "nmd").write_text("existing command")
        self.assertNotEqual(self.install("--manager-only").returncode, 0)
        self.assertFalse((self.bin / "mh").exists())
        self.assertFalse(self.root.exists())
        self.assertEqual((self.bin / "nmd").read_text(), "existing command")

    def test_lock_and_failed_first_deployment_are_visible(self):
        self.assert_ok(self.install("--manager-only"))
        with (self.root / ".git/nmd.lock").open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.invoke("update")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("另一个", result.stderr)
        result = self.invoke("apply", extra_env={"NMD_TEST_FAIL_DEPLOY": "1"})
        self.assertEqual(result.returncode, 42)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        self.assert_ok(self.invoke("apply"))
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "false")


if __name__ == "__main__":
    unittest.main()

