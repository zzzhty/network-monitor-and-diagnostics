"""Manager scope dispatch with real Git and event-only service installers.

These fixtures never import the real install_scope or invoke systemd, sudo,
network setup, asset downloads, or writes outside a temporary directory.
"""
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from test_lifecycle import LifecycleFixture


class ScopeLifecycleTests(LifecycleFixture, unittest.TestCase):
    @contextmanager
    def manager_module(self):
        """Load a copied manager with the same safe installer as subprocess tests."""
        scope_spec = importlib.util.spec_from_file_location(
            "fixture_install_scope", self.source / "scripts/install_scope.py")
        scope = importlib.util.module_from_spec(scope_spec)
        scope_spec.loader.exec_module(scope)
        spec = importlib.util.spec_from_file_location(
            "fixture_scope_manager", self.source / "scripts/manager.py")
        manager = importlib.util.module_from_spec(spec)
        platform_spec = importlib.util.spec_from_file_location(
            "fixture_platform", self.source / "scripts/nmd_platform.py")
        platform = importlib.util.module_from_spec(platform_spec)
        platform_spec.loader.exec_module(platform)
        with patch.dict(sys.modules, {"install_scope": scope, "nmd_platform": platform}), \
                patch.dict(os.environ, self.env, clear=True):
            spec.loader.exec_module(manager)
            yield manager

    def unset(self, key):
        self.git(self.root, "config", "--unset", "nmd." + key)

    def private_checkout(self):
        # Only this test's temporary copy models a trusted system checkout.
        # Keep actual ownership checks and each explicit unsafe-mode mutation.
        for path in (self.source, *self.source.rglob("*")):
            if not path.is_symlink():
                path.chmod(path.stat().st_mode & ~0o022)

    def test_default_bootstrap_records_user_scope_and_xdg_paths(self):
        self.assert_ok(self.install("--manager-only"))
        for key, expected in {
            "home": str(self.root), "scope": "user",
            "configDir": str(self.base / "config/nmd"),
            "stateDir": str(self.base / "state/nmd"),
            "pendingApply": "true",
        }.items():
            self.assertEqual(self.git(self.root, "config", "nmd." + key), expected)
        self.assertEqual(self.event_lines(), [])
        self.assertFalse((self.base / ".bashrc").exists())
        self.assertFalse((self.base / ".profile").exists())

    def test_default_install_only_installs_monitor_without_starting(self):
        self.assert_ok(self.install())
        self.assertEqual(self.scope_events(), [{
            "action": "install", "scope": "user", "root": str(self.root),
            "config_dir": str(self.base / "config/nmd"),
            "state_dir": str(self.base / "state/nmd"),
        }])
        self.assertEqual(len(self.event_lines()), 1)
        self.assertEqual(self.git(self.root, "config", "nmd.monitorInstalled"), "true")
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        for name in ("mihomo.deb", "geoip.metadb", "GeoSite.dat"):
            self.assertFalse((self.root / name).exists())
        for command in (("install",), ("monitor", "install")):
            self.assert_ok(self.invoke(*command))
        self.assertEqual([event["action"] for event in self.scope_events()],
                         ["install", "install", "install"])

    def test_sudo_does_not_choose_system_scope(self):
        result = self.invoke("bootstrap", "--home", str(self.root),
                             "--repository", str(self.remote), "--bin-dir", str(self.bin),
                             "--no-path", root=self.source,
                             extra_env={"SUDO_USER": "operator", "SUDO_UID": "1001"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--system", result.stderr)
        self.assertIn("sudo", result.stderr)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.bin.exists())
        self.assertEqual(self.event_lines(), [])

    def test_system_requires_root_before_any_write(self):
        with self.manager_module() as manager, \
                patch.object(manager.os, "geteuid", return_value=1001):
            with self.assertRaises(manager.ManagerError):
                manager.main(["bootstrap", "--system"])
        self.assertFalse(self.root.exists())
        self.assertEqual(self.event_lines(), [])

    def test_system_defaults_are_fixed_before_preflight(self):
        class PreflightReached(Exception):
            pass

        real_lstat = Path.lstat
        system_ancestors = {Path("/"), Path("/opt"), Path("/usr"),
                            Path("/usr/local"), Path("/usr/local/bin")}

        def trusted_metadata(path):
            info = real_lstat(path)
            if path in system_ancestors:
                values = list(info)
                values[4] = 0  # Model root ownership, independent of the test host.
                values[0] &= ~0o022
                return os.stat_result(values)
            return info

        with self.manager_module() as manager, \
                patch.object(manager.os, "geteuid", return_value=0), \
                patch.object(Path, "lstat", trusted_metadata), \
                patch.object(manager, "preflight_links", side_effect=PreflightReached) as preflight:
            # Stop before locks, clone, links, or any system-path mutation.
            with self.assertRaises(PreflightReached):
                manager.main(["bootstrap", "--system", "--manager-only"])
            root, bindir, migration = preflight.call_args.args
            self.assertEqual(root, Path("/opt/nmd"))
            self.assertEqual(bindir, Path("/usr/local/bin"))
            self.assertIsNone(migration)
        self.assertEqual(self.event_lines(), [])

    def test_system_rejects_personal_home_or_bin_directory(self):
        with self.manager_module() as manager, \
                patch.object(manager.os, "geteuid", return_value=0), \
                patch.object(manager, "preflight_links") as preflight:
            for option, value in (("--home", self.root), ("--bin-dir", self.bin)):
                with self.subTest(option=option), self.assertRaises(manager.ManagerError):
                    manager.main(["bootstrap", "--system", option, str(value)])
            preflight.assert_not_called()
        self.assertFalse(self.root.exists())
        self.assertFalse(self.bin.exists())

    def test_system_checkout_rejects_user_owned_root_or_descendant(self):
        real_lstat = Path.lstat
        for untrusted_path in (self.source, self.source / "nmd"):
            def ownership(path):
                values = list(real_lstat(path))
                values[4] = 1001 if path == untrusted_path else 0
                return os.stat_result(values)

            with self.subTest(path=untrusted_path), self.manager_module() as manager, \
                    patch.object(Path, "lstat", ownership):
                self.private_checkout()
                with self.assertRaises(manager.ManagerError) as caught:
                    manager.trusted_system_checkout(self.source, ancestors=False)
                self.assertIn(str(untrusted_path), str(caught.exception))
        self.assertEqual(self.event_lines(), [])

    def test_root_ownership_does_not_allow_group_writes_or_symlinks(self):
        real_lstat = Path.lstat

        def root_ownership(path):
            values = list(real_lstat(path))
            values[4] = 0
            return os.stat_result(values)

        with self.manager_module() as manager, patch.object(Path, "lstat", root_ownership):
            self.private_checkout()
            # A fully safe model is accepted before each specific weakness is
            # introduced. Real ownership and system paths remain untouched.
            manager.trusted_system_checkout(self.source, ancestors=False)
            entrypoint = self.source / "nmd"
            original_mode = entrypoint.stat().st_mode
            entrypoint.chmod(original_mode | 0o020)
            with self.assertRaises(manager.ManagerError) as caught:
                manager.trusted_system_checkout(self.source, ancestors=False)
            self.assertIn(str(entrypoint), str(caught.exception))
            entrypoint.chmod(original_mode)
            manager.trusted_system_checkout(self.source, ancestors=False)
            link = self.source / "foreign-link"
            link.symlink_to(entrypoint)
            with self.assertRaises(manager.ManagerError) as caught:
                manager.trusted_system_checkout(self.source, ancestors=False)
            self.assertIn(str(link), str(caught.exception))
        self.assertEqual(self.event_lines(), [])

    def test_monitor_commands_dispatch_user_scope_and_legacy_commands_stay_network(self):
        self.assert_ok(self.install("--manager-only"))
        for command in ("start", "stop", "restart", "enable", "disable", "logs", "service-status"):
            self.assert_ok(self.invoke("monitor", command))
        self.assertEqual(self.scope_events(), [
            {"action": action, "scope": "user"}
            for action in ("start", "stop", "restart", "enable", "disable", "logs", "status")
        ])
        before = len(self.event_lines())
        for command in ("start", "stop", "restart", "enable", "disable"):
            self.assert_ok(self.invoke(command))
        self.assertEqual(self.event_lines()[before:], ["start", "stop", "restart", "enable", "disable"])

    def test_monitor_commands_dispatch_recorded_system_scope(self):
        self.assert_ok(self.install("--manager-only"))
        self.git(self.root, "config", "nmd.scope", "system")
        self.git(self.root, "config", "nmd.configDir", "/etc/nmd")
        self.git(self.root, "config", "nmd.stateDir", "/var/lib/nmd-monitor")
        commands = ("start", "stop", "restart", "enable", "disable", "logs", "service-status")
        # First verify a forged system receipt in a user home is rejected.
        with self.manager_module() as manager:
            with self.assertRaises(manager.ManagerError):
                manager.scope_of(self.root)
            defaults = manager.install_scope.paths("system")
            # Relocate only the modeled fixed home and bypass its privileged
            # ownership guard. Receipt reading and scope dispatch stay real;
            # all service actions still go to the event-only fixture module.
            with patch.object(manager, "ROOT", self.root), \
                    patch.object(manager, "managed") as managed, \
                    patch.object(manager.install_scope, "paths", return_value={
                        **defaults, "home": self.root,
                    }):
                for command in commands:
                    manager.main(["monitor", command])
                self.assertEqual(managed.call_count, len(commands))
                managed.assert_called_with(self.root)
        self.assertEqual(self.scope_events(), [
            {"action": "status" if action == "service-status" else action, "scope": "system"}
            for action in commands
        ])

    def test_monitor_install_uses_recorded_paths_even_when_xdg_changes(self):
        self.assert_ok(self.install("--manager-only"))
        self.assert_ok(self.invoke("monitor", "install", extra_env={
            "XDG_CONFIG_HOME": str(self.base / "different-config"),
            "XDG_STATE_HOME": str(self.base / "different-state"),
        }))
        event = self.scope_events()[0]
        self.assertEqual(event["config_dir"], str(self.base / "config/nmd"))
        self.assertEqual(event["state_dir"], str(self.base / "state/nmd"))
        self.assertEqual(event["scope"], "user")

    def test_failed_monitor_install_is_not_recorded_as_success(self):
        self.assert_ok(self.install("--manager-only"))
        result = self.invoke("install", extra_env={"NMD_TEST_FAIL_MONITOR_INSTALL": "1"})
        self.assertNotEqual(result.returncode, 0)
        absent = subprocess.run(["git", "-C", str(self.root), "config", "--get",
                                 "nmd.monitorInstalled"], env=self.env, capture_output=True)
        self.assertEqual(absent.returncode, 1)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        self.assert_ok(self.invoke("install"))
        self.assertEqual(self.git(self.root, "config", "nmd.monitorInstalled"), "true")
        self.assertEqual([event["action"] for event in self.scope_events()], ["install", "install"])

    def test_old_installation_needs_explicit_user_adoption(self):
        self.assert_ok(self.install("--manager-only"))
        for key in ("scope", "configDir", "stateDir"):
            self.unset(key)
        for command in (("version",), ("update",), ("monitor", "install")):
            result = self.invoke(*command)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("adopt", result.stderr)
        self.assertNotEqual(self.invoke("adopt").returncode, 0)
        self.assertEqual(self.event_lines(), [])
        self.assert_ok(self.invoke("adopt", "--user"))
        self.assertEqual(self.git(self.root, "config", "nmd.scope"), "user")
        self.assertEqual(self.git(self.root, "config", "nmd.configDir"), str(self.base / "config/nmd"))
        self.assertEqual(self.git(self.root, "config", "nmd.stateDir"), str(self.base / "state/nmd"))
        self.assert_ok(self.invoke("version"))
        self.assertEqual(self.event_lines(), [])

    def test_new_source_can_adopt_and_code_only_update_an_old_home(self):
        current_entrypoint = (self.source / "nmd").read_text()
        # Model an old installed entry point that must never execute during a
        # source-directed upgrade, because old versions implicitly applied.
        (self.source / "nmd").write_text(
            '#!/usr/bin/env bash\necho legacy-entrypoint >> "$NMD_TEST_EVENTS"\nexit 97\n')
        self.commit("legacy entrypoint fixture")
        self.git(self.source, "push", "origin", "main")
        self.assert_ok(self.install("--manager-only"))
        self.unset("scope")
        old = self.git(self.root, "rev-parse", "HEAD")
        (self.source / "nmd").write_text(current_entrypoint)
        target = self.advance()
        self.assert_ok(self.invoke("adopt", "--home", str(self.root), "--user", root=self.source))
        self.assertEqual(self.git(self.root, "config", "nmd.scope"), "user")
        self.assert_ok(self.invoke("update", "--home", str(self.root), "--check", root=self.source))
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), old)
        self.assert_ok(self.invoke("update", "--home", str(self.root), root=self.source))
        self.assertEqual(self.git(self.root, "rev-parse", "HEAD"), target)
        self.assertEqual(self.git(self.root, "config", "nmd.pendingApply"), "true")
        self.assertEqual(self.event_lines(), [])
        self.assert_ok(self.invoke("version"))

    def test_adopt_cannot_switch_user_installation_to_system_scope(self):
        self.assert_ok(self.install("--manager-only"))
        result = self.invoke("adopt", "--system")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git(self.root, "config", "nmd.scope"), "user")
        self.assertEqual(self.event_lines(), [])

    def test_moved_home_is_rejected_by_local_and_source_adoption_and_update(self):
        self.assert_ok(self.install("--manager-only"))
        moved = self.base / "moved managed home"
        self.root.rename(moved)
        for command in (("version",), ("adopt", "--user"), ("update",)):
            self.assertNotEqual(self.invoke(*command, root=moved).returncode, 0)
        for command in (("adopt", "--user"), ("update",), ("update", "--check")):
            result = self.invoke(*command, "--home", str(moved), root=self.source)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git(moved, "config", "nmd.home"), str(self.root))
        self.assertEqual(self.event_lines(), [])

    def test_monitor_uninstall_retains_data_code_and_command_link(self):
        self.assert_ok(self.install())
        config = self.base / "config/nmd/monitor.json"
        history = self.base / "state/nmd/history.sqlite3"
        for path in (config, history):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("keep existing user data")
        self.assert_ok(self.invoke("monitor", "uninstall"))
        self.assertEqual(self.git(self.root, "config", "nmd.monitorInstalled"), "false")
        self.assertTrue((self.root / ".git").is_dir())
        self.assertEqual((self.bin / "nmd").resolve(), self.root / "nmd")
        for path in (config, history):
            self.assertEqual(path.read_text(), "keep existing user data")
        self.assertEqual([event["action"] for event in self.scope_events()], ["install", "uninstall"])
        self.assertEqual(len(self.event_lines()), 2)

    def test_full_uninstall_removes_owned_link_and_retains_data(self):
        self.assert_ok(self.install())
        config = self.base / "config/nmd/monitor.json"
        history = self.base / "state/nmd/history.sqlite3"
        for path in (config, history):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("keep existing user data")
        self.assert_ok(self.invoke("uninstall"))
        self.assertFalse((self.bin / "nmd").is_symlink())
        self.assertTrue((self.root / ".git").is_dir())
        for path in (config, history):
            self.assertEqual(path.read_text(), "keep existing user data")
        self.assertEqual([event["action"] for event in self.scope_events()], ["install", "uninstall"])
        self.assertEqual(len(self.event_lines()), 2)

    def test_full_uninstall_preserves_foreign_command_and_indirect_link(self):
        self.assert_ok(self.install("--manager-only"))
        link = self.bin / "nmd"
        link.unlink()
        link.write_text("operator-owned command")
        self.assert_ok(self.invoke("uninstall"))
        self.assertEqual(link.read_text(), "operator-owned command")
        link.unlink()
        indirect = self.base / "foreign indirect link"
        indirect.symlink_to(self.root / "nmd")
        link.symlink_to(indirect)
        self.assert_ok(self.invoke("uninstall"))
        self.assertEqual(os.readlink(link), str(indirect))
        self.assertTrue(indirect.is_symlink())
        self.assertTrue((self.root / ".git").is_dir())
        self.assertEqual([event["action"] for event in self.scope_events()], ["uninstall", "uninstall"])
        self.assertEqual(len(self.event_lines()), 2)


if __name__ == "__main__":
    unittest.main()
