"""Scope/service regressions: temporary files and mocked commands only."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import install_scope


class ScopeDefaultsTests(unittest.TestCase):
    def test_user_and_system_defaults_are_distinct(self):
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/foreign/config", "XDG_STATE_HOME": "/foreign/state"}):
            user = install_scope.paths("user", Path("/home/alice"))
        self.assertEqual(user["home"], Path("/home/alice/.nmd"))
        self.assertEqual(user["bin_dir"], Path("/home/alice/.local/bin"))
        self.assertEqual(user["config_dir"], Path("/home/alice/.config/nmd"))
        self.assertEqual(user["state_dir"], Path("/home/alice/.local/state/nmd-monitor"))
        self.assertEqual(user["unit_file"], Path("/home/alice/.config/systemd/user/nmd-monitor.service"))
        system = install_scope.paths("system")
        self.assertEqual(system["home"], Path("/opt/nmd"))
        self.assertEqual(system["config_dir"], Path("/etc/nmd"))
        self.assertEqual(system["state_dir"], Path("/var/lib/nmd-monitor"))
        self.assertEqual(system["unit_file"], Path("/etc/systemd/system/nmd-monitor.service"))

    def test_only_absolute_xdg_values_are_used(self):
        with patch.object(Path, "home", return_value=Path("/home/alice")), patch.dict(
                os.environ, {"XDG_CONFIG_HOME": "relative", "XDG_STATE_HOME": "/custom/state"}):
            paths = install_scope.paths("user")
        self.assertEqual(paths["config_dir"], Path("/home/alice/.config/nmd"))
        self.assertEqual(paths["state_dir"], Path("/custom/state/nmd-monitor"))

    def test_invalid_scope_has_no_side_effects(self):
        with patch.object(install_scope, "_run") as run:
            for fn, args in ((install_scope.paths, ("bad",)),
                             (install_scope.service, ("bad", "start"))):
                with self.assertRaises(install_scope.ScopeError):
                    fn(*args)
            run.assert_not_called()


class ScopeInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "checkout with spaces $literal%name"
        (self.root / "examples").mkdir(parents=True)
        (self.root / "examples/monitor-local.json").write_text((ROOT / "examples/monitor-local.json").read_text())
        self.paths = install_scope.paths("user", self.base / "user")
        self.config = self.paths["config_dir"]
        self.state = self.paths["state_dir"]
        self.unit = self.paths["unit_file"]
        # Existing parent directories are fixture inputs, not installer output.
        # Model a private user home independently of the invoking shell's umask.
        for parent in (self.base / "user", self.base / "user/.config",
                       self.base / "user/.config/systemd",
                       self.base / "user/.local", self.base / "user/.local/state"):
            parent.mkdir(mode=0o700)
        self.path_patch = patch.object(install_scope, "paths", return_value=self.paths)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.commands = patch.object(install_scope, "_run")
        self.run = self.commands.start()
        self.addCleanup(self.commands.stop)

    def install(self):
        return install_scope.install_monitor(self.root, "user", self.config, self.state)

    def test_user_install_is_opt_in_unprivileged_and_preserves_existing_data(self):
        self.assertEqual(self.install(), self.unit)
        self.assertEqual(self.run.call_args_list, [call("systemctl", "--user", "daemon-reload")])
        value = json.loads((self.config / "monitor.json").read_text())
        self.assertEqual(value["probes"], [])
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.config / "monitor.json").stat().st_mode), 0o600)
        unit = self.unit.read_text()
        self.assertIn("WantedBy=default.target", unit)
        self.assertNotIn("User=", unit)
        self.assertNotIn("Group=", unit)
        self.assertNotIn("mihomo", unit)
        self.assertNotIn("tailscale", unit)
        self.assertNotIn("linger", unit)
        self.assertIn("$$literal%%name", unit)
        value["interval_seconds"] = 45
        (self.config / "monitor.json").write_text(json.dumps(value))
        history = self.state / "history.txt"
        history.write_text("keep history")
        self.install()
        self.assertEqual(json.loads((self.config / "monitor.json").read_text())["interval_seconds"], 45)
        self.assertEqual(history.read_text(), "keep history")
        self.assertTrue(all(args == call("systemctl", "--user", "daemon-reload") for args in self.run.call_args_list))

    def test_unit_location_uses_saved_config_even_after_xdg_change(self):
        self.install()
        other = self.base / "other-config"
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(other)}):
            install_scope.uninstall_monitor(self.root, "user", self.config, self.state)
        self.assertFalse(self.unit.exists())
        self.assertFalse(other.exists())

    def test_system_install_only_prepares_nonroot_service(self):
        account = SimpleNamespace(pw_uid=999, pw_gid=998, pw_shell="/usr/sbin/nologin")
        with patch.object(install_scope.os, "geteuid", return_value=0), patch.object(
                install_scope, "_unit_path", return_value=self.unit), patch.object(
                install_scope, "_validate_system_code") as validate, patch.object(
                install_scope, "_ensure_system_account", return_value=account), patch.object(
                install_scope, "_directory") as directory, patch.object(
                install_scope, "_service_access") as access, patch.object(
                install_scope, "_atomic_write") as write:
            install_scope.install_monitor(self.root, "system", self.config, self.state)
        validate.assert_called_once_with(self.root)
        self.assertIn(call(self.config, 0o750, 0, 998), directory.call_args_list)
        self.assertIn(call(self.state, 0o700, 999, 998, private=True), directory.call_args_list)
        self.assertIn(call(self.config, 999, 998, directory=True), access.call_args_list)
        self.assertEqual(write.call_args_list[0].args[2:], (0o640, 0, 998))
        self.assertIn("User=nmd-monitor", write.call_args_list[1].args[1])
        self.assertEqual(self.run.call_args_list, [call("systemctl", "daemon-reload")])
        self.assertFalse(self.state.exists())
        self.assertFalse(self.config.exists())
        self.assertFalse(self.unit.exists())

    def test_check_monitor_rejects_absent_unit_without_commands(self):
        with self.assertRaisesRegex(install_scope.ScopeError, "monitor install"):
            install_scope.check_monitor(self.root, "user", self.config)
        self.assertFalse(self.unit.parent.exists())
        self.run.assert_not_called()

    def test_check_monitor_rejects_foreign_unit_without_commands(self):
        self.unit.parent.mkdir(parents=True)
        self.unit.write_text("[Service]\nExecStart=/foreign/command\n")
        with self.assertRaises(install_scope.ScopeError):
            install_scope.check_monitor(self.root, "user", self.config)
        self.assertIn("/foreign/command", self.unit.read_text())
        self.run.assert_not_called()

    def test_check_monitor_verifies_exact_checkout_provenance_without_commands(self):
        self.install()
        self.run.reset_mock()
        self.assertEqual(install_scope.check_monitor(self.root, "user", self.config), self.unit)
        with self.assertRaises(install_scope.ScopeError):
            install_scope.check_monitor(self.root.parent / "other-checkout", "user", self.config)
        self.run.assert_not_called()

    def test_foreign_unit_is_never_overwritten(self):
        self.unit.parent.mkdir(parents=True)
        self.unit.write_text("[Service]\nExecStart=/foreign/command\n")
        with self.assertRaises(install_scope.ScopeError):
            self.install()
        self.assertIn("/foreign/command", self.unit.read_text())
        self.assertFalse(self.config.exists())
        self.assertFalse(self.state.exists())
        self.run.assert_not_called()

    def test_foreign_checkout_marker_does_not_authorize_replacement(self):
        self.install()
        self.run.reset_mock()
        other = self.root.parent / "other"
        with self.assertRaises(install_scope.ScopeError):
            install_scope.install_monitor(other, "user", self.config, self.state)
        self.run.assert_not_called()

    def test_symlinked_config_or_unit_is_rejected(self):
        for location in (self.config, self.unit):
            with self.subTest(location=location):
                location.parent.mkdir(parents=True, exist_ok=True)
                foreign = self.base / ("foreign-" + location.name)
                foreign.mkdir()
                location.symlink_to(foreign)
                with self.assertRaises(install_scope.ScopeError):
                    self.install()
                self.assertFalse(list(foreign.iterdir()))
                location.unlink()
        self.run.assert_not_called()

    def test_invalid_existing_config_is_not_replaced_or_started(self):
        self.config.mkdir(parents=True, mode=0o700)
        config = self.config / "monitor.json"
        config.write_text('{"probes":"not-a-list"}')
        config.chmod(0o600)
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(config.read_text(), '{"probes":"not-a-list"}')
        self.assertFalse(self.unit.exists())
        self.run.assert_not_called()

    def test_nonprivate_existing_state_is_not_silently_repaired(self):
        self.state.mkdir(parents=True, mode=0o755)
        self.state.chmod(0o755)
        with self.assertRaises(install_scope.ScopeError):
            self.install()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o755)
        self.assertFalse(self.unit.exists())
        self.run.assert_not_called()

    def test_uninstall_removes_only_owned_unit_and_keeps_config_state_code(self):
        self.install()
        self.run.reset_mock()
        history = self.state / "history.txt"
        history.write_text("keep")
        self.assertTrue(install_scope.uninstall_monitor(self.root, "user", self.config, self.state))
        self.assertFalse(self.unit.exists())
        self.assertTrue((self.config / "monitor.json").is_file())
        self.assertEqual(history.read_text(), "keep")
        self.assertTrue(self.root.is_dir())
        self.assertEqual(self.run.call_args_list,
                         [call("systemctl", "--user", "disable", "--now", "nmd-monitor.service"),
                          call("systemctl", "--user", "daemon-reload")])
        self.run.reset_mock()
        self.assertFalse(install_scope.uninstall_monitor(self.root, "user", self.config, self.state))
        self.run.assert_not_called()

    def test_uninstall_foreign_unit_is_a_noop_failure(self):
        self.unit.parent.mkdir(parents=True)
        self.unit.write_text("foreign unit")
        with self.assertRaises(install_scope.ScopeError):
            install_scope.uninstall_monitor(self.root, "user", self.config, self.state)
        self.assertEqual(self.unit.read_text(), "foreign unit")
        self.run.assert_not_called()

    def test_failed_disable_does_not_delete_unit(self):
        self.install()
        self.run.side_effect = subprocess.CalledProcessError(1, "systemctl")
        with self.assertRaises(subprocess.CalledProcessError):
            install_scope.uninstall_monitor(self.root, "user", self.config, self.state)
        self.assertTrue(self.unit.is_file())


class ScopeServiceTests(unittest.TestCase):
    def test_user_and_system_commands_touch_only_monitor(self):
        for scope in ("user", "system"):
            for command in install_scope.SERVICE_COMMANDS:
                with self.subTest(scope=scope, command=command), patch.object(install_scope, "_run") as run, patch.object(
                        install_scope.os, "geteuid", return_value=0):
                    install_scope.service(scope, command)
                    args = run.call_args.args
                    self.assertIn("nmd-monitor.service", args)
                    self.assertEqual("--user" in args, scope == "user")
                    self.assertFalse(any("mihomo" in arg or "tailscaled" in arg or "linger" in arg for arg in args))
                    self.assertNotIn("--now", args)
                    self.assertEqual(args[0], "journalctl" if command == "logs" else "systemctl")

    def test_nonroot_system_mutation_rejected_before_commands(self):
        with patch.object(install_scope.os, "geteuid", return_value=1000), patch.object(install_scope, "_run") as run:
            for command in ("start", "stop", "restart", "enable", "disable"):
                with self.assertRaises(install_scope.ScopeError):
                    install_scope.service("system", command)
            run.assert_not_called()
            for command in ("status", "logs"):
                install_scope.service("system", command)
            self.assertEqual(run.call_count, 2)

    def test_unknown_commands_do_not_fall_through_to_network_management(self):
        with patch.object(install_scope, "_run") as run:
            for command in ("setup", "cutover", "rollback", "daemon-reload", "start mihomo"):
                with self.assertRaises(install_scope.ScopeError):
                    install_scope.service("user", command)
            run.assert_not_called()

    def test_system_unit_is_nonroot_and_hardened(self):
        text = install_scope._unit_text(Path("/opt/nmd"), "system", Path("/etc/nmd/monitor.json"), Path("/var/lib/nmd-monitor"))
        for setting in ("User=nmd-monitor", "Group=nmd-monitor", "ProtectHome=true", "ProtectSystem=strict",
                        "NoNewPrivileges=true", "CapabilityBoundingSet=", "UMask=0077", "WantedBy=multi-user.target"):
            self.assertIn(setting, text)
        self.assertIn('ReadWritePaths="/var/lib/nmd-monitor"', text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("mihomo", text)
        self.assertNotIn("tailscaled", text)

    def test_system_account_is_dedicated_and_has_no_login(self):
        account = SimpleNamespace(pw_uid=999, pw_gid=999, pw_shell="/usr/sbin/nologin")
        with patch.object(install_scope.pwd, "getpwnam", side_effect=[KeyError, account]), patch.object(
                install_scope.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=999)), patch.object(install_scope, "_run") as run:
            self.assertEqual(install_scope._ensure_system_account(), account)
            args = run.call_args.args
            self.assertEqual(args[0], "useradd")
            self.assertIn("--system", args)
            self.assertIn("--no-create-home", args)
            self.assertIn("/usr/sbin/nologin", args)
            self.assertEqual(args[-1], "nmd-monitor")

    def test_root_or_interactive_existing_account_is_rejected(self):
        for uid, gid, shell in ((0, 999, "/usr/sbin/nologin"), (999, 0, "/bin/false"), (999, 999, "/bin/bash")):
            with patch.object(install_scope.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=uid, pw_gid=gid, pw_shell=shell)), patch.object(
                    install_scope, "_run") as run:
                with self.assertRaises(install_scope.ScopeError):
                    install_scope._ensure_system_account()
                run.assert_not_called()

    def test_existing_system_group_must_match_account(self):
        account = SimpleNamespace(pw_uid=999, pw_gid=998, pw_shell="/usr/sbin/nologin")
        with patch.object(install_scope.pwd, "getpwnam", return_value=account), patch.object(
                install_scope.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=997)), patch.object(
                install_scope, "_run") as run:
            with self.assertRaises(install_scope.ScopeError):
                install_scope._ensure_system_account()
            run.assert_not_called()

    def test_service_access_rejects_root_only_config_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(install_scope.ScopeError):
                install_scope._service_access(directory, 999, 998, directory=True)

    def test_system_install_requires_root_before_files_or_commands(self):
        with patch.object(install_scope.os, "geteuid", return_value=1000), patch.object(install_scope, "_run") as run:
            with self.assertRaises(install_scope.ScopeError):
                install_scope.install_monitor(Path("/opt/nmd"), "system", Path("/etc/nmd"), Path("/var/lib/nmd-monitor"))
            run.assert_not_called()

    def test_system_code_in_user_home_is_rejected(self):
        with self.assertRaises(install_scope.ScopeError):
            install_scope._validate_system_code(Path("/home/somebody/nmd"))

    def test_unit_newline_injection_is_rejected(self):
        with self.assertRaises(install_scope.ScopeError):
            install_scope._unit_text(Path("/opt/nmd\nUser=root"), "system", Path("/etc/nmd/monitor.json"), Path("/var/lib/nmd-monitor"))


if __name__ == "__main__":
    unittest.main()
