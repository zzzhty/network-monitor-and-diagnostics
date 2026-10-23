"""User-level desktop shell lifecycle with a fake cargo and temp-only receipt.

No real build, GUI, service manager or system paths are touched.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import manager

SCRIPTS = ("manager.py", "install_scope.py", "egress_sources.py", "nmd_platform.py")


class DesktopTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.checkout = self.base / "installed-code"
        (self.checkout / "scripts").mkdir(parents=True)
        for name in SCRIPTS:
            shutil.copy2(ROOT / "scripts" / name, self.checkout / "scripts" / name)
        subprocess.run(["git", "init", "--quiet", str(self.checkout)], check=True, capture_output=True)
        crate = self.checkout / "apps/desktop/src-tauri"
        (crate / "icons").mkdir(parents=True)
        (crate / "Cargo.toml").write_text("[package]\nname = 'synthetic'\n", encoding="utf-8")
        (crate / "icons/icon.png").write_bytes(b"PNG")
        for key, value in (("home", self.checkout), ("scope", "user"),
                           ("configDir", self.base / "config/nmd"),
                           ("stateDir", self.base / "state/nmd-monitor"),
                           ("binDir", self.base / "bin"),
                           ("desktopInstalled", "false"),
                           ("desktopAutostart", "false")):
            manager.setting(self.checkout, key, value)
        self.fake_bin = self.base / "fakebin"
        self.fake_bin.mkdir()
        self.cargo_log = self.base / "cargo-args.log"
        (self.fake_bin / "cargo").write_text(
            "#!/bin/sh\n"
            f'echo \"$*|$(pwd)\" >> {shlex.quote(str(self.cargo_log))}\n'
            'if [ \"$NMD_FAKE_CARGO_FAIL\" = \"1\" ]; then exit 3; fi\n'
            "mkdir -p target/release\n"
            "printf synthetic-binary > target/release/nmd-desktop\n"
            "chmod +x target/release/nmd-desktop\n",
            encoding="utf-8")
        (self.fake_bin / "cargo").chmod(0o755)
        self.home = self.base / "home"
        self.home.mkdir()

    def invoke(self, *args, fail_cargo=False, xdg=None):
        env = dict(os.environ)
        env["PATH"] = str(self.fake_bin) + os.pathsep + "/usr/bin:/bin"
        env["HOME"] = str(self.home)
        env.pop("XDG_DATA_HOME", None)
        env.pop("XDG_CONFIG_HOME", None)
        env["NMD_FAKE_CARGO_FAIL"] = "1" if fail_cargo else "0"
        if xdg:
            env.update(xdg)
        # Exercise Linux installation logic on any host, in this private fixture
        # only. Production platform guards remain unchanged.
        wrapper = "import runpy,sys; sys.platform='linux'; sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')"
        env["PYTHONPATH"] = str(self.checkout / "scripts")
        return subprocess.run([sys.executable, "-c", wrapper, str(self.checkout / "scripts/manager.py"), "desktop", *args],
                              env=env, capture_output=True, text=True, timeout=60)

    def receipt(self, key):
        result = subprocess.run(["git", "config", "--file", str(self.checkout / ".git/config"),
                                 "--get", "nmd." + key], capture_output=True, text=True)
        return result.stdout.strip()

    def test_install_writes_bin_icon_entry_and_receipt_with_fixed_argv(self):
        result = self.invoke("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        binary = self.base / "bin/nmd-desktop"
        self.assertEqual(binary.read_bytes(), b"synthetic-binary")
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
        icon = self.home / ".local/share/icons/hicolor/32x32/apps/nmd-desktop.png"
        self.assertEqual(icon.read_bytes(), b"PNG")
        self.assertEqual(stat.S_IMODE(icon.stat().st_mode), 0o644)
        entry = self.home / ".local/share/applications/nmd-desktop.desktop"
        text = entry.read_text(encoding="utf-8")
        self.assertIn(f'Exec="{binary}"', text)
        self.assertIn("Icon=nmd-desktop", text)
        self.assertIn("Name=NMD", text)
        self.assertEqual(self.receipt("desktopInstalled"), "true")
        first = self.cargo_log.read_text().splitlines()[0]
        self.assertTrue(first.startswith("build --release --locked|"), first)
        self.assertIn("/apps/desktop/src-tauri", first)
        # Re-running is a safe rebuild + reinstall.
        self.assertEqual(self.invoke("install").returncode, 0, self.cargo_log.read_text())

    def test_install_without_cargo_fails_before_writing_anything(self):
        (self.fake_bin / "cargo").unlink()
        result = self.invoke("install")
        self.assertEqual(result.returncode, 1)
        self.assertIn("desktop_requires_cargo", result.stderr)
        self.assertEqual(self.receipt("desktopInstalled"), "false")
        self.assertFalse((self.base / "bin/nmd-desktop").exists())

    def test_failing_cargo_leaves_system_untouched(self):
        result = self.invoke("install", fail_cargo=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("desktop_build_failed", result.stderr)
        self.assertFalse((self.checkout / "apps/desktop/src-tauri/target/release/nmd-desktop").exists())
        self.assertFalse((self.base / "bin/nmd-desktop").exists())
        self.assertEqual(self.receipt("desktopInstalled"), "false")

    def test_autostart_requires_install_then_toggles(self):
        denied = self.invoke("autostart", "on")
        self.assertEqual(denied.returncode, 1)
        self.assertIn("desktop_not_installed", denied.stderr)
        self.assertEqual(self.invoke("install").returncode, 0)
        enabled = self.invoke("autostart", "on")
        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        autostart = self.home / ".config/autostart/nmd-desktop.desktop"
        self.assertTrue(autostart.is_file())
        self.assertEqual(self.receipt("desktopAutostart"), "true")
        self.assertEqual(self.invoke("autostart", "off").returncode, 0)
        self.assertFalse(autostart.exists())
        self.assertEqual(self.receipt("desktopAutostart"), "false")

    def test_uninstall_removes_installed_files_and_autostart(self):
        self.assertEqual(self.invoke("install").returncode, 0)
        self.assertEqual(self.invoke("autostart", "on").returncode, 0)
        preserved = [self.base / "config/nmd/user.json", self.base / "state/nmd-monitor/user.sqlite"]
        for path in preserved:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"existing user data")
        removed = self.invoke("uninstall")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse((self.base / "bin/nmd-desktop").exists())
        self.assertFalse((self.home / ".local/share/icons/hicolor/32x32/apps/nmd-desktop.png").exists())
        self.assertFalse((self.home / ".local/share/applications/nmd-desktop.desktop").exists())
        self.assertFalse((self.home / ".config/autostart/nmd-desktop.desktop").exists())
        self.assertEqual(self.receipt("desktopInstalled"), "false")
        self.assertEqual(self.receipt("desktopAutostart"), "false")
        for path in preserved:
            self.assertEqual(path.read_bytes(), b"existing user data")

    def test_status_reports_without_installing(self):
        before = self.invoke("status")
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertIn("未安装", before.stdout)
        self.assertEqual(self.invoke("install").returncode, 0)
        after = self.invoke("status")
        self.assertIn("已安装", after.stdout)
        self.assertIn(str(self.base / "bin/nmd-desktop"), after.stdout)

    def test_usage_and_platform_guards(self):
        bad_usage = self.invoke("frobnicate")
        self.assertEqual(bad_usage.returncode, 1)
        self.assertIn("用法:", bad_usage.stderr)
        # The platform guard is checked in-process: patch here and call the
        # dispatcher directly instead of hoping a subprocess inherits the patch.
        with patch("sys.platform", "darwin"):
            with self.assertRaisesRegex(manager.ManagerError, "desktop_requires_linux"):
                manager.desktop_main(self.checkout, ["status"])

    def test_receipt_paths_stay_inside_recorded_bin_dir(self):
        self.assertEqual(self.invoke("install").returncode, 0)
        self.assertTrue((self.base / "bin/nmd-desktop").is_file())
        self.assertEqual(Path(self.receipt("binDir")), self.base / "bin")


    def destinations(self):
        return {"binary": self.base / "bin/nmd-desktop",
                "icon": self.home / ".local/share/icons/hicolor/32x32/apps/nmd-desktop.png",
                "entry": self.home / ".local/share/applications/nmd-desktop.desktop",
                "autostart": self.home / ".config/autostart/nmd-desktop.desktop"}

    def test_foreign_files_are_preserved_before_any_install_write(self):
        for key, path in self.destinations().items():
            with self.subTest(key=key):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"foreign-user-data")
                result = self.invoke("install")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("desktop_file_not_owned", result.stderr)
                self.assertEqual(path.read_bytes(), b"foreign-user-data")
                self.assertEqual(self.receipt("desktopInstalled"), "false")
                for other in self.destinations().values():
                    if other != path: self.assertFalse(other.exists())
                path.unlink()

    def test_uninstalled_uninstall_and_autostart_off_preserve_foreign_files(self):
        for action in [("uninstall",), ("autostart", "off")]:
            path = self.destinations()["autostart"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("foreign")
            result = self.invoke(*action)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("desktop_file_not_owned", result.stderr)
            self.assertEqual(path.read_text(), "foreign")
            path.unlink()
        self.assertEqual(self.invoke("uninstall").returncode, 0)
        self.assertEqual(self.invoke("autostart", "off").returncode, 0)

    def test_legacy_boolean_receipt_never_claims_unmarked_files(self):
        manager.setting(self.checkout, "desktopInstalled", "true")
        binary = self.destinations()["binary"]
        binary.parent.mkdir(parents=True)
        binary.write_text("legacy-or-foreign")
        for action in [("install",), ("uninstall",)]:
            result = self.invoke(*action)
            self.assertEqual(result.returncode, 1)
            self.assertIn("desktop_file_not_owned", result.stderr)
            self.assertEqual(binary.read_text(), "legacy-or-foreign")

    def test_symlinks_and_linked_parent_paths_are_never_modified(self):
        victim = self.base / "user-data"
        victim.write_text("keep")
        binary = self.destinations()["binary"]
        binary.parent.mkdir(parents=True)
        binary.symlink_to(victim)
        for action in [("install",), ("uninstall",)]:
            self.assertEqual(self.invoke(*action).returncode, 1)
            self.assertTrue(binary.is_symlink())
            self.assertEqual(victim.read_text(), "keep")
        binary.unlink()
        binary.parent.rmdir()
        foreign_dir = self.base / "foreign-bin"
        foreign_dir.mkdir()
        binary.parent.symlink_to(foreign_dir, target_is_directory=True)
        self.assertEqual(self.invoke("install").returncode, 1)
        self.assertEqual(list(foreign_dir.iterdir()), [])

    def test_replaced_owned_file_blocks_all_uninstall_deletions(self):
        self.assertEqual(self.invoke("install").returncode, 0)
        paths = self.destinations()
        paths["entry"].write_text("new user file")
        result = self.invoke("uninstall")
        self.assertEqual(result.returncode, 1)
        self.assertIn("desktop_file_not_owned", result.stderr)
        self.assertTrue(paths["binary"].is_file())
        self.assertTrue(paths["icon"].is_file())
        self.assertEqual(paths["entry"].read_text(), "new user file")

    def test_saved_paths_survive_xdg_and_bin_directory_changes(self):
        self.assertEqual(self.invoke("install").returncode, 0)
        original = self.destinations()
        manager.setting(self.checkout, "binDir", self.base / "other-bin")
        xdg = {"XDG_DATA_HOME": str(self.base / "other-data"),
               "XDG_CONFIG_HOME": str(self.base / "other-config")}
        self.assertEqual(self.invoke("install", xdg=xdg).returncode, 0)
        self.assertEqual(self.invoke("autostart", "on", xdg=xdg).returncode, 0)
        self.assertTrue(original["autostart"].is_file())
        self.assertEqual(self.invoke("uninstall", xdg=xdg).returncode, 0)
        self.assertTrue(all(not p.exists() for p in original.values()))
        self.assertFalse((self.base / "other-bin").exists())
        self.assertFalse((self.base / "other-data").exists())
        self.assertFalse((self.base / "other-config").exists())

    def test_foreign_autostart_blocks_toggle_and_uninstall(self):
        self.assertEqual(self.invoke("install").returncode, 0)
        path = self.destinations()["autostart"]
        path.parent.mkdir(parents=True)
        path.write_text("foreign startup")
        for action in [("autostart", "on"), ("autostart", "off"), ("uninstall",)]:
            self.assertEqual(self.invoke(*action).returncode, 1)
            self.assertEqual(path.read_text(), "foreign startup")
            self.assertTrue(self.destinations()["binary"].exists())

    def test_stale_fixed_temp_symlink_is_not_followed(self):
        binary = self.destinations()["binary"]
        binary.parent.mkdir(parents=True)
        victim = self.base / "user-file"
        victim.write_text("keep")
        alias = binary.parent / ("." + binary.name + ".tmp")
        alias.symlink_to(victim)
        result = self.invoke("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(victim.read_text(), "keep")
        self.assertTrue(alias.is_symlink())


if __name__ == "__main__":
    unittest.main()
