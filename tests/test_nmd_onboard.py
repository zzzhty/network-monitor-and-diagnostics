"""nmd onboard: fail closed, and do not install Tailscale on macOS."""
import contextlib
import gzip
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))

import macos_coexist
import nmd_daemon
import nmd_onboard
import nmd_platform
SERVER = "fd7a:115c:a1e0::abcd"
SERVER4 = "100.64.0.8"


def macho_gzip():
    return gzip.compress(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)


class OnboardTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name)
        self.daemon = self.base / "config" / "daemon.json"
        self.env = self.base / "config" / "nmd-local.env"
        self.bindir = self.base / "bin"
        self.bindir.mkdir(mode=0o700)
        self.calls = []

    def download(self, url):
        self.calls.append(("download", url))
        return macho_gzip()

    def fetch(self):
        self.calls.append("fetch")

    def invoke(self, argv, **kwargs):
        bombs = (
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            patch("manager.ensure_assets", side_effect=AssertionError("ensure")),
            patch("manager.apply", side_effect=AssertionError("apply")),
            patch("manager.activate", side_effect=AssertionError("activate")),
            patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")),
            patch.object(nmd_daemon, "cli_daemon", side_effect=AssertionError("daemon-cli")),
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        kwargs.setdefault("download", self.download)
        kwargs.setdefault("fetch_linux_assets", self.fetch)
        kwargs.setdefault("daemon_path", self.daemon)
        kwargs.setdefault("env_path", self.env)
        kwargs.setdefault("install_directories", [])
        kwargs.setdefault("fallback_dir", self.bindir)
        kwargs.setdefault("machine", "arm64")
        with contextlib.ExitStack() as stack:
            for item in bombs:
                stack.enter_context(item)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = nmd_onboard.main(list(argv), **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_release_url_matches_fetch_assets_version(self):
        version = nmd_onboard.release_version(ROOT)
        text = (ROOT / "fetch-assets.sh").read_text(encoding="utf-8")
        self.assertIn(f"VER={version}", text)
        self.assertIn("mihomo-linux-$ARCH-$VER.deb", text)
        url = nmd_onboard.darwin_asset_url(version, "arm64")
        self.assertEqual(
            url,
            f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/"
            f"mihomo-darwin-arm64-{version}.gz")
        self.assertIn("VPS_PORT=1080", (ROOT / "local-setup.sh").read_text(encoding="utf-8"))
        self.assertEqual(nmd_onboard.LINUX_SOCKS_PORT, 1080)

    def test_macos_stops_when_tailscale_is_missing_and_does_not_download(self):
        code, out, err = self.invoke(
            ["--server", SERVER, "--port", "1081"], platform="macos",
            find_tailscale=lambda platform: None,
            find_mihomo=lambda platform: None,
            download=AssertionError("download"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        body = json.loads(err)
        self.assertEqual(body["error"], "tailscale_missing")
        self.assertIn("不会下载或安装 Tailscale", body["remediation"])
        self.assertNotIn(SERVER, err)
        self.assertFalse(self.daemon.exists())
        self.assertEqual(self.calls, [])
        self.assertFalse(any(self.bindir.iterdir()))

    def test_macos_installs_mihomo_then_records_the_address(self):
        code, out, err = self.invoke(
            ["--server", SERVER, "--port", "1081", "--proxy-name", "VPS"],
            platform="macos",
            find_tailscale=lambda platform: "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
            find_mihomo=lambda platform: None)
        self.assertEqual(code, 0, err)
        self.assertNotIn(SERVER, out)
        body = json.loads(out)
        self.assertEqual(body["result"], "configured")
        self.assertIs(body["on_boot"], False)
        self.assertIs(body["mihomo_installed"], True)
        self.assertIs(body["loaded_daemon"], False)
        self.assertIs(body["takeover_started"], False)
        self.assertIs(body["apply_ran"], False)
        self.assertEqual(self.calls[0][0], "download")
        self.assertIn("mihomo-darwin-arm64-", self.calls[0][1])
        self.assertNotIn("fetch", self.calls)
        binary = self.bindir / "mihomo"
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode) & 0o777, 0o755)
        self.assertEqual(binary.stat().st_uid, os.geteuid())
        self.assertFalse(binary.is_symlink())
        stored = json.loads(self.daemon.read_text(encoding="utf-8"))
        self.assertIs(stored["takeover"]["on_boot"], False)
        self.assertEqual(stored["takeover"]["inputs"]["server"], SERVER)
        self.assertEqual(stored["takeover"]["inputs"]["port"], 1081)
        self.assertEqual(stored["takeover"]["mihomo_path"], str(binary))
        self.assertIn('"on_boot": false', self.daemon.read_text(encoding="utf-8"))
        self.assertNotIn("203.0.113.20", self.daemon.read_text(encoding="utf-8"))

    def test_macos_does_not_download_when_mihomo_is_already_present(self):
        present = "/opt/homebrew/bin/mihomo"
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="macos",
            find_tailscale=lambda platform: "/usr/local/bin/tailscale",
            find_mihomo=lambda platform: present,
            download=AssertionError("download"))
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertIs(body["mihomo_installed"], False)
        self.assertEqual(body["mihomo"], present)
        stored = nmd_daemon.load_daemon_config(self.daemon)
        self.assertIsNone(stored["takeover"]["mihomo_path"])
        self.assertIs(stored["takeover"]["on_boot"], False)
        self.assertEqual(self.calls, [])

    def test_macos_preserves_on_boot_and_does_not_turn_it_on(self):
        nmd_daemon.write_daemon_config(self.daemon, {
            "schema_version": 1,
            "dashboard": {"port": 8765},
            "takeover": {
                "inputs": {"proxy_name": "VPS", "server": SERVER4, "port": 1080},
                "profile": None, "on_boot": False, "check_interval_seconds": 20,
                "critical_failures": 3, "mihomo_path": None, "state_dir": None}})
        code, out, err = self.invoke(
            ["--server", SERVER, "--port", "1081"], platform="macos",
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: "/usr/local/bin/mihomo")
        self.assertEqual(code, 0, err)
        self.assertIs(json.loads(out)["on_boot"], False)
        self.assertEqual(nmd_daemon.load_daemon_config(self.daemon)["takeover"]["inputs"]["server"],
                         SERVER)
        turned = json.loads(self.daemon.read_text(encoding="utf-8"))
        turned["takeover"]["on_boot"] = True
        self.daemon.write_text(json.dumps(turned), encoding="utf-8")
        os.chmod(self.daemon, 0o600)
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="macos",
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: "/usr/local/bin/mihomo")
        self.assertEqual(code, 0, err)
        self.assertIs(json.loads(out)["on_boot"], True)
        self.assertIs(nmd_daemon.load_daemon_config(self.daemon)["takeover"]["on_boot"], True)
        self.assertIs(json.loads(out)["takeover_started"], False)

    def test_macos_bad_download_or_no_directory_writes_nothing(self):
        code, out, err = self.invoke(
            ["--server", SERVER, "--port", "1081"], platform="macos",
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: None,
            download=lambda url: b"not-gzip")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "mihomo_download_invalid")
        self.assertFalse(self.daemon.exists())
        self.assertFalse((self.bindir / "mihomo").exists())

        code, out, err = self.invoke(
            ["--server", SERVER, "--port", "1081"], platform="macos",
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: None,
            install_directories=[], fallback_dir=None,
            download=AssertionError("download"))
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "mihomo_install_unavailable")
        self.assertIn("没有写入配置", json.loads(err)["remediation"])
        self.assertFalse(self.daemon.exists())

    def test_rejects_placeholder_and_public_addresses_before_download(self):
        for server, token in (("203.0.113.20", "placeholder_inputs"),
                              ("8.8.8.8", "invalid_server")):
            code, out, err = self.invoke(
                ["--server", server, "--port", "1080"], platform="macos",
                find_tailscale=AssertionError("tailscale"),
                find_mihomo=AssertionError("mihomo"),
                download=AssertionError("download"))
            self.assertEqual(code, 1, server)
            self.assertEqual(json.loads(err)["error"], token)
            self.assertFalse(self.daemon.exists())

    def test_root_refuses_before_home_or_download(self):
        with patch.object(nmd_onboard.os, "geteuid", return_value=0), \
                patch.object(nmd_onboard.Path, "home", side_effect=AssertionError("home")):
            code, out, err = self.invoke(
                ["--server", SERVER4, "--port", "1080"], platform="macos",
                download=AssertionError("download"),
                find_tailscale=AssertionError("tailscale"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["error"], "root_refused")
        self.assertFalse(self.daemon.exists())

    def test_linux_stops_without_tailscale_or_an_installed_mihomo(self):
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux",
            find_tailscale=lambda platform: None,
            find_mihomo=lambda platform: None)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "tailscale_missing")
        self.assertNotIn("fetch", self.calls)
        self.assertFalse(self.env.exists())

        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux",
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: None)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "mihomo_not_installed")
        self.assertIn("不会执行 dpkg", json.loads(err)["remediation"])
        self.assertEqual(self.calls, ["fetch"])
        self.assertFalse(self.env.exists())
        self.assertNotIn(SERVER4, out + err)

    def test_linux_records_only_the_tailnet_address(self):
        code, out, err = self.invoke(
            ["--inputs", str(self.write_inputs())], platform="linux",
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: "/usr/bin/mihomo")
        self.assertEqual(code, 0, err)
        self.assertNotIn(SERVER4, out)
        body = json.loads(out)
        self.assertNotIn("on_boot", body)
        self.assertIs(body["apply_ran"], False)
        self.assertIs(body["takeover_started"], False)
        self.assertNotIn("fetch", self.calls)
        text = self.env.read_text(encoding="utf-8")
        self.assertEqual(text, f"NMD_VPS_TS_IP={SERVER4}\n")
        self.assertNotIn("203.0.113", text)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode) & 0o777, 0o600)

    def test_linux_placeholder_public_address_stops_before_fetch(self):
        self.env.parent.mkdir(parents=True, exist_ok=True)
        self.env.write_text("NMD_VPS_TS_IP=100.64.0.1\nNMD_VPS_PUB=203.0.113.10\n",
                            encoding="utf-8")
        os.chmod(self.env, 0o600)
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux",
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: None)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "placeholder_inputs")
        self.assertNotIn("fetch", self.calls)
        self.assertIn("NMD_VPS_PUB=203.0.113.10", self.env.read_text(encoding="utf-8"))

    def test_linux_rejects_ipv6_and_a_nondefault_port_before_fetch(self):
        for argv, token in (
                (["--server", SERVER, "--port", "1080"], "linux_requires_ipv4"),
                (["--server", SERVER4, "--port", "1081"], "linux_port_fixed")):
            code, out, err = self.invoke(
                argv, platform="linux",
                find_tailscale=AssertionError("tailscale"),
                fetch_linux_assets=AssertionError("fetch"))
            self.assertEqual(code, 1, argv)
            self.assertEqual(json.loads(err)["error"], token)
            self.assertFalse(self.env.exists())

    def test_unsafe_directory_and_symlink_are_not_used(self):
        unsafe = self.base / "unsafe"
        unsafe.mkdir(mode=0o700)
        os.chmod(unsafe, 0o777)
        self.assertIsNone(nmd_onboard.choose_install_dir([unsafe], None))
        link = self.base / "linked"
        link.symlink_to(self.bindir, target_is_directory=True)
        self.assertIsNone(nmd_onboard.choose_install_dir([link], None))
        self.assertEqual(nmd_onboard.choose_install_dir([], self.bindir), self.bindir)

    def test_help_and_manager_dispatch(self):
        import manager
        code, out, err = self.invoke(["--help"], platform="windows")
        self.assertEqual(code, 0)
        self.assertIn("不下载、不安装 Tailscale", out)
        self.assertEqual(err, "")

        with patch.object(nmd_platform, "name", return_value="windows"):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    manager.main(["onboard", "--server", SERVER4, "--port", "1080"])
            self.assertEqual(caught.exception.code, 1)
            self.assertEqual(json.loads(stderr.getvalue())["error"], "unsupported_platform")

        with patch.object(nmd_platform, "name", return_value="linux"), \
                patch("nmd_onboard.main", return_value=0) as onboard:
            with self.assertRaises(SystemExit) as caught:
                manager.main(["onboard", "--server", SERVER4, "--port", "1080"])
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(onboard.call_args.args[0], ["--server", SERVER4, "--port", "1080"])

    def write_inputs(self):
        path = self.base / "inputs.json"
        path.write_text(json.dumps({"server": SERVER4, "port": 1080, "proxy_name": "VPS"}),
                        encoding="utf-8")
        os.chmod(path, 0o600)
        return path


class PolicyTests(unittest.TestCase):
    def test_boot_policy_is_unchanged(self):
        policy = macos_coexist.DAEMON_POLICY
        self.assertIs(policy["takeover_on_boot_default"], False)
        self.assertIs(policy["same_boot_keepalive_restart_never_resumes"], True)
        self.assertIs(policy["wake_does_not_start_takeover"], True)


if __name__ == "__main__":
    unittest.main()
