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
import macos_preflight
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
        kwargs.setdefault("probe_version", lambda path: {"status": "pass", "parsed": (1, 19, 33)})
        kwargs.setdefault("stdin_is_tty", False)
        kwargs.setdefault("read_line", lambda: (_ for _ in ()).throw(AssertionError("read")))
        with contextlib.ExitStack() as stack:
            for item in bombs:
                stack.enter_context(item)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = nmd_onboard.main(list(argv), **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_darwin_release_assets_and_linux_defaults(self):
        version = nmd_onboard.darwin_release_version()
        self.assertGreaterEqual(nmd_onboard.DARWIN_MIHOMO_VERSION,
                                macos_preflight.NATIVE_DNS_MODE_VERSION)
        self.assertEqual(version, "v1.19.34")
        for host, arch in (("arm64", "arm64"), ("x86_64", "amd64")):
            with self.subTest(host=host):
                self.assertEqual(nmd_onboard.darwin_asset_url(version, host),
                                 "https://github.com/MetaCubeX/mihomo/releases/download/"
                                 f"v1.19.34/mihomo-darwin-{arch}-v1.19.34.gz")
        text = (ROOT / "fetch-assets.sh").read_text(encoding="utf-8")
        self.assertIn("mihomo-linux-$ARCH-$VER.deb", text)
        self.assertIn("VPS_PORT=1080", (ROOT / "local-setup.sh").read_text(encoding="utf-8"))
        self.assertEqual(nmd_onboard.LINUX_SOCKS_PORT, 1080)

    def test_existing_old_or_unknown_mihomo_is_not_overwritten(self):
        for result, error in (
                ({"status": "pass", "parsed": (1, 19, 30)}, "unsupported"),
                ({"status": "unknown", "parsed": None}, "unknown"),
                ({"status": "unknown", "parsed": (1, 19, 34)}, "unknown")):
            with self.subTest(result=result):
                code, out, err = self.invoke(
                    ["--server", SERVER4, "--port", "1081"], platform="macos",
                    find_tailscale=lambda platform: "/usr/local/bin/tailscale",
                    find_mihomo=lambda platform: "/usr/local/bin/mihomo",
                    probe_version=lambda path: result,
                    download=AssertionError("do not replace an existing binary"))
                self.assertEqual(code, 1, err)
                self.assertEqual(out, "")
                self.assertEqual(json.loads(err)["error"], f"mihomo_native_dns_version_{error}")
                self.assertFalse(self.daemon.exists())

    def test_existing_config_checks_its_preserved_mihomo_override(self):
        old = str(self.bindir / "mihomo")
        nmd_daemon.write_daemon_config(self.daemon, {
            "schema_version": 1, "dashboard": {"port": 8765},
            "takeover": {"inputs": {"proxy_name": "VPS", "server": SERVER4, "port": 1080},
                         "profile": None, "on_boot": False, "check_interval_seconds": 20,
                         "critical_failures": 3, "mihomo_path": old, "state_dir": None}})
        original = self.daemon.read_bytes()
        probes = []

        def probe(path):
            probes.append(path)
            return {"status": "pass", "parsed": (1, 19, 30)}

        code, _, err = self.invoke(
            ["--server", SERVER, "--port", "1081"], platform="macos",
            find_tailscale=lambda platform: "/usr/local/bin/tailscale",
            find_mihomo=lambda platform: "/usr/local/bin/mihomo", probe_version=probe)
        self.assertEqual(code, 1, err)
        self.assertEqual(probes, [old])
        self.assertEqual(self.daemon.read_bytes(), original)

    def test_existing_disabled_dns_profile_does_not_require_native_version(self):
        profile = json.loads((ROOT / "examples/macos-mihomo-coexist.experiment.json").read_text())
        self.assertEqual(profile["dns_mode"]["selected"], "native")
        profile["dns_mode"]["selected"] = "disabled"
        profile["dns_mode"]["system_dns"] = None
        original = {"schema_version": 1, "dashboard": {"port": 8765},
                    "takeover": {"inputs": {"proxy_name": "VPS", "server": SERVER4, "port": 1080},
                                 "profile": profile, "on_boot": False, "check_interval_seconds": 20,
                                 "critical_failures": 3, "mihomo_path": None, "state_dir": None}}
        nmd_daemon.write_daemon_config(self.daemon, original)
        code, _, err = self.invoke(
            ["--server", SERVER, "--port", "1081"], platform="macos",
            find_tailscale=lambda platform: "/usr/local/bin/tailscale",
            find_mihomo=lambda platform: "/usr/local/bin/mihomo",
            probe_version=lambda path: self.fail("disabled DNS has no native version gate"))
        self.assertEqual(code, 0, err)
        self.assertEqual(nmd_daemon.load_daemon_config(self.daemon)["takeover"]["profile"], profile)

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
        self.assertTrue(self.calls[0][1].endswith("/v1.19.34/mihomo-darwin-arm64-v1.19.34.gz"))
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

    def test_linux_same_address_still_requires_a_trusted_endpoint(self):
        parent = self.env.parent
        parent.mkdir(mode=0o700)
        body = f"NMD_VPS_TS_IP={SERVER4}\n"
        self.env.write_text(body, encoding="utf-8")
        os.chmod(self.env, 0o600)
        finders = dict(find_tailscale=lambda platform: "/usr/bin/tailscale",
                       find_mihomo=lambda platform: "/usr/bin/mihomo")
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux", **finders)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.env.read_text(encoding="utf-8"), body)
        self.assertNotIn("fetch", self.calls)

        os.chmod(self.env, 0o666)
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux", **finders)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_group_or_world_writable")
        self.assertEqual(self.env.read_text(encoding="utf-8"), body)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode) & 0o777, 0o666)
        self.assertNotIn("fetch", self.calls)
        os.chmod(self.env, 0o600)

        os.chmod(parent, 0o777)
        code, out, err = self.invoke(
            ["--server", "100.64.0.9", "--port", "1080"], platform="linux", **finders)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_group_or_world_writable")
        self.assertEqual(self.env.read_text(encoding="utf-8"), body)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode) & 0o777, 0o777)
        self.assertNotIn("fetch", self.calls)
        os.chmod(parent, 0o700)

        real = self.base / "real-config"
        real.mkdir(mode=0o700)
        target = real / "nmd-local.env"
        target.write_text(body, encoding="utf-8")
        os.chmod(target, 0o600)
        linked = self.base / "linked-config"
        linked.symlink_to(real, target_is_directory=True)
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux",
            env_path=linked / "nmd-local.env", **finders)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_not_regular")
        self.assertEqual(target.read_text(encoding="utf-8"), body)
        self.assertTrue(linked.is_symlink())
        self.assertNotIn("fetch", self.calls)

        wide = self.base / "wide-new"
        wide.mkdir(mode=0o777)
        os.chmod(wide, 0o777)
        missing = wide / "nmd-local.env"
        before = list(self.calls)
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux",
            env_path=missing, find_tailscale=finders["find_tailscale"],
            find_mihomo=lambda platform: None)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_group_or_world_writable")
        self.assertEqual(self.calls, before)
        self.assertFalse(missing.exists())
        self.assertEqual(stat.S_IMODE(wide.stat().st_mode) & 0o777, 0o777)

        self.env.write_text("NMD_VPS_TS_IP=100.64.0.9\n", encoding="utf-8")
        os.chmod(self.env, 0o600)
        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux", **finders)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.env.read_text(encoding="utf-8"), body)

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
        self.assertIn("不是交互终端", out)
        self.assertIn("确认之前不检查组件", out)
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

        with patch.object(nmd_platform, "name", return_value="macos"), \
                patch("nmd_onboard.main", return_value=0) as onboard:
            with self.assertRaises(SystemExit) as caught:
                manager.main(["onboard"])
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(onboard.call_args.args[0], [])

    def error_body(self, err):
        start = err.rfind("\n{")
        start = err.find("{") if start == -1 else start + 1
        self.assertGreaterEqual(start, 0, err)
        return json.loads(err[start:])

    def answers(self, lines):
        pending = iter(lines)

        def read():
            try:
                return next(pending)
            except StopIteration as exc:
                raise EOFError from exc
        return read

    def test_interactive_retries_then_records_after_confirmation(self):
        seen = []

        def download(url):
            self.assertIn("请核对", "".join(seen))
            self.assertIn(SERVER, "".join(seen))
            self.calls.append(("download", url))
            return macho_gzip()

        def tailscale(platform):
            self.assertIn("请核对", "".join(seen))
            return "/usr/bin/tailscale"

        code, out, err = self.invoke(
            [], platform="macos", stdin_is_tty=True,
            read_line=self.answers([
                "8.8.8.8", "203.0.113.20", SERVER, "22", "nope", "1081", "DIRECT", "Work", "是"]),
            prompt_write=seen.append, download=download, find_tailscale=tailscale,
            find_mihomo=lambda platform: None)
        self.assertEqual(code, 0, err)
        self.assertNotIn(SERVER, out)
        body = json.loads(out)
        self.assertEqual(body["result"], "configured")
        self.assertIs(body["on_boot"], False)
        self.assertIs(body["mihomo_installed"], True)
        self.assertIs(body["takeover_started"], False)
        self.assertIs(body["apply_ran"], False)
        stored = json.loads(self.daemon.read_text(encoding="utf-8"))
        self.assertEqual(stored["takeover"]["inputs"]["server"], SERVER)
        self.assertEqual(stored["takeover"]["inputs"]["port"], 1081)
        self.assertEqual(stored["takeover"]["inputs"]["proxy_name"], "Work")
        self.assertIs(stored["takeover"]["on_boot"], False)
        self.assertIn("请重新填写", "".join(seen))
        self.assertTrue(self.calls)

    def test_interactive_explicit_flag_and_linux_defaults(self):
        seen = []
        code, out, err = self.invoke(
            ["--interactive"], platform="linux", stdin_is_tty=True,
            read_line=self.answers([SERVER, SERVER4, "1081", "", "", "y"]),
            prompt_write=seen.append,
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: "/usr/bin/mihomo")
        self.assertEqual(code, 0, err)
        self.assertNotIn(SERVER4, out)
        text = "".join(seen)
        self.assertIn("端口 [1080]", text)
        self.assertIn("代理名会核对", text)
        self.assertIn(SERVER4, text)
        self.assertEqual(self.env.read_text(encoding="utf-8"), f"NMD_VPS_TS_IP={SERVER4}\n")
        self.assertNotIn("proxy", self.env.read_text(encoding="utf-8"))
        self.assertNotIn("fetch", self.calls)
        self.assertNotIn("download", [item[0] for item in self.calls if isinstance(item, tuple)])

    def test_cancel_eof_and_keyboard_interrupt_write_nothing(self):
        for answers, token in (
                (["100.64.0.8", "1081", "VPS", ""], "confirmation_declined"),
                (["100.64.0.8", "1081", "VPS", "n"], "confirmation_declined"),
                ([], "input_cancelled")):
            self.calls.clear()
            code, out, err = self.invoke(
                [], platform="macos", stdin_is_tty=True,
                read_line=self.answers(answers),
                find_tailscale=AssertionError("tailscale"),
                download=AssertionError("download"))
            self.assertEqual(code, 1, answers)
            self.assertEqual(out, "")
            body = self.error_body(err)
            self.assertEqual(body["error"], token)
            self.assertIn("没有下载", body["remediation"])
            self.assertNotIn("Tailnet 地址", out)
            self.assertFalse(self.daemon.exists())
            self.assertEqual(self.calls, [])

        def interrupt():
            raise KeyboardInterrupt

        code, out, err = self.invoke(
            ["--interactive"], platform="linux", stdin_is_tty=True, read_line=interrupt,
            fetch_linux_assets=AssertionError("fetch"),
            find_tailscale=AssertionError("tailscale"))
        self.assertEqual(code, 1)
        self.assertEqual(self.error_body(err)["error"], "input_cancelled")
        self.assertFalse(self.env.exists())

    def test_non_tty_does_not_read_and_flags_still_skip_prompts(self):
        code, out, err = self.invoke(
            [], platform="macos", stdin_is_tty=False,
            read_line=AssertionError("read"),
            find_tailscale=AssertionError("tailscale"))
        self.assertEqual(code, 1)
        body = json.loads(err)
        self.assertEqual(body["error"], "not_a_terminal")
        self.assertIn("--inputs", body["remediation"])
        self.assertNotIn("Tailnet 地址", err)
        self.assertFalse(self.daemon.exists())

        code, out, err = self.invoke(
            ["--interactive"], platform="linux", stdin_is_tty=False,
            read_line=AssertionError("read"))
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "not_a_terminal")

        code, out, err = self.invoke(
            ["--server", SERVER4, "--port", "1080"], platform="linux",
            stdin_is_tty=True, read_line=AssertionError("read"),
            find_tailscale=lambda platform: "/usr/bin/tailscale",
            find_mihomo=lambda platform: "/usr/bin/mihomo")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.env.read_text(encoding="utf-8"), f"NMD_VPS_TS_IP={SERVER4}\n")

        code, out, err = self.invoke(
            ["--interactive", "--server", SERVER4], platform="macos",
            stdin_is_tty=True, read_line=AssertionError("read"))
        self.assertEqual(code, 2)
        self.assertIn("不能和这些参数一起用", err)
        self.assertFalse(self.daemon.exists())

        with patch.object(nmd_onboard.os, "geteuid", return_value=0):
            code, out, err = self.invoke(
                [], platform="macos", stdin_is_tty=True, read_line=AssertionError("read"))
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "root_refused")

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
