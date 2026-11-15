"""Windows local-monitor contracts. Fixtures only; no host metadata or task registration."""
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import install_scope
import manager
import nmd_monitor
import nmd_platform
import nmd_windows
import observability


SAMPLE = "\r\n".join([
    "IF|Ethernet|Up",
    "IF|以太网|Disconnected",
    "RT|192.0.2.0/24",
    "RT|0.0.0.0/0",
    "RT|10.0.0.0/8",
    "RT|0.0.0.0/0",
    "",
])


class InterpreterTests(unittest.TestCase):
    def test_blocked_launchers_are_named_without_executing_them(self):
        self.assertEqual(
            nmd_windows.blocked_reason(r"C:\Users\Max\.local\bin\python.exe"),
            "smart_app_control_local_bin")
        self.assertEqual(
            nmd_windows.blocked_reason(r"C:/Users/Max/.local/bin/python.exe"),
            "smart_app_control_local_bin")
        self.assertEqual(
            nmd_windows.blocked_reason(r"C:\Users\Max\AppData\Local\Microsoft\WindowsApps\python.exe"),
            "windowsapps_stub")
        real = r"C:\Users\Max\AppData\Roaming\uv\python\cpython-3.13.12-windows-x86_64-none\python.exe"
        self.assertIsNone(nmd_windows.blocked_reason(real))

    def test_uv_venv_is_blocked_and_stdlib_venv_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            uv_root = base / "uv-env"
            scripts = uv_root / "Scripts"
            scripts.mkdir(parents=True)
            uv_python = scripts / "python.exe"
            uv_python.write_bytes(b"")
            (uv_root / "pyvenv.cfg").write_text("home = C:\\Python\nuv = 0.9.5\n", encoding="utf-8")
            std_root = base / "stdlib-env"
            std_scripts = std_root / "Scripts"
            std_scripts.mkdir(parents=True)
            std_python = std_scripts / "python.exe"
            std_python.write_bytes(b"")
            (std_root / "pyvenv.cfg").write_text(
                "home = C:\\Python313\ninclude-system-site-packages = false\nversion = 3.13.12\n",
                encoding="utf-8")
            self.assertEqual(nmd_windows.blocked_reason(uv_python), "smart_app_control_uv_venv")
            self.assertIsNone(nmd_windows.blocked_reason(std_python))
            with self.assertRaises(nmd_windows.InterpreterError) as caught:
                nmd_windows.require_interpreter(uv_python)
        message = str(caught.exception)
        self.assertIn("python -m venv --without-pip", message)
        self.assertIn("Smart App Control", message)
        self.assertNotIn("\nuv venv", message)

    def test_user_path_merge_avoids_local_bin(self):
        profile = Path("C:/Users/Max")
        paths = nmd_windows.user_paths(profile)
        self.assertEqual(paths["home"], profile / "AppData" / "Local" / "nmd")
        self.assertEqual(paths["bin_dir"], profile / "AppData" / "Local" / "nmd-bin")
        self.assertEqual(paths["config_dir"], profile / "AppData" / "Roaming" / "nmd")
        self.assertEqual(paths["state_dir"], profile / "AppData" / "Local" / "nmd-monitor")
        self.assertTrue(nmd_windows.command_dir_blocked(profile / ".local" / "bin"))
        self.assertFalse(nmd_windows.command_dir_blocked(paths["bin_dir"]))
        self.assertTrue(nmd_windows.command_inside_checkout(paths["home"], paths["home"] / "bin"))
        merged = nmd_windows.merge_user_path(r"C:\Windows", paths["bin_dir"])
        self.assertEqual(merged, str(paths["bin_dir"]) + r";C:\Windows")
        self.assertIsNone(nmd_windows.merge_user_path(merged, paths["bin_dir"]))
        self.assertEqual(nmd_windows.remove_user_path(merged, paths["bin_dir"]), r"C:\Windows")


class SamplerTests(unittest.TestCase):
    def test_fixture_reports_adapters_and_default_routes_without_gateways(self):
        run = Mock(return_value=(0, SAMPLE, None))
        with patch.object(nmd_platform, "name", return_value="windows"):
            result = nmd_platform.sample_local(run)
        argv = run.call_args.args[0]
        self.assertTrue(argv[0].endswith("powershell.exe"))
        self.assertEqual(argv[1:4], ["-NoProfile", "-NonInteractive", "-Command"])
        self.assertIn("Get-NetAdapter", argv[4])
        self.assertIn("Get-NetRoute", argv[4])
        self.assertNotIn("curl", argv[4])
        self.assertEqual(result["platform"], "windows")
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["interfaces"], ["Ethernet", "以太网"])
        self.assertEqual(result["interface_states"], {"Ethernet": "up", "以太网": "down"})
        self.assertEqual(result["ipv4_default_routes"], 2)
        self.assertEqual(len(result["route_fingerprint"]), 16)
        self.assertEqual(result["services"], {})
        self.assertEqual(result["service_observation_error"], "unsupported_platform")
        self.assertNotIn("192.0.2.0", json.dumps(result))

    def test_malformed_or_failed_commands_stay_unknown(self):
        with patch.object(nmd_platform, "name", return_value="windows"):
            for response in ((None, "", "tool_missing"), (0, "not a sample\r\n", None), (1, "", None)):
                with self.subTest(response=response):
                    result = nmd_platform.sample_local(Mock(return_value=response))
                    self.assertEqual(result["status"], "unknown")
                    self.assertIsNone(result["route_fingerprint"])
                    self.assertEqual(result["interfaces"], [])
                    self.assertNotIn("not a sample", json.dumps(result))

    def test_http_probe_uses_windows_curl_and_keeps_linux_curl(self):
        cfg = {"probes": [dict(id="edge", type="http", target="https://example.invalid/")]}
        with patch.object(nmd_platform, "name", return_value="windows"), \
                patch.object(nmd_monitor, "_run", return_value=(0, "200 0.01 0.02 0.03 0.04 0.05", None)) as run:
            result = nmd_monitor.sample_probe(cfg)[1]
        argv = run.call_args_list[-1].args[0]
        self.assertTrue(argv[0].endswith("curl.exe"))
        self.assertIn("NUL", argv)
        self.assertNotIn("/dev/null", argv)
        self.assertNotIn("/usr/bin/curl", argv)
        self.assertEqual(result["status"], "success")
        with patch.object(nmd_platform, "name", return_value="linux"), \
                patch.object(nmd_monitor, "_run", return_value=(0, "200 0.01 0.02 0.03 0.04 0.05", None)) as run:
            nmd_monitor.sample_probe(cfg)
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/curl")
        self.assertIn("/dev/null", run.call_args.args[0])

    def test_command_output_accepts_utf16_and_crlf(self):
        text = "IF|以太网|Up\r\nRT|0.0.0.0/0\r\n"
        decoded = nmd_windows.decode_command_output(text.encode("utf-16-le"))
        parsed = nmd_windows.parse_local_sample(decoded)
        self.assertEqual(parsed["states"], {"以太网": "up"})
        self.assertEqual(parsed["routes"], ["0.0.0.0/0"])
        self.assertFalse(parsed["foreign"])

    def test_windows_runner_kills_the_process_and_drops_proxy_env(self):
        proc = Mock()
        proc.communicate.side_effect = [subprocess.TimeoutExpired("test", 1), (b"", b"")]
        group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        window = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        with patch.dict(os.environ, {"HTTP_PROXY": "http://secret.invalid", "SystemRoot": r"C:\Windows"}), \
                patch.object(nmd_monitor.subprocess, "CREATE_NEW_PROCESS_GROUP", group, create=True), \
                patch.object(nmd_monitor.subprocess, "CREATE_NO_WINDOW", window, create=True), \
                patch.object(nmd_monitor.subprocess, "Popen", return_value=proc) as popen:
            self.assertEqual(nmd_monitor._run_windows(["C:\\Windows\\System32\\curl.exe"], 1)[2], "timeout")
        proc.kill.assert_called_once_with()
        self.assertNotIn("HTTP_PROXY", popen.call_args.kwargs["env"])
        self.assertNotIn("start_new_session", popen.call_args.kwargs)
        self.assertEqual(popen.call_args.kwargs["creationflags"], group | window)
        self.assertEqual(popen.call_args.kwargs["env"]["PATH"], r"C:\Windows\System32")


class StateTests(unittest.TestCase):
    def test_windows_directory_rejects_a_symlink_and_round_trips_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                nmd_monitor._directory_windows(link / "state", create=True)
            self.assertFalse((real / "state").exists())
            state = base / "state"
            with patch.object(nmd_monitor, "_directory", nmd_monitor._directory_windows):
                store = nmd_monitor.Store(state, {})
                try:
                    store.record([dict(id="local", type="passive", path="local", status="unknown",
                                       error="fixture_only", timings={}, observed_at=100)], now=100)
                finally:
                    store.close()
                snapshot = nmd_monitor.read_snapshot(state)
            self.assertEqual(snapshot["samples"][0]["error"], "fixture_only")
            self.assertTrue((state / "monitor.sqlite3").is_file())

    def test_readonly_uri_uses_a_drive_prefix(self):
        uri = nmd_monitor._windows_readonly_uri("C:/Users/Max/AppData/Local/nmd-monitor/monitor.sqlite3")
        self.assertEqual(uri, "file:///C:/Users/Max/AppData/Local/nmd-monitor/monitor.sqlite3?mode=ro")


class TaskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "checkout"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "scripts" / "observability.py").write_text("# fixture\n", encoding="utf-8")
        (self.root / "examples").mkdir()
        (self.root / "examples" / "monitor-local.json").write_text(json.dumps({
            "schema_version": 1, "interval_seconds": 30, "timeout_seconds": 5,
            "retention_hours": 168, "max_samples": 100000, "probes": [],
        }), encoding="utf-8")
        self.bin_dir = self.base / "nmd-bin"
        self.config = self.base / "config"
        self.state = self.base / "state"
        self.python = self.base / "Python313" / "python.exe"
        self.python.parent.mkdir()
        self.python.write_bytes(b"")

    def test_install_registers_a_task_without_starting_or_using_uv(self):
        scripts = []
        task = install_scope.install_windows_monitor(
            self.root, self.config, self.state, self.bin_dir, self.python, runner=scripts.append)
        self.assertTrue(task.is_file())
        body = task.read_bytes()
        self.assertTrue(body.startswith(b"\xef\xbb\xbf"))
        text = body.decode("utf-8-sig")
        self.assertIn("\r\n", text)
        self.assertIn("monitor run", text)
        self.assertIn(str(self.python), text)
        self.assertNotIn("uv venv", text)
        self.assertEqual(json.loads((self.config / "monitor.json").read_text(encoding="utf-8"))["probes"], [])
        self.assertEqual(len(scripts), 1)
        self.assertIn("Register-ScheduledTask", scripts[0])
        self.assertIn("-ExecutionPolicy Bypass", scripts[0])
        self.assertIn("RunLevel Limited", scripts[0])
        self.assertNotIn("Start-ScheduledTask", scripts[0])
        self.assertNotIn("uv venv", scripts[0])
        self.assertIn("未启动", scripts[0])
        saved = (self.config / "monitor.json").read_text(encoding="utf-8")
        install_scope.install_windows_monitor(
            self.root, self.config, self.state, self.bin_dir, self.python, runner=scripts.append)
        self.assertEqual((self.config / "monitor.json").read_text(encoding="utf-8"), saved)

    def test_enable_does_not_start_and_disable_does_not_stop(self):
        install_scope.install_windows_monitor(
            self.root, self.config, self.state, self.bin_dir, self.python, runner=lambda script: None)
        enable = install_scope.windows_task(self.root, self.bin_dir, "enable", runner=lambda script: script)
        disable = install_scope.windows_task(self.root, self.bin_dir, "disable", runner=lambda script: script)
        start = install_scope.windows_task(self.root, self.bin_dir, "start", runner=lambda script: script)
        self.assertIn("AtLogOn", enable)
        self.assertNotIn("Start-ScheduledTask", enable)
        self.assertIn("Triggers.Clear", disable)
        self.assertNotIn("Stop-ScheduledTask", disable)
        self.assertIn("Start-ScheduledTask", start)
        self.assertIn(str(self.root), enable)
        with self.assertRaises(install_scope.ScopeError):
            install_scope.install_windows_monitor(
                self.root, self.config, self.state, self.root / "bin", self.python, runner=lambda script: None)

    def test_command_files_do_not_embed_paths_in_cmd(self):
        self.assertNotIn("python.exe", nmd_windows.render_cmd())
        entry = nmd_windows.render_entry_ps1(self.python, self.root)
        self.assertIn("\r\n", entry)
        self.assertIn(str(self.python), entry)
        self.assertIn("Managed by NMD install_scope:", entry)


class CommandTests(unittest.TestCase):
    def test_network_commands_fail_before_side_effects_and_monitor_install_is_allowed(self):
        with patch.object(nmd_platform, "name", return_value="windows"):
            for args in (["apply"], ["start"], ["source", "status"], ["channel", "list"],
                         ["desktop", "install"], ["adopt", "--user"]):
                with self.subTest(args=args), patch.object(manager, "run", side_effect=AssertionError("command")), \
                        patch.object(manager, "setting", side_effect=AssertionError("settings")), \
                        patch.object(manager, "managed", side_effect=AssertionError("installation")):
                    with self.assertRaisesRegex(manager.ManagerError, "Linux"):
                        manager.main(args)
            with patch.object(manager, "managed", side_effect=AssertionError("reached")):
                with self.assertRaisesRegex(AssertionError, "reached"):
                    manager.main(["monitor", "install"])
            with self.assertRaisesRegex(manager.ManagerError, "--system"):
                manager.main(["bootstrap", "--system"])
            output = io.StringIO()
            with redirect_stdout(output):
                manager.main(["help"])
            self.assertIn("计划任务", output.getvalue())

    def test_capabilities_and_config_editing(self):
        with patch.object(nmd_platform, "name", return_value="windows"):
            capabilities = nmd_platform.capabilities()
        self.assertEqual(capabilities["platform"], "windows")
        self.assertTrue(capabilities["background_service"])
        self.assertEqual(capabilities["background_mechanism"], "scheduled_task")
        self.assertFalse(capabilities["local_egress_control"])
        self.assertIn("network_management_unsupported", capabilities["limitations"])
        self.assertNotIn("background_service_unsupported", capabilities["limitations"])
        self.assertIn("windows", capabilities["supported_platforms"])
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / "monitor.json"
            with patch.object(observability.nmd_platform, "name", return_value="windows"):
                server = observability.DashboardServer(0, base / "state", None, config_path=config)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    import http.client
                    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                    connection.request("GET", "/api/capabilities")
                    body = json.loads(connection.getresponse().read())
                    connection.close()
                    self.assertTrue(body["config_management"])
                    self.assertFalse(body["local_egress_control"])
                finally:
                    server.shutdown()
                    server.server_close()
                    worker.join(3)

    def test_real_platform_name_matches_the_host(self):
        expected = {"linux": "linux", "darwin": "macos", "win32": "windows"}.get(sys.platform, "unsupported")
        self.assertEqual(nmd_platform.name(), expected)


class ScriptContractTests(unittest.TestCase):
    def test_entry_scripts_keep_the_venv_recipe_and_do_not_call_uv_venv(self):
        helper = (ROOT / "scripts" / "nmd_windows.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("python -m venv --without-pip", helper)
        self.assertIn(".local", helper)
        self.assertIn("Smart App Control", helper)
        for name in ("install.ps1", "nmd.ps1", "scripts/nmd_windows.ps1"):
            text = (ROOT / name).read_text(encoding="utf-8-sig")
            if name != "scripts/nmd_windows.ps1":
                self.assertIn("nmd_windows.ps1", text)
            for line in text.splitlines():
                code = re.sub(r"#.*", "", line)
                self.assertIsNone(re.search(r"(^|[;&|])\s*uv(\.exe)?\s+venv\b", code, re.I), name)


class LayoutOnThisHostTests(unittest.TestCase):
    def test_paths_follow_the_running_os(self):
        if sys.platform == "win32":
            paths = install_scope.paths("user", Path(r"C:\Users\Max"))
            self.assertEqual(paths["bin_dir"], Path(r"C:\Users\Max\AppData\Local\nmd-bin"))
            with self.assertRaises(install_scope.ScopeError):
                install_scope.paths("system")
        else:
            paths = install_scope.paths("user", Path("/home/alice"))
            self.assertEqual(paths["bin_dir"], Path("/home/alice/.local/bin"))
            self.assertEqual(paths["unit_file"], Path("/home/alice/.config/systemd/user/nmd-monitor.service"))


if __name__ == "__main__":
    unittest.main()
