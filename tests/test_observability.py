"""Read-only loopback API and independent source-checkout CLI contract."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import http.client
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import manager
import observability


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux system-scope account gate")
class InstalledSystemDryRunTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / ".git").mkdir()
        self.state = self.root / "state"
        self.config = self.root / "config"
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(manager, "ROOT", self.root))
        stack.enter_context(patch.object(manager.nmd_platform, "name", return_value="linux"))
        stack.enter_context(patch.object(manager, "_euid", return_value=1000))
        self.scope = stack.enter_context(patch.object(manager, "scope_of", return_value="system"))
        self.setting = stack.enter_context(patch.object(manager, "setting", side_effect=lambda root, key: {
            "home": str(self.root), "stateDir": str(self.state),
            "configDir": str(self.config),
        }[key]))
        self.sources = stack.enter_context(patch.object(manager, "source_directory",
                                                        return_value=self.root / "private"))
        self.account = stack.enter_context(patch("pwd.getpwnam", return_value=Mock(pw_uid=123)))
        stack.enter_context(patch.object(observability.nmd_monitor, "sample_probe",
                                         side_effect=AssertionError("real probe")))

    def assert_no_install_resolution(self):
        self.setting.assert_not_called()
        self.scope.assert_not_called()
        self.sources.assert_not_called()
        self.account.assert_not_called()
        self.assertFalse(self.state.exists())
        self.assertFalse(self.config.exists())

    def test_status_dry_run_only_reads_and_removes_disposable_state(self):
        self.account.side_effect = KeyError("missing system monitor")
        output = io.StringIO()
        with patch.object(observability.nmd_monitor, "read_snapshot",
                          wraps=observability.nmd_monitor.read_snapshot) as read, redirect_stdout(output):
            manager.main(["monitor", "status", "--state-dir", str(self.state), "--dry-run"])
        snapshot = json.loads(output.getvalue())
        self.assertEqual(snapshot["collector"]["data_origin"], "demo")
        self.assertTrue(snapshot["samples"])
        self.assertTrue(all(row["synthetic"] for row in snapshot["samples"]))
        read.assert_called_once()
        temporary_state = read.call_args.args[0]
        self.assertNotEqual(temporary_state, self.state)
        self.assertFalse(temporary_state.exists())
        self.assert_no_install_resolution()

    def test_gui_abbreviated_dry_run_ignores_both_explicit_paths(self):
        def serve(port, state_dir, *, sources_dir, config_path):
            self.assertEqual(port, 9)
            self.assertNotEqual(state_dir, self.state)
            self.assertTrue((state_dir / "monitor.sqlite3").is_file())
            self.assertIsNone(sources_dir)
            self.assertIsNone(config_path)
            snapshot = observability.nmd_monitor.read_snapshot(state_dir)
            self.assertEqual(snapshot["collector"]["data_origin"], "demo")
            self.assertTrue(snapshot["samples"])
            self.assertTrue(all(row["synthetic"] for row in snapshot["samples"]))

        with patch.object(observability, "serve_dashboard", side_effect=serve) as dashboard, \
                redirect_stdout(io.StringIO()):
            manager.main(["gui", "--state-dir", str(self.state), "--config", str(self.config),
                          "--port", "9", "--dry"])
        dashboard.assert_called_once()
        self.assertFalse(dashboard.call_args.args[1].exists())
        self.assert_no_install_resolution()

    def test_invalid_dry_run_neither_dispatches_nor_resolves_install(self):
        for argv in (["monitor", "status", "--dry-run", "--bogus"],
                     ["gui", "--dry-run", "--port", "65536"],
                     ["gui", "--dry-run=x"]):
            with self.subTest(argv=argv), patch.object(observability, "demo_state") as demo, \
                    patch.object(observability, "main") as real, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    manager.main(argv)
                self.assertEqual(exc.exception.code, 2)
                demo.assert_not_called()
                real.assert_not_called()
        self.assert_no_install_resolution()

    def test_real_data_stays_gated_and_flag_text_in_value_is_not_an_opt_in(self):
        for argv in (["monitor", "status"], ["gui"], ["gui", "--config=--dry-run"]):
            with self.subTest(argv=argv), patch.object(observability, "demo_state") as demo, \
                    patch.object(observability, "main") as observe:
                with self.assertRaisesRegex(manager.ManagerError, "仅限 nmd-monitor UID"):
                    manager.main(argv)
                demo.assert_not_called()
                observe.assert_not_called()
        self.assertEqual(self.account.call_count, 3)

    def test_authorized_installed_config_default_is_preserved(self):
        self.account.return_value.pw_uid = 1000
        for command in ("config-check", "run"):
            with self.subTest(command=command), \
                    patch.object(observability.nmd_monitor, "load_config",
                                 return_value={"probes": []}) as read_config, \
                    patch.object(observability.nmd_monitor, "collect"), redirect_stdout(io.StringIO()):
                argv = ["monitor", command] + (["--once"] if command == "run" else [])
                manager.main(argv)
                read_config.assert_called_once_with(self.config / "monitor.json")


class DashboardAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'not-created'
        self.server = observability.DashboardServer(0, self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.port = self.server.server_address[1]

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def request(self, path, headers=None, method='GET'):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_capabilities_and_uninitialized_state_are_read_only(self):
        status, headers, body = self.request('/api/capabilities')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['schema_version'], 1)
        self.assertFalse(json.loads(body)['network_mutations'])
        self.assertTrue(json.loads(body)['read_only_gui'])
        self.assertFalse(json.loads(body)['local_egress_control'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        status, _, body = self.request('/api/snapshot')
        self.assertEqual(status, 200, body)
        self.assertFalse(self.state.exists())

    def test_post_surface_is_limited_and_requires_private_sources(self):
        # Unrouted paths keep rejecting every write verb; the fixed egress routes
        # need a configured sources store, which this server does not have.
        for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
            self.assertEqual(self.request('/api/snapshot', method=method)[0], 405)
        self.assertEqual(self.request('/api/egress/select', method='PUT')[0], 405)
        self.assertEqual(self.request('/api/egress/select', method='POST')[0], 405 if observability.nmd_platform.name() != 'linux' else 503)
        self.assertEqual(self.request('/api/auto', method='POST')[0], 405 if observability.nmd_platform.name() != 'linux' else 503)
        self.assertEqual(self.request('/api/channels/refresh', method='POST')[0], 405 if observability.nmd_platform.name() != 'linux' else 503)
        self.assertEqual(self.request('/api/egress/diagnose', method='POST')[0], 405 if observability.nmd_platform.name() != 'linux' else 503)
        self.assertEqual(self.request('/api/egress/select?node=x', method='POST')[0], 400)
        self.assertFalse(self.state.exists())

    def test_rebinding_cross_site_and_absolute_url_rejected(self):
        for headers in ({'Host': 'evil.invalid'}, {'Origin': 'https://evil.invalid'},
                        {'Sec-Fetch-Site': 'cross-site'}, {'Origin': 'null'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('/api/snapshot', headers)[0], 403)
        self.assertEqual(self.request('http://evil.invalid/api/snapshot')[0], 403)

    def test_top_level_shell_navigation_does_not_grant_cross_site_api_access(self):
        navigation = {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate',
                      'Sec-Fetch-Dest': 'document'}
        self.assertEqual(self.request('/', navigation)[0], 200)
        self.assertEqual(self.request('/api/snapshot', navigation)[0], 403)
        self.assertEqual(self.request('/api/capabilities', navigation)[0], 403)
        self.assertEqual(self.request('/', navigation, method='POST')[0], 403)
        self.assertEqual(self.request('/', dict(navigation, Origin='https://evil.invalid'))[0], 403)
        self.assertEqual(self.request('/', {'Sec-Fetch-Site': 'cross-site'})[0], 403)
        self.assertEqual(self.request('/', dict(navigation, **{'Sec-Fetch-Dest': 'iframe'}))[0], 403)
        self.assertEqual(self.request('/', dict(navigation, **{'Host': 'evil.invalid'}))[0], 403)
        self.assertFalse(self.state.exists())

    def test_no_generic_file_server_or_mutations(self):
        for path in ('/../config.yaml', '/%2e%2e/config.yaml', '/config.yaml', '/api/restart'):
            self.assertEqual(self.request(path)[0], 404)
        for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
            self.assertEqual(self.request('/api/snapshot', method=method)[0], 405)
        self.assertFalse(self.state.exists())

    def test_unreadable_state_is_not_healthy_empty_state(self):
        with patch.object(observability.nmd_monitor, 'read_snapshot', side_effect=ValueError('secret')):
            status, _, body = self.request('/api/snapshot')
        self.assertEqual(status, 503)
        self.assertNotIn(b'secret', body)
        self.assertEqual(json.loads(body)['error'], 'snapshot_unavailable')

    def test_assets_have_expected_types_and_no_cors(self):
        for path, content in (('/', 'text/html'), ('/app.js', 'text/javascript'),
                              ('/style.css', 'text/css'), ('/logo.png', 'image/png')):
            status, headers, body = self.request(path)
            self.assertEqual(status, 200, body)
            self.assertTrue(headers['Content-Type'].startswith(content))
            self.assertNotIn('Access-Control-Allow-Origin', headers)


class FakeBridge:
    def __init__(self, view=None, stop_reply=None):
        self.view = view if view is not None else {
            "takeover_active": True, "phase": "active", "result": None,
            "on_boot": False, "failures": 0, "mihomo_pid": 42}
        self.stop_reply = stop_reply if stop_reply is not None else {
            "result": "rollback_restored", "reason": "manual_stop"}
        self.stops = 0

    def status_cached(self):
        return dict(self.view)

    def stop_takeover(self):
        self.stops += 1
        return dict(self.stop_reply)


class DaemonEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "not-created"
        self.bridge = FakeBridge()
        self.server = observability.DashboardServer(0, self.state, daemon_client=self.bridge)
        worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(self.stop)
        self.port = self.server.server_address[1]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        # Re-point the class default server so later suites stay unaffected.

    def request(self, path, method='GET', body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            head = dict(headers or {})
            if body is not None:
                head.setdefault('Content-Type', 'application/json')
            conn.request(method, path, body=json.dumps(body) if body is not None else None,
                         headers=head)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_capabilities_and_status_expose_the_daemon(self):
        status, body = self.request('/api/capabilities')
        data = json.loads(body)
        self.assertTrue(data['daemon'])
        self.assertTrue(data['daemon_available'])
        self.assertTrue(data['takeover_active'])
        status, body = self.request('/api/daemon/status')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['mihomo_pid'], 42)

    def test_stop_forwards_a_strict_empty_body_once(self):
        status, body = self.request('/api/daemon/takeover/stop', method='POST', body={})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['result'], 'stop_requested')
        self.assertEqual(self.bridge.stops, 1)
        status, body = self.request('/api/daemon/takeover/stop', method='POST',
                                    body={"force": True})
        self.assertEqual(status, 400)
        status, body = self.request('/api/daemon/takeover/stop', method='POST', body={},
                                    headers={'Origin': 'https://evil.invalid'})
        self.assertEqual(status, 403)

    def test_stop_failure_is_a_503_not_a_success(self):
        self.bridge.stop_reply = {"error": "daemon_unavailable"}
        status, body = self.request('/api/daemon/takeover/stop', method='POST', body={})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)['error'], 'daemon_unavailable')

    def test_without_a_bridge_the_routes_stay_closed(self):
        self.server.daemon_client = None
        status, _ = self.request('/api/daemon/status')
        self.assertEqual(status, 404)
        status, _ = self.request('/api/daemon/takeover/stop', method='POST', body={})
        self.assertEqual(status, 405)


class IndependentCLITests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/manager.py'), *args],
                              capture_output=True, text=True, timeout=10)

    def test_machine_interface_needs_no_install_or_daemon(self):
        result = self.invoke('machine', 'capabilities')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['schema_version'], 1)

    def test_status_does_not_create_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'absent'
            result = self.invoke('monitor', 'status', '--state-dir', str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['schema_version'], 1)
            self.assertFalse(path.exists())

    def test_corrupt_database_returns_sanitized_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'monitor.sqlite3'
            path.write_text('not sqlite')
            path.chmod(0o600)
            result = self.invoke('monitor', 'status', '--state-dir', tmp)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)['schema_version'], 1)
            self.assertNotIn('Traceback', result.stderr)

    def test_unknown_commands_cannot_be_shell(self):
        result = self.invoke('monitor', 'restart;echo unsafe')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')


class NMDEntryTests(unittest.TestCase):
    def test_service_example_invokes_real_cli_dispatcher(self):
        text = (ROOT / 'systemd/nmd-monitor.service.example').read_text()
        line = next(line for line in text.splitlines() if line.startswith('ExecStart='))
        script = line.split()[1].replace('/ABSOLUTE/PATH/TO/REPO', str(ROOT))
        result = subprocess.run([sys.executable, script, 'monitor', 'run', '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--state-dir', result.stdout)
        self.assertIn('--config', result.stdout)

    def test_only_nmd_source_entrypoint_exists(self):
        self.assertFalse((ROOT / 'mh').exists())
        self.assertFalse((ROOT / 'mihomoctl').exists())
        self.assertFalse((ROOT / 'nmd').is_symlink())
        result = subprocess.run([str(ROOT / 'nmd'), 'machine', 'capabilities'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['component'], 'nmd-observability')

if __name__ == '__main__':
    unittest.main()
