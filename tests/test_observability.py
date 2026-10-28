"""Read-only loopback API and independent source-checkout CLI contract."""
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import observability


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
        for path, content in (('/', 'text/html'), ('/app.js', 'text/javascript'), ('/style.css', 'text/css')):
            status, headers, body = self.request(path)
            self.assertEqual(status, 200, body)
            self.assertTrue(headers['Content-Type'].startswith(content))
            self.assertNotIn('Access-Control-Allow-Origin', headers)


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
