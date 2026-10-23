"""macOS contracts: synthetic input, private temporary state, loopback only."""
import os
import json
import io
import http.client
import threading
from contextlib import redirect_stdout
import subprocess
from unittest.mock import Mock, patch
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import nmd_monitor
import manager
import observability
import nmd_platform


class PortableStateTests(unittest.TestCase):
    def test_round_trip_preserves_synthetic_evidence_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state with spaces'
            store = nmd_monitor.Store(state, {})
            try:
                store.record([dict(id='local', type='passive', path='local',
                                   status='unknown', error='fixture_only',
                                   timings={}, observed_at=100)], now=100)
            finally:
                store.close()
            snapshot = nmd_monitor.read_snapshot(state)
            self.assertEqual(snapshot['samples'][0]['error'], 'fixture_only')
            self.assertEqual(snapshot['samples'][0]['status'], 'unknown')
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            self.assertEqual((state / 'monitor.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_renamed_locked_directory_stays_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = base / 'state'
            with nmd_monitor.collector_lock(state) as pinned:
                state.rename(base / 'original')
                (base / 'foreign').mkdir(mode=0o700)
                state.symlink_to(base / 'foreign', target_is_directory=True)
                store = nmd_monitor.Store(pinned, {})
                store.close()
                with self.assertRaises(RuntimeError):
                    with nmd_monitor.collector_lock(base / 'original'):
                        pass
            self.assertEqual(list((base / 'foreign').iterdir()), [])
            self.assertTrue((base / 'original/monitor.sqlite3').is_file())


class MacOSObservationTests(unittest.TestCase):
    def setUp(self):
        platform = patch.object(nmd_platform, 'name', return_value='macos')
        platform.start(); self.addCleanup(platform.stop)

    def fixture_run(self):
        return Mock(side_effect=[
            (0, (ROOT / 'tests/fixtures/macos-ifconfig.txt').read_text(), None),
            (0, (ROOT / 'tests/fixtures/macos-routes.txt').read_text(), None)])

    def test_macos_sample_uses_only_fixed_read_only_metadata_commands(self):
        run = self.fixture_run()
        with patch.object(nmd_monitor, '_run', run):
            result = nmd_monitor.sample_probe({})[0]
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/sbin/ifconfig', '-a'], ['/usr/sbin/netstat', '-rn', '-f', 'inet']])
        self.assertEqual(result['platform'], 'macos')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['interfaces'], ['en0', 'en1', 'lo0', 'utun2'])
        self.assertEqual(result['interface_states'], {'en0': 'up', 'en1': 'down', 'lo0': 'unknown', 'utun2': 'unknown'})
        self.assertEqual(result['ipv4_default_routes'], 2)
        self.assertEqual(len(result['route_fingerprint']), 16)
        self.assertEqual(result['services'], {})
        self.assertEqual(result['service_observation_error'], 'unsupported_platform')
        for private_value in ['192.0.2.10', '192.0.2.1', '02:00:00:00:00:01', 'fe80::1']:
            self.assertNotIn(private_value, json.dumps(result))

    def test_missing_or_malformed_metadata_never_claims_observed(self):
        for response in [(None, 'secret fixture', 'tool_missing'), (None, '', 'timeout'), (0, 'not valid metadata', None)]:
            with self.subTest(response=response), patch.object(nmd_monitor, '_run', return_value=response):
                result = nmd_monitor.sample_probe({})[0]
            self.assertEqual(result['status'], 'unknown')
            self.assertIsNone(result['route_fingerprint'])
            self.assertIsNone(result['ipv4_default_routes'])
            self.assertEqual(result['interfaces'], [])
            self.assertNotIn('secret fixture', json.dumps(result))


class PortableEntryTests(unittest.TestCase):
    def test_entrypoint_and_symlink_need_no_gnu_readlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            bindir = base / 'bin'; bindir.mkdir()
            readlink = bindir / 'readlink'
            readlink.write_text('#!/bin/sh\nexit 88\n'); readlink.chmod(0o755)
            entry = base / 'nmd link with spaces'; entry.symlink_to(ROOT / 'nmd')
            env = dict(os.environ, HOME=tmp, XDG_CONFIG_HOME=str(base / 'config'),
                       XDG_STATE_HOME=str(base / 'state'), PYTHONDONTWRITEBYTECODE='1',
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       PATH=str(bindir) + os.pathsep + os.environ['PATH'])
            result = subprocess.run([str(entry), 'machine', 'capabilities'], env=env,
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            caps = json.loads(result.stdout)
            self.assertEqual(caps['platform'], nmd_platform.name())
            self.assertFalse(caps['network_mutations'])
            self.assertFalse(caps['native_desktop'])
            result = subprocess.run([str(entry), 'demo', '--once'], env=env,
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            snapshot = json.loads(result.stdout)
            self.assertEqual(snapshot['collector']['data_origin'], 'demo')
            self.assertTrue(all(row['synthetic'] for row in snapshot['samples']))
            self.assertFalse((base / 'config').exists())
            self.assertFalse((base / 'state').exists())


class SafeMacOSCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        platform = patch.object(nmd_platform, 'name', return_value='macos')
        platform.start(); self.addCleanup(platform.stop)
        env = patch.dict(os.environ, dict(HOME=self.temp.name,
                         XDG_CONFIG_HOME=str(base / 'config'), XDG_STATE_HOME=str(base / 'state'),
                         GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull))
        env.start(); self.addCleanup(env.stop)

    def test_demo_once_is_synthetic_and_never_observes_host_or_reads_sources(self):
        output = io.StringIO()
        with patch.object(nmd_monitor, 'sample_probe', side_effect=AssertionError('real collection')), \
                patch.object(manager, 'source_directory', side_effect=AssertionError('private sources')), \
                patch.object(manager, 'setting', side_effect=AssertionError('installed settings')), \
                redirect_stdout(output):
            manager.main(['demo', '--once'])
        snapshot = json.loads(output.getvalue())
        self.assertEqual(snapshot['collector']['data_origin'], 'demo')
        self.assertTrue(snapshot['samples'])
        self.assertTrue(all(sample['synthetic'] for sample in snapshot['samples']))
        self.assertEqual(snapshot['collector']['state'], 'fresh')

    def test_macos_lifecycle_and_network_commands_fail_before_any_side_effect(self):
        for args in [['apply'], ['start'], ['verify'], ['source', 'status'], ['channel', 'list'],
                     ['bootstrap'], ['update'], ['adopt', '--user'],
                     ['install'], ['monitor', 'install'], ['monitor', 'start'],
                     ['monitor', 'enable'], ['monitor', 'uninstall']]:
            with self.subTest(args=args), patch.object(manager, 'run', side_effect=AssertionError('command')), \
                    patch.object(manager, 'setting', side_effect=AssertionError('settings')), \
                    patch.object(manager, 'managed', side_effect=AssertionError('installation')):
                with self.assertRaisesRegex(manager.ManagerError, 'Linux'):
                    manager.main(args)

    def test_macos_gui_never_selects_real_source_registry(self):
        with patch.object(manager, 'source_directory', side_effect=AssertionError('private registry')), \
                patch.object(manager, 'setting', side_effect=AssertionError('installed settings')), \
                patch.object(observability, 'main') as observe:
            manager.main(['gui', '--port', '0'])
        self.assertIsNone(observe.call_args.kwargs['sources_dir'])


class CapabilityTests(unittest.TestCase):
    def test_capabilities_describe_actual_platform_and_unsupported_services(self):
        for platform in ['macos', 'linux', 'unsupported']:
            with self.subTest(platform=platform), patch.object(nmd_platform, 'name', return_value=platform):
                capabilities = nmd_platform.capabilities()
                self.assertEqual(capabilities['platform'], platform)
                self.assertEqual(capabilities['local_observations']['systemd_services'], platform == 'linux')
                self.assertEqual(capabilities['background_service'], platform == 'linux')
                self.assertFalse(capabilities['network_mutations'])
        with patch.object(nmd_platform, 'name', return_value='unsupported'):
            run = Mock(side_effect=AssertionError('unsupported platform cannot run commands'))
            sample = nmd_platform.sample_local(run)
            self.assertEqual(sample['status'], 'unknown')
            self.assertEqual(sample['error'], 'unsupported_platform')
            run.assert_not_called()

    def test_demo_directory_is_disposable_even_after_error(self):
        with self.assertRaisesRegex(RuntimeError, 'fixture exit'):
            with observability.demo_state() as state:
                self.assertTrue(state.exists())
                raise RuntimeError('fixture exit')
        self.assertFalse(state.exists())

    def test_oversized_command_output_is_unknown_instead_of_truncated_evidence(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (b'x' * 65537, b'')
        with patch.object(nmd_monitor.subprocess, 'Popen', return_value=process):
            self.assertEqual(nmd_monitor._run(['/fixture'], 2), (None, '', 'output_too_large'))


class MacOSIntegrationTests(unittest.TestCase):
    def test_fixture_collector_to_database_to_read_only_loopback_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state'
            fixture = MacOSObservationTests().fixture_run()
            with patch.object(nmd_platform, 'name', return_value='macos'), \
                    patch.object(nmd_monitor, '_run', fixture):
                nmd_monitor.collect({}, state, once=True)
                with observability.DashboardServer(0, state, sources_dir=None) as server:
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        def request(path, method='GET', headers=None):
                            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                            try:
                                connection.request(method, path, headers=headers or {})
                                response = connection.getresponse()
                                return response.status, response.read()
                            finally:
                                connection.close()
                        status, body = request('/api/snapshot')
                        self.assertEqual(status, 200)
                        snapshot = json.loads(body)
                        self.assertEqual(snapshot['collector']['state'], 'fresh')
                        self.assertEqual(snapshot['samples'][0]['platform'], 'macos')
                        self.assertEqual(snapshot['samples'][0]['service_observation_error'], 'unsupported_platform')
                        self.assertEqual(snapshot['samples'][0]['ipv4_default_routes'], 2)
                        self.assertEqual(json.loads(request('/api/capabilities')[1])['platform'], 'macos')
                        import egress_sources
                        with patch.object(egress_sources, 'public_status', side_effect=AssertionError('private config')):
                            status, body = request('/api/sources')
                            self.assertEqual(status, 200)
                            self.assertEqual(json.loads(body)['controller'], 'not_configured')
                        self.assertEqual(request('/api/snapshot', method='POST')[0], 405)
                        self.assertEqual(request('/api/snapshot', headers={'Host': 'evil.invalid'})[0], 403)
                        for asset in ['/', '/app.js', '/style.css']:
                            self.assertEqual(request(asset)[0], 200)
                    finally:
                        server.shutdown(); thread.join(5)
            self.assertEqual(fixture.call_count, 2)

    def test_linux_sampler_uses_fixtures_without_macos_commands(self):
        from unittest.mock import mock_open
        with tempfile.TemporaryDirectory() as tmp:
            net = Path(tmp) / 'net'
            (net / 'eth-fixture').mkdir(parents=True)
            (net / 'eth-fixture/operstate').write_text('down')
            real_path = Path
            run = Mock(return_value=(0, 'Id=mihomo.service\nActiveState=inactive\nSubState=dead\nLoadState=loaded\n', None))
            with patch.object(nmd_platform, 'name', return_value='linux'), \
                    patch.object(nmd_platform, 'Path', side_effect=lambda value: net if value == '/sys/class/net' else real_path(value)), \
                    patch('nmd_platform.open', mock_open(read_data=b'Iface Destination Gateway\nfixture 00000000 00000000\n'), create=True):
                result = nmd_platform.sample_local(run)
            self.assertEqual(result['interfaces'], ['eth-fixture'])
            self.assertEqual(result['interface_states']['eth-fixture'], 'down')
            self.assertEqual(result['ipv4_default_routes'], 1)
            self.assertEqual(result['services']['mihomo.service']['ActiveState'], 'inactive')
            self.assertEqual(run.call_args.args[0][0], '/usr/bin/systemctl')


class SourceControlBoundaryTests(unittest.TestCase):
    def test_macos_collector_rejects_sources_before_any_observation_or_state_write(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(nmd_platform, 'name', return_value='macos'), \
                patch.object(nmd_monitor, 'sample_probe', side_effect=AssertionError('real observation')), \
                patch.object(nmd_monitor, 'run_auto_cycle', side_effect=AssertionError('source access')):
            state = Path(tmp) / 'not-created'
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                nmd_monitor.collect({}, state, once=True, sources_dir=Path(tmp) / 'private-fixture')
            self.assertFalse(state.exists())

    def test_macos_cli_rejects_auto_source_option_before_reading_configuration(self):
        with patch.object(nmd_platform, 'name', return_value='macos'), \
                patch.object(nmd_monitor, 'load_config', side_effect=AssertionError('config must not be read')):
            with self.assertRaises(SystemExit) as result:
                manager.main(['monitor', 'run', '--config', '/fixture-not-read',
                              '--sources-dir', '/fixture-not-read', '--once'])
            self.assertEqual(result.exception.code, 2)

    def test_platform_boundary_keeps_linux_controls_and_rejects_macos_controls(self):
        import egress_sources
        for platform, expected_status in [('macos', 405), ('linux', 200)]:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(nmd_platform, 'name', return_value=platform), \
                    patch.object(egress_sources, 'Store', return_value=Mock()) as source_store, \
                    patch.object(egress_sources, 'select', return_value={}) as select, \
                    patch.object(egress_sources, 'delay_test', return_value={'delay_ms': 10}) as delay, \
                    patch.object(egress_sources, 'auto_configure', return_value={'result': 'disabled'}) as auto:
                with observability.DashboardServer(0, Path(tmp) / 'state', sources_dir=Path(tmp) / 'sources') as server:
                    thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
                    try:
                        def request(path, body=None):
                            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                            try:
                                headers={'Content-Type': 'application/json'} if body is not None else {}
                                connection.request('POST' if body is not None else 'GET', path,
                                                   body=json.dumps(body) if body is not None else None, headers=headers)
                                response=connection.getresponse();return response.status,json.loads(response.read())
                            finally:connection.close()
                        caps=request('/api/capabilities')[1]
                        self.assertEqual(caps['local_egress_control'], platform=='linux')
                        self.assertEqual(caps['read_only_gui'], platform!='linux')
                        self.assertEqual(caps['channel_management'], platform=='linux')
                        for path, body in [('/api/egress/select', {'node':'nmd-fixture-0123456789abcdef0123'}),
                                           ('/api/egress/delay', {'node':'nmd-fixture-0123456789abcdef0123'}),
                                           ('/api/auto', {'action':'disable'})]:
                            self.assertEqual(request(path,body)[0],expected_status)
                        if platform=='macos':
                            source_store.assert_not_called();select.assert_not_called();delay.assert_not_called();auto.assert_not_called()
                    finally:server.shutdown();thread.join(5)


if __name__ == '__main__':
    unittest.main()
