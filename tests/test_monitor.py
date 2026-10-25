import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, mock_open

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import nmd_monitor as m


def row(status, probe='test'):
    return dict(id=probe, type='http', path='system', status=status, error=None,
                timings={}, observed_at=1)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        # The original Linux contracts must not inspect this test host.
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        net = Path(self.temp.name) / 'net'
        (net / 'eth-fixture').mkdir(parents=True)
        (net / 'eth-fixture/operstate').write_text('up')
        real_path = Path
        for context in [patch.object(m.nmd_platform, 'name', return_value='linux'),
                        patch.object(m.nmd_platform, 'Path', side_effect=lambda value: net if value == '/sys/class/net' else real_path(value)),
                        patch('nmd_platform.open', mock_open(read_data=b'Iface Destination Gateway\nfixture 00000000 00000000\n'), create=True)]:
            context.start(); self.addCleanup(context.stop)

    def test_default_no_network(self):
        with patch.object(m, '_run', return_value=(None, '', 'tool_missing')) as run:
            self.assertEqual(len(m.sample_probe({})), 1)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][0], '/usr/bin/systemctl')

    def test_passive_service_fields_are_allowlisted(self):
        output = 'Id=mihomo.service\nActiveState=inactive\nSubState=dead\nLoadState=loaded\nSecret=do-not-save\n'
        with patch.object(m, '_run', return_value=(0, output, None)):
            result = m.sample_probe({})[0]
        self.assertEqual(result['services']['mihomo.service']['ActiveState'], 'inactive')
        self.assertNotIn('Secret', json.dumps(result))
        self.assertEqual(result['status'], 'observed')

    def test_reject_secrets_and_commands(self):
        for target in ('https://u:p@example.com', 'https://example.com/?token=secret',
                       'https://example.com/#secret', 'file:///etc/passwd', 'https://example.com/\nx'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                m.validate_config({'probes': [dict(id='a', type='http', target=target)]})
        with self.assertRaises(ValueError): m.validate_config({'command': 'echo bad'})
        with self.assertRaises(ValueError): m.validate_config({'interval_seconds': True})
        with self.assertRaises(ValueError): m.validate_config({'schema_version': True})
        with self.assertRaises(ValueError): m.validate_config({'probes': [dict(id=123, type='dns', target='example.invalid')]})
        with self.assertRaises(ValueError): m.validate_config({'max_samples': 100.5})
        with self.assertRaises(ValueError): m.validate_config({'probes': [dict(id='a', type='shell', target='echo')]})

    def test_duplicate_and_oversize_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'config.json'
            p.write_text('{"probes":[],"probes":[]}')
            with self.assertRaises(ValueError): m.load_config(p)
            p.write_text(' ' * 65537)
            with self.assertRaises(ValueError): m.load_config(p)

    def test_disabled(self):
        cfg = {'probes': [dict(id='a', type='http', target='https://example.invalid', enabled=False)]}
        with patch.object(m, '_run', return_value=(None, '', 'tool_missing')) as run:
            result = m.sample_probe(cfg)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][0], '/usr/bin/systemctl')
        self.assertEqual(result[1]['status'], 'skipped')

    def test_curl_fixed_argv_and_timings(self):
        cfg = {'probes': [dict(id='a', type='http', target='https://example.invalid')]}
        with patch.object(m, '_run', return_value=(0, '200 0.01 0.02 0.03 0.04 0.05', None)) as run:
            r = m.sample_probe(cfg)[1]
        self.assertEqual(r['status'], 'success')
        self.assertEqual(r['timings']['tls'], .03)
        argv = run.call_args.args[0]
        self.assertEqual(argv[1], '--disable')
        self.assertNotIn('--insecure', argv)
        self.assertIn('--head', argv)
        self.assertIn('--globoff', argv)
        self.assertEqual(argv[argv.index('--proxy') + 1], '')
        self.assertEqual(r['path'], 'system')

    def test_stop_checked_between_probes(self):
        stop = threading.Event()
        cfg = {'probes': [dict(id='a', type='http', target='https://example.invalid'), dict(id='b', type='http', target='https://example.invalid')]}
        def run(argv, timeout):
            if argv[0] == '/usr/bin/curl': stop.set()
            return 0, '200 0.01 0.02 0.03 0.04 0.05', None
        with patch.object(m, '_run', side_effect=run) as runner:
            results = m.sample_probe(cfg, stop_event=stop)
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(results[2]['error'], 'collector_stopping')

    def test_proxy_and_error_redaction(self):
        cfg = {'probes': [dict(id='a', type='http', target='https://example.invalid', path='proxy', proxy='socks5h://127.0.0.1:7890')]}
        with patch.object(m, '_run', return_value=(7, 'secret bearer token', None)) as run:
            r = m.sample_probe(cfg)[1]
        self.assertEqual(r['error'], 'connect_error')
        self.assertNotIn('secret', json.dumps(r))
        self.assertIn('socks5h://127.0.0.1:7890', run.call_args.args[0])

    def test_missing_tool_unknown_timeout_failure(self):
        cfg = {'probes': [dict(id='a', type='tcp', target='example.invalid:443')]}
        for err, status in [('tool_missing', 'unknown'), ('timeout', 'failure')]:
            with patch.object(m, '_run', return_value=(None, '', err)):
                self.assertEqual(m.sample_probe(cfg)[1]['status'], status)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state'
        self.store = m.Store(self.path, {})

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_debounce_and_boundaries(self):
        for t, status in enumerate(['success', 'failure', 'failure', 'failure', 'success', 'success'], 100):
            self.store.record([row(status)], t)
        incident = m.read_snapshot(self.path)['incidents'][0]
        self.assertEqual(incident['last_success'], 100)
        self.assertEqual(incident['first_failure'], 101)
        self.assertEqual(incident['confirmed_at'], 103)
        self.assertEqual(incident['recovery_first'], 104)
        self.assertEqual(incident['recovered_at'], 105)
        self.assertEqual(incident['end_reason'], 'recovered')

    def test_unknown_skipped_break_failure_streak(self):
        for t, status in enumerate(['failure', 'failure', 'unknown', 'failure', 'skipped', 'failure', 'failure']):
            self.store.record([row(status)], t)
        self.assertEqual(m.read_snapshot(self.path)['incidents'], [])

    def test_open_incident_survives_retention(self):
        self.store.config['retention_hours'] = 24
        for t in (0, 1, 2, 90000, 90001, 90002): self.store.record([row('failure')], t)
        self.assertEqual(len(m.read_snapshot(self.path)['incidents']), 1)
        self.store.record([row('success')], 90003)
        self.store.record([row('success')], 90004)
        # Closed old incidents may now age out, but the state is no longer dangling.
        self.assertIsNone(self.store.states['test']['incident'])

    def test_per_probe_timestamps(self):
        for t in (100, 110, 120):
            r = row('failure'); r['observed_at'] = t
            with patch.object(m.time, 'time', return_value=t + 50): self.store.record([r])
        incident = m.read_snapshot(self.path)['incidents'][0]
        self.assertEqual(incident['first_failure'], 100)
        self.assertEqual(incident['confirmed_at'], 120)

    def test_unknown_segments_active_incident(self):
        for t in range(3): self.store.record([row('failure')], t)
        self.store.record([row('unknown')], 3)
        snap = m.read_snapshot(self.path)
        self.assertEqual(snap['incidents'][0]['end_reason'], 'observation_gap')
        self.assertIsNone(snap['incidents'][0]['recovered_at'])
        self.assertEqual(snap['gaps'][0]['reason'], 'probe_unknown:test')

    def test_gap_ends_incident_without_fake_recovery(self):
        for t in range(3): self.store.record([row('failure')], t)
        self.store.gap(2, 100, 'sleep_or_clock_jump')
        self.store.record([row('success')], 100)
        snap = m.read_snapshot(self.path)
        self.assertEqual(snap['incidents'][0]['end_reason'], 'observation_gap')
        self.assertIsNone(snap['incidents'][0]['recovered_at'])
        self.assertEqual(len(snap['gaps']), 1)

    def test_restart_persistent_gap(self):
        self.store.record([row('failure')], 100)
        self.store.close()
        self.store = m.Store(self.path, {})
        self.assertEqual(m.read_snapshot(self.path)['gaps'][0]['reason'], 'collector_restart')

    def test_bounded_rows(self):
        self.store.config['max_samples'] = 100
        for t in range(120): self.store.record([row('success')], t)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM samples').fetchone()[0], 100)

    def test_sample_retention_intersects_time_with_newest_ids(self):
        self.store.config.update(max_samples=100, retention_hours=24)
        now = 200000
        cutoff = now - 24 * 3600
        for count in (0, 1, 99, 100, 101, 207):
            for offsets in ((1,), (-1,), (-1, 0, 1), (1, 0, -1)):
                with self.subTest(count=count, offsets=offsets):
                    # Sparse ids and out-of-order times model pruned history
                    # and clock changes. The two retention rules intersect.
                    rows = [(3 * i + 5, cutoff + offsets[i % len(offsets)],
                             dict(row('success'), id=f'fixture-{i}')) for i in range(count)]
                    self.store.db.execute('DELETE FROM samples')
                    self.store.db.executemany('INSERT INTO samples VALUES(?,?,?)',
                                             [(key, ts, json.dumps(payload)) for key, ts, payload in rows])
                    self.store.record([], now=now)
                    actual = [(key, ts, json.loads(payload)) for key, ts, payload in
                              self.store.db.execute('SELECT * FROM samples ORDER BY id')]
                    self.assertEqual(actual, [r for r in rows[-100:] if r[1] >= cutoff])
                    # Clearing all rows must not poison the next insertion.
                    self.store.record([], now=now + 2 * 86400)
                    self.store.record([row('success')], now=now + 2 * 86400 + 1)
                    self.assertEqual(self.store.db.execute('SELECT count(*) FROM samples').fetchone()[0], 1)

    def test_legacy_samples_survive_repeated_open_and_retention(self):
        now = 200000
        self.store.config.update(max_samples=100, retention_hours=24)
        self.store.record([row('success')], now=now)
        self.store.record([row('failure')], now=now + 1)
        # Model a v1 database created before the optional timestamp index.
        self.store.db.execute('DROP INDEX IF EXISTS samples_ts')
        columns = self.store.db.execute('PRAGMA table_info(samples)').fetchall()
        self.store.close()
        before = m.read_snapshot(self.path)['samples']
        for _ in range(2):
            with patch.object(m.time, 'time', return_value=now + 2):
                self.store = m.Store(self.path, {'max_samples': 100, 'retention_hours': 24})
            self.assertEqual(self.store.db.execute('PRAGMA table_info(samples)').fetchall(), columns)
            self.assertEqual(self.store.meta('schema_version'), 1)
            self.assertEqual(m.read_snapshot(self.path)['samples'], before)
            self.store.close()
        self.store = m.Store(self.path, {'max_samples': 100, 'retention_hours': 24})
        self.store.record([row('success')], now=now + 86401)
        self.assertEqual([r[0] for r in self.store.db.execute('SELECT ts FROM samples ORDER BY id')],
                         [now + 1, now + 86401])

    def test_private_and_exclusive(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.path / 'monitor.sqlite3').stat().st_mode & 0o777, 0o600)
        with m.collector_lock(self.path):
            with self.assertRaises(RuntimeError):
                with m.collector_lock(self.path): pass

    def test_viewer_does_not_create(self):
        nonexistent = Path(self.tmp.name) / 'missing'
        self.assertEqual(m.read_snapshot(nonexistent)['collector']['state'], 'no_data')
        self.assertFalse(nonexistent.exists())

    def test_symlink_rejected(self):
        link = Path(self.tmp.name) / 'link'
        link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(ValueError): m.read_snapshot(link)

    def test_once_no_real_probes(self):
        target = Path(self.tmp.name) / 'other'
        r = row('success'); r['observed_at'] = m.time.time()
        with patch.object(m, 'sample_probe', return_value=[r]) as probe:
            m.collect({}, target, once=True)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(len(m.read_snapshot(target)['samples']), 1)

    def test_slow_active_cycle_is_not_gap(self):
        target = Path(self.tmp.name) / 'slow'
        stop = threading.Event()
        calls = []
        def sample(cfg, stop_event=None):
            calls.append(1)
            if len(calls) == 3: stop.set()
            return [row('failure')]
        with patch.object(m, 'sample_probe', side_effect=sample), patch.object(stop, 'wait'), patch.object(m.time, 'monotonic', side_effect=[0, 90, 90, 180, 180, 270]), patch.object(m.time, 'time', side_effect=[1000, 1090, 1090, 1180, 1180, 1270]):
            m.collect({}, target, stop_event=stop)
        snap = m.read_snapshot(target)
        self.assertEqual(snap['gaps'], [])
        self.assertEqual(len(snap['incidents']), 1)

    def test_sleep_gap(self):
        target = Path(self.tmp.name) / 'other'
        stop = threading.Event()
        calls = []
        def sample(cfg, stop_event=None):
            calls.append(1)
            if len(calls) == 2: stop.set()
            return [row('success')]
        with patch.object(m, 'sample_probe', side_effect=sample), patch.object(stop, 'wait'), patch.object(m.time, 'monotonic', side_effect=[0, 1, 120, 121]):
            m.collect({}, target, stop_event=stop)
        self.assertEqual(m.read_snapshot(target)['gaps'][0]['reason'], 'sleep_or_clock_jump')

    def test_state_handle_lives_until_store_close(self):
        fd = self.store._directory.fd
        self.assertEqual(os.fstat(fd).st_ino, self.path.stat().st_ino)
        self.store.close()
        with self.assertRaises(OSError):
            os.fstat(fd)
        self.store.close()  # Closing twice must not close a reused descriptor.

    def test_untrusted_ancestor_owner_rejected(self):
        from types import SimpleNamespace
        with patch.object(m.os, 'fstat', return_value=SimpleNamespace(
                st_uid=os.getuid() + 123456, st_mode=0o40700)):
            with self.assertRaisesRegex(ValueError, 'unsafe_state_directory_ancestor'):
                m._check_directory(-1)

    def test_parent_components_rejected(self):
        with self.assertRaises(ValueError):
            m.Store(self.path / '..' / 'other', {})
        self.assertFalse((Path(self.tmp.name) / 'other').exists())


class AutoCycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state'
        self.store = m.Store(self.path, {})
        self.sources = Path(self.tmp.name) / 'sources'
        import egress_sources
        self.egress = egress_sources

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_auto_cycle_persists_events_runtime_and_freshness_window(self):
        def fake_evaluate(directory, runtime, emit):
            emit('auto_switch', {'from': None, 'to': 'primary', 'node': 'nmd-x-y', 'reason': 'auto_engaged'})
            return {'signature': 's', 'target': 'primary'}
        with patch.object(self.egress, 'auto_evaluate', fake_evaluate):
            self.assertGreaterEqual(m.run_auto_cycle(self.store, self.sources, {'interval_seconds': 30}), 0)
        snapshot = m.read_snapshot(self.path)
        self.assertEqual(snapshot['auto_events'][0]['kind'], 'auto_switch')
        self.assertEqual(snapshot['auto_events'][0]['detail']['node'], 'nmd-x-y')
        self.assertEqual(snapshot['collector']['auto_runtime']['target'], 'primary')
        self.assertGreaterEqual(snapshot['collector']['expected_cycle_seconds'], 32)

    def test_source_errors_are_silent_but_other_failures_are_recorded(self):
        with patch.object(self.egress, 'auto_evaluate', side_effect=self.egress.SourceError('invalid_auto')):
            self.assertEqual(m.run_auto_cycle(self.store, self.sources, {'interval_seconds': 30}), 0.0)
        self.assertEqual(m.read_snapshot(self.path)['auto_events'], [])
        with patch.object(self.egress, 'auto_evaluate', side_effect=RuntimeError('boom')):
            self.assertEqual(m.run_auto_cycle(self.store, self.sources, {'interval_seconds': 30}), 0.0)
        self.assertEqual(m.read_snapshot(self.path)['auto_events'][0]['kind'], 'auto_error')

    def test_collect_once_runs_auto_without_breaking_sampling(self):
        events = []
        def fake_evaluate(directory, runtime, emit):
            events.append(1)
            return {}
        with patch.object(self.egress, 'auto_evaluate', fake_evaluate), \
                patch.object(m.nmd_platform, 'name', return_value='linux'), \
                patch.object(m, 'sample_probe', return_value=[dict(id='local', type='passive', path='local', status='unknown', error='fixture_only', timings={}, observed_at=m.time.time())]):
            m.collect({'interval_seconds': 5, 'probes': []}, self.path, once=True, sources_dir=self.sources)
        self.assertEqual(events, [1])
        snapshot = m.read_snapshot(self.path)
        self.assertEqual(snapshot['collector']['state'], 'fresh')
        self.assertTrue(any(sample['type'] == 'passive' for sample in snapshot['samples']))

    def test_snapshot_tolerates_state_from_before_auto_mode(self):
        self.store.db.execute('DROP TABLE auto_events')
        self.store.db.commit()
        self.assertEqual(m.read_snapshot(self.path)['auto_events'], [])


class RunnerTests(unittest.TestCase):
    def test_deadline_kills_group_and_scrubs_environment(self):
        import subprocess
        from unittest.mock import Mock
        proc = Mock(pid=123)
        proc.communicate.side_effect = [subprocess.TimeoutExpired('test', 1), (b'', b'')]
        with patch.object(m.subprocess, 'Popen', return_value=proc) as popen, patch.object(m.os, 'killpg') as kill:
            self.assertEqual(m._run(['/usr/bin/curl', '--disable'], 1)[2], 'timeout')
        kill.assert_called_once_with(123, m.signal.SIGKILL)
        self.assertNotIn('HTTP_PROXY', popen.call_args.kwargs['env'])
        self.assertTrue(popen.call_args.kwargs['start_new_session'])


if __name__ == '__main__': unittest.main()
