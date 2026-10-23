"""Exercise the actual isolated probe code and result mapping without networking."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import nmd_monitor as m

FIXTURE = Path(__file__).resolve().parent / 'fixtures/socket_probe.py'


class SocketProbeTests(unittest.TestCase):
    def probe(self, kind='tcp', scenario=None, timeout=1, enabled=True, stop=None):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'events.json'
            prefix = (f'import runpy\nrunpy.run_path({str(FIXTURE)!r})'
                      f"['install']({scenario or {}!r}, {str(report)!r})\n")
            target = 'fixture.invalid' + ('' if kind == 'dns' else ':443')
            config = {'timeout_seconds': timeout, 'probes': [
                dict(id='fixture', type=kind, target=target, enabled=enabled)]}
            with patch.object(m, '_SOCKET_CODE', prefix + m._SOCKET_CODE), \
                    patch.object(m.nmd_platform, 'sample_local', return_value={}):
                result = m.sample_probe(config, stop_event=stop)[1]
            events = json.loads(report.read_text()) if report.exists() else []
        # No exception text, hostname or resolved address may enter stored results.
        serialized = json.dumps(result)
        for private in ('SYNTHETIC_PRIVATE', 'fixture.invalid', '192.0.2.1', '2001:db8'):
            self.assertNotIn(private, serialized)
        return result, events

    def failure(self, kind, scenario, error):
        result, events = self.probe(kind, scenario)
        self.assertEqual((result['status'], result['error'], result['timings']),
                         ('failure', error, {}))
        return events

    def test_dns_failure(self):
        events = self.failure('tcp', {'dns_error': 'dns'}, 'dns_error')
        self.assertEqual([event[0] for event in events], ['dns'])

    def test_refused_connection(self):
        events = self.failure('tcp', {'connect': [{'error': 'refused'}]}, 'connect_error')
        self.assertIn(['close', 0], events)

    def test_connect_timeout(self):
        self.failure('tcp', {'connect': [{'error': 'timeout'}]}, 'timeout')

    def test_tls_timeout(self):
        events = self.failure('tls', {'tls_error': 'timeout'}, 'timeout')
        self.assertIn(['close', 0], events)

    def test_certificate_verification_failure(self):
        events = self.failure('tls', {'tls_error': 'verify'}, 'tls_verify_error')
        self.assertIn(['close', 0], events)

    def test_other_tls_failure(self):
        self.failure('tls', {'tls_error': 'tls'}, 'tls_error')

    def test_tcp_resolves_once_and_reports_cumulative_timings(self):
        result, events = self.probe()
        self.assertEqual(result['status'], 'success')
        self.assertEqual(sum(event[0] == 'dns' for event in events), 1)
        self.assertAlmostEqual(result['timings']['dns'], 0.1)
        self.assertAlmostEqual(result['timings']['connect'], 0.3)
        self.assertAlmostEqual(result['timings']['total'], 0.3)
        self.assertNotIn('tls', result['timings'])
        self.assertIn(['close', 0], events)

    def test_tls_timings_sni_and_remaining_budget(self):
        result, events = self.probe('tls')
        self.assertEqual(result['status'], 'success')
        self.assertAlmostEqual(result['timings']['dns'], 0.1)
        self.assertAlmostEqual(result['timings']['connect'], 0.3)
        self.assertAlmostEqual(result['timings']['tls'], 0.6)
        self.assertAlmostEqual(result['timings']['total'], 0.6)
        self.assertIn(['tls', 'fixture.invalid'], events)
        budgets = [event[2] for event in events if event[0] == 'timeout']
        self.assertAlmostEqual(budgets[0], 0.9)
        self.assertAlmostEqual(budgets[-1], 0.7)

    def test_ipv6_to_ipv4_fallback_reuses_dns_and_closes_sockets(self):
        result, events = self.probe(scenario={'connect': [
            {'delay': 0.2, 'error': 'refused'}, {'delay': 0.3}]})
        self.assertEqual(result['status'], 'success')
        self.assertEqual(sum(event[0] == 'dns' for event in events), 1)
        addresses = [event[2][0] for event in events if event[0] == 'connect']
        self.assertEqual(addresses, ['2001:db8::1', '192.0.2.1'])
        self.assertIn(['close', 0], events)
        self.assertIn(['close', 1], events)
        self.assertAlmostEqual(result['timings']['connect'], 0.6)
        budgets = [event[2] for event in events if event[0] == 'timeout']
        self.assertAlmostEqual(budgets[0], 0.9)
        self.assertAlmostEqual(budgets[1], 0.7)

    def test_all_addresses_refused(self):
        events = self.failure('tcp', {'connect': [
            {'error': 'refused'}, {'error': 'refused'}]}, 'connect_error')
        self.assertEqual(sum(event[0] == 'connect' for event in events), 2)
        self.assertEqual(sum(event[0] == 'close' for event in events), 2)

    def test_empty_resolver_result(self):
        events = self.failure('tcp', {'empty_dns': True}, 'connect_error')
        self.assertEqual([event[0] for event in events], ['dns'])

    def test_exhausted_deadline_does_not_try_another_address(self):
        events = self.failure('tcp', {'connect': [{'delay': 2}, {}]}, 'timeout')
        self.assertEqual(sum(event[0] == 'connect' for event in events), 1)
        self.assertEqual(sum(event[0] == 'close' for event in events), 1)

    def test_early_timeout_can_fall_back_with_remaining_budget(self):
        result, events = self.probe(scenario={'connect': [
            {'delay': 0.2, 'error': 'timeout'}, {}]})
        self.assertEqual(result['status'], 'success')
        self.assertEqual(sum(event[0] == 'connect' for event in events), 2)
        self.assertEqual(sum(event[0] == 'close' for event in events), 2)

    def test_dns_only_does_not_create_socket(self):
        result, events = self.probe('dns')
        self.assertEqual(result['timings'], {'dns': 0.1})
        self.assertEqual([event[0] for event in events], ['dns'])

    def test_dns_exhausts_total_budget(self):
        for kind in ('dns', 'tcp', 'tls'):
            with self.subTest(kind=kind):
                events = self.failure(kind, {'dns_delay': 1.1}, 'timeout')
                self.assertEqual([event[0] for event in events], ['dns'])

    def test_fallback_shares_total_budget(self):
        events = self.failure('tcp', {'connect': [
            {'delay': 0.6, 'error': 'refused'}, {'delay': 0.4}]}, 'timeout')
        self.assertEqual(sum(event[0] == 'connect' for event in events), 2)
        self.assertEqual(sum(event[0] == 'close' for event in events), 2)

    def test_tls_shares_total_budget_with_dns_and_connect(self):
        self.failure('tls', {'dns_delay': 0.2, 'connect': [{'delay': 0.4}],
                             'tls_delay': 0.5}, 'timeout')

    def test_context_setup_also_consumes_budget(self):
        events = self.failure('tls', {'context_delay': 0.8}, 'timeout')
        self.assertFalse(any(event[0] == 'tls' for event in events))
        self.assertIn(['close', 0], events)

    def test_blocking_resolver_is_killed_by_real_parent_deadline(self):
        start = time.monotonic()
        events = self.failure('dns', {'dns_block': True}, 'timeout')
        self.assertLess(time.monotonic() - start, 4)
        self.assertEqual([event[0] for event in events], ['dns'])

    def test_stopping_and_disabled_never_launch_probe(self):
        stop = threading.Event()
        stop.set()
        for kwargs, error in [({'stop': stop}, 'collector_stopping'),
                              ({'enabled': False}, 'disabled')]:
            with self.subTest(error=error):
                result, events = self.probe(**kwargs)
                self.assertEqual((result['status'], result['error']), ('skipped', error))
                self.assertEqual(events, [])


if __name__ == '__main__':
    unittest.main()
