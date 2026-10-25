"""Automatic state regressions: private JSON fixtures and mocked controller only."""
from contextlib import contextmanager, redirect_stdout
import copy
import http.client
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import egress_sources as e


class AutomaticStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve() / 'sources'
        self.store = e.Store(self.directory)
        self.tail = dict(kind='tailnet', server='100.64.0.10', port=1080)
        self.subscription = dict(kind='subscription', url='https://fixture.example.invalid/sub')
        e.put_source(self.store, 'tail-a', self.tail)
        e.put_source(self.store, 'tail-other', dict(self.tail, port=1081))
        e.put_source(self.store, 'sub-a', self.subscription)
        nodes = e.normalize_nodes('sub-a', self.subscription, [
            dict(name='fixture-one', type='socks5', server='192.0.2.10', port=1080),
            dict(name='fixture-two', type='socks5', server='192.0.2.11', port=1080)])
        with self.store.edit() as value:
            value['cache']['sub-a'] = dict(nodes=nodes, refreshed_at=1)
        value = self.store.load()
        self.primary = nodes[0]['name']
        self.other_primary = nodes[1]['name']
        self.secondary = value['cache']['tail-a']['nodes'][0]['name']
        self.manual_tail = value['cache']['tail-other']['nodes'][0]['name']
        e.select(self.store, self.primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', primary='subscription',
                         tailnet_node=self.secondary, subscription_node=self.primary,
                         fail_after=2, recover_after=2, cooldown=2))
        self.actual = self.primary
        self.puts = []
        self.failing = set()
        self.during_delay = None
        self.uncertain = False
        self.real_controller = e.Controller
        test = self
        class Controller:
            def current(self):
                return dict(now=test.actual, all=list(e.inventory(test.store.load())), type='Selector')
            def request(self, method, body):
                if method != 'PUT': raise AssertionError('unexpected controller operation')
                test.puts.append(body['name']);test.actual=body['name']
                if test.uncertain:
                    test.uncertain=False
                    raise e.SourceError('fixture_timeout_after_put')
                return {}
            def delay(self, provider, name):
                callback=test.during_delay;test.during_delay=None
                if callback is not None: callback()
                if name in test.failing: raise e.SourceError('delay_test_failed')
                return 10
        self.controller = Controller()
        mock = patch.object(e, 'Controller', return_value=self.controller)
        mock.start();self.addCleanup(mock.stop)
        transport = patch.object(e, 'fetch_subscription', side_effect=AssertionError('external subscription forbidden'))
        transport.start();self.addCleanup(transport.stop)

    def evaluate(self, runtime):
        events=[]
        runtime=e.auto_evaluate(self.directory, runtime, lambda kind, detail: events.append(kind))
        return runtime,events

    def ready_to_fail_over(self):
        runtime,_=self.evaluate({})
        self.failing={self.primary}
        runtime,_=self.evaluate(runtime)
        self.assertEqual(self.puts, [])
        return runtime

    def test_controller_probe_faults_preserve_counters_and_never_switch(self):
        runtime = self.ready_to_fail_over()
        expected = copy.deepcopy(runtime)
        before = self.store.path.read_bytes()
        client = self.real_controller(self.store.load())
        # Execute the real delay parser while current()/PUT remain mocked.
        # Node errors are only the pinned core's HTTP 503/504 responses.
        faults = [OSError('SYNTHETIC_SECRET'), http.client.HTTPException('SYNTHETIC_SECRET'),
                  (401, b'{}'), (404, b'{}'), (500, b'{}'), (200, b'not json'),
                  (200, b'{"delay":true}'), (200, b'{"delay":-1}'),
                  (200, b'x' * (e.MAX_BYTES + 1))]
        for fault in faults:
            for affected in ({self.primary}, {self.secondary}, {self.primary, self.secondary}):
                with self.subTest(fault=type(fault).__name__, affected=affected):
                    self.actual = self.primary
                    self.puts.clear()
                    with self.store.edit() as value:
                        value['selected'] = self.primary
                    connection = Mock()
                    def response():
                        target = connection.request.call_args.args[1]
                        hit = any('/' + node + '/healthcheck?' in target for node in affected)
                        if hit and isinstance(fault, Exception):
                            raise fault
                        code, body = fault if hit else (200, b'{"delay":10}')
                        return Mock(status=code, read=Mock(return_value=body))
                    connection.getresponse.side_effect = response
                    with patch.object(e.http.client, 'HTTPConnection', return_value=connection), \
                            patch.object(self.controller, 'delay', side_effect=client.delay):
                        # Several fault cycles must never satisfy the failover threshold.
                        observed = copy.deepcopy(expected)
                        for _ in range(4):
                            observed, events = self.evaluate(observed)
                            self.assertEqual(events, ['controller_unreachable'])
                            self.assertEqual(observed, expected)
                            self.assertEqual(self.puts, [])
                    self.assertEqual(self.store.path.read_bytes(), before)

    def test_valid_node_failures_still_switch_and_recover(self):
        client = self.real_controller(self.store.load())
        for failure_status in (503, 504):
            with self.subTest(status=failure_status):
                self.actual = self.primary
                with self.store.edit() as value:
                    value['selected'] = self.primary
                self.puts.clear()
                connection = Mock()
                failing = {self.primary}
                def response():
                    target = connection.request.call_args.args[1]
                    failed = any('/' + node + '/healthcheck?' in target for node in failing)
                    return Mock(status=failure_status if failed else 200,
                                read=Mock(return_value=b'{"message":"SYNTHETIC"}' if failed else b'{"delay":10}'))
                connection.getresponse.side_effect = response
                with patch.object(e.http.client, 'HTTPConnection', return_value=connection), \
                        patch.object(self.controller, 'delay', side_effect=client.delay):
                    runtime = {}
                    for _ in range(4):
                        runtime, _ = self.evaluate(runtime)
                    self.assertEqual(self.puts, [self.secondary])
                    failing.clear()
                    for _ in range(4):
                        runtime, _ = self.evaluate(runtime)
                    self.assertEqual(self.puts, [self.secondary, self.primary])

    def test_disable_completed_during_probes_prevents_auto_put(self):
        runtime=self.ready_to_fail_over()
        self.during_delay=lambda:e.auto_configure(self.store, {'action':'disable'})
        self.evaluate(runtime)
        self.assertEqual(self.puts, [])
        self.assertFalse(self.store.load()['auto']['enabled'])

    def test_manual_pause_during_probes_keeps_the_manual_exit(self):
        runtime=self.ready_to_fail_over()
        self.during_delay=lambda:e.select(self.store, self.manual_tail)
        self.evaluate(runtime)
        self.assertEqual(self.puts, [self.manual_tail])
        self.assertEqual(self.actual, self.manual_tail)
        self.assertTrue(self.store.load()['auto']['paused'])

    def test_policy_change_during_probes_invalidates_the_old_decision(self):
        runtime=self.ready_to_fail_over()
        self.during_delay=lambda:e.auto_configure(self.store, {'action':'set-primary','primary':'tailnet'})
        self.evaluate(runtime)
        self.assertEqual(self.puts, [])
        self.assertEqual(self.store.load()['auto']['primary']['node'], self.secondary)

    def test_manual_candidate_change_during_probes_pauses_without_replacing_pins(self):
        runtime=self.ready_to_fail_over()
        self.during_delay=lambda:e.select(self.store, self.other_primary)
        self.evaluate(runtime)
        self.assertEqual(self.puts, [self.other_primary])
        self.assertEqual(self.actual, self.other_primary)
        self.assertEqual(self.store.load()['auto']['primary']['node'], self.primary)

    def test_last_check_reads_the_value_loaded_under_the_writer_lock(self):
        runtime=self.ready_to_fail_over()
        original=e.Store.edit
        armed=True
        @contextmanager
        def disable_before_acquiring_writer(store, **options):
            nonlocal armed
            if armed:
                armed=False
                with original(store) as value:value['auto']['enabled']=False
            with original(store, **options) as value:yield value
        with patch.object(e.Store, 'edit', disable_before_acquiring_writer):
            self.evaluate(runtime)
        self.assertEqual(self.puts, [])
        self.assertFalse(self.store.load()['auto']['enabled'])

    def test_valid_failover_still_uses_the_shared_writer(self):
        runtime=self.ready_to_fail_over()
        runtime,events=self.evaluate(runtime)
        self.assertEqual(self.puts, [self.secondary])
        self.assertEqual(events, ['auto_switch'])
        self.assertEqual(runtime['target'], 'secondary')
        self.assertEqual(self.store.load()['selected'], self.secondary)

    def test_uncertain_secondary_adoption_is_persisted_and_eventually_recovers(self):
        runtime=self.ready_to_fail_over();self.uncertain=True
        runtime,events=self.evaluate(runtime)
        self.assertEqual(events, ['auto_switch_failed'])
        self.assertEqual(self.actual, self.secondary)
        self.assertEqual(self.store.load()['selected'], self.primary)
        self.failing=set()
        runtime,events=self.evaluate(runtime)
        self.assertEqual(events, ['auto_verify_adopted'])
        self.assertEqual(runtime['target'], 'secondary')
        self.assertEqual(self.store.load()['selected'], self.secondary)
        for _ in range(10):runtime,_=self.evaluate(runtime)
        self.assertEqual((self.actual,self.store.load()['selected'],runtime['target']),
                         (self.primary,self.primary,'primary'))
        self.assertEqual(self.puts, [self.secondary,self.primary])

    def test_manual_operation_before_pending_confirmation_wins(self):
        runtime=self.ready_to_fail_over();self.uncertain=True
        runtime,_=self.evaluate(runtime)
        e.select(self.store,self.manual_tail)
        before=list(self.puts)
        runtime,_=self.evaluate(runtime)
        self.assertEqual(self.puts,before)
        self.assertEqual(self.actual,self.manual_tail)
        self.assertEqual(self.store.load()['selected'],self.manual_tail)

    def test_removing_a_pinned_nonselected_source_clears_auto_atomically(self):
        for enabled in (True,False):
            with self.subTest(enabled=enabled):
                with self.store.edit() as value:value['auto']['enabled']=enabled
                with redirect_stdout(io.StringIO()):e.main(['remove','tail-a'],directory=self.directory)
                value=self.store.load()
                self.assertNotIn('auto',value)
                self.assertNotIn('tail-a',value['sources'])
                self.assertEqual(value['selected'],self.primary)
                e.put_source(self.store,'tail-a',self.tail)
                e.auto_configure(self.store,dict(action='enable',primary='subscription',tailnet_node=self.secondary,subscription_node=self.primary))
        self.assertEqual(self.puts,[])

    def test_kind_changes_clear_pins_but_same_kind_updates_remain_valid(self):
        for enabled in (True,False):
            with self.subTest(enabled=enabled):
                with self.store.edit() as value:value['auto']['enabled']=enabled
                e.put_source(self.store,'tail-a',dict(self.tail,port=1082),replace=True)
                self.assertIn('auto',self.store.load())
                e.put_source(self.store,'tail-a',self.subscription,replace=True)
                value=self.store.load()
                self.assertNotIn('auto',value)
                self.assertEqual(value['sources']['tail-a']['kind'],'subscription')
                e.put_source(self.store,'tail-a',self.tail,replace=True)
                e.auto_configure(self.store,dict(action='enable',primary='subscription',tailnet_node=self.secondary,subscription_node=self.primary))
        self.assertEqual(self.puts,[])

    def test_selected_source_delete_is_rejected_without_losing_policy(self):
        original=self.store.path.read_bytes()
        with self.assertRaisesRegex(e.SourceError,'selected_source'):
            e.main(['remove','sub-a'],directory=self.directory)
        self.assertEqual(self.store.path.read_bytes(),original)

    def test_invalid_auto_reference_cannot_be_committed(self):
        original=self.store.path.read_bytes()
        with self.assertRaisesRegex(e.SourceError,'invalid_auto'):
            with self.store.edit() as value:value['auto']['secondary']['source']='missing'
        self.assertEqual(self.store.path.read_bytes(),original)


if __name__=='__main__':unittest.main()
