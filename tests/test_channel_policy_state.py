"""Channel/Policy state transitions with synthetic fixtures and mocked controllers.

No real subscription, controller, deployment or network operation is used.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import egress_sources as e


class StateFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.directory = self.base / 'config/egress'
        self.directory.parent.mkdir(mode=0o700)
        self.store = e.Store(self.directory)
        env = patch.dict(os.environ, {'HOME': str(self.base / 'home'),
                                     'XDG_CONFIG_HOME': str(self.base / 'config'),
                                     'XDG_STATE_HOME': str(self.base / 'state')})
        env.start(); self.addCleanup(env.stop)
        for name in ('Controller', 'fetch_subscription'):
            guard = patch.object(e, name, side_effect=AssertionError('real network forbidden'))
            guard.start(); self.addCleanup(guard.stop)
        self.tail = {'kind': 'tailnet', 'server': '100.64.0.10', 'port': 1080}
        self.subscription = {'kind': 'subscription', 'url': 'https://fixture.example.invalid/SYNTHETIC_SECRET'}

    def provider(self, names):
        """Synthetic provider document; identical rows reproduce identical node ids."""
        proxies = [dict(name=name, type='socks5', server=f'192.0.2.{20 + index}', port=1080)
                   for index, name in enumerate(names)]
        path = self.base / ('provider-' + '-'.join(names).replace(' ', '_') + '.json')
        path.write_text(json.dumps({'proxies': proxies}))
        return path

    def seed_subscription(self, names=('one', 'two')):
        e.put_source(self.store, 'sub-a', self.subscription)
        e.refresh(self.store, 'sub-a', self.provider(list(names)))
        return [node['name'] for node in self.store.load()['cache']['sub-a']['nodes']]

    def controller(self, selected):
        test = self
        self.actual, self.puts, self.probes, self.failing = selected, [], [], set()
        self.uncertain = False
        class Controller:
            def current(self):
                return dict(type='Selector', now=test.actual, all=list(e.inventory(test.store.load())))
            def request(self, method, body):
                test.actual = body['name']; test.puts.append(body['name'])
                if test.uncertain:
                    test.uncertain = False
                    raise e.SourceError('synthetic_uncertain_put')
            def delay(self, provider, node):
                test.probes.append(node)
                if node in test.failing: raise e.SourceError('delay_test_failed')
                return 10
        return patch.object(e, 'Controller', return_value=Controller())

    def evaluate(self, runtime):
        events = []
        runtime = e.auto_evaluate(self.directory, runtime, lambda kind, detail: events.append(kind))
        return runtime, events


class NoNodeTests(StateFixture):
    def test_empty_or_unrefreshed_registry_rejects_every_state_entry(self):
        for name in ('DIRECT', 'nmd-sub-a-00000000000000000000'):
            with self.subTest(name=name), self.assertRaisesRegex(e.SourceError, 'node_not_found'):
                e.select(self.store, name, deferred=True)
        with self.assertRaisesRegex(e.SourceError, 'auto_legacy_payload_removed'):
            e.auto_configure(self.store, dict(action='enable', primary_node='DIRECT', secondary_node='other'))
        with self.assertRaisesRegex(e.SourceError, 'auto_node_not_in_inventory'):
            e.auto_configure(self.store, dict(action='enable', nodes=['nmd-sub-a-00000000000000000000']))
        self.assertFalse(self.store.path.exists())
        view = e.public_status(self.directory, online=False)
        self.assertIsNone(view['desired'])
        # An added but never-refreshed subscription still exposes no nodes.
        e.put_source(self.store, 'sub-a', self.subscription)
        with self.assertRaisesRegex(e.SourceError, 'auto_node_not_in_inventory'):
            e.auto_configure(self.store, dict(action='enable',
                                             nodes=['nmd-sub-a-00000000000000000000',
                                                    'nmd-sub-a-11111111111111111111']))
        self.assertNotIn('auto', self.store.load())
        with self.assertRaisesRegex(e.SourceError, 'choose_cached'):
            e.render_runtime(self.directory, ROOT / 'config.yaml', self.base / 'stage/config.yaml')


class ChannelIdentityTests(StateFixture):
    def test_duplicate_display_names_keep_independent_identities_and_ids(self):
        e.put_source(self.store, 'proxy-a', dict(kind='proxy', server='192.0.2.10', port=1080,
                                                display_name='同名通道'))
        e.put_source(self.store, 'proxy-b', dict(kind='proxy', server='192.0.2.11', port=1080,
                                                display_name='同名通道'))
        e.put_source(self.store, 'tail-a', self.tail)
        first = self.store.load()['cache']['proxy-a']['nodes'][0]['name']
        second = self.store.load()['cache']['proxy-b']['nodes'][0]['name']
        self.assertNotEqual(first, second)
        e.rename_source(self.store, 'tail-a', '同名通道')
        with self.assertRaisesRegex(e.SourceError, 'source_already_exists'):
            e.put_source(self.store, 'proxy-a', dict(kind='proxy', server='192.0.2.10', port=1080))
        view = e.public_status(self.directory, online=False, include_display=True)
        shown = {row['id']: row['display_name'] for row in view['sources']}
        self.assertEqual(sorted(shown), ['proxy-a', 'proxy-b', 'tail-a'])
        self.assertEqual(len(set(shown.values())), 1)
        # The registry cap keeps identities bounded even with shared names.
        for index in range(29):
            e.put_source(self.store, f'fill-{index:02}',
                         dict(kind='proxy', server=f'192.0.2.{30 + index}', port=1080,
                              display_name='同名通道'))
        self.assertEqual(len(self.store.load()['sources']), 32)
        with self.assertRaisesRegex(e.SourceError, 'too_many_sources'):
            e.put_source(self.store, 'overflow', dict(kind='proxy', server='203.0.113.1', port=1080))
        self.assertNotIn('overflow', self.store.load()['sources'])
        self.assertEqual(self.store.load()['cache']['proxy-a']['nodes'][0]['name'], first)

    def test_invalid_display_names_are_rejected_without_any_write(self):
        e.put_source(self.store, 'tail-a', self.tail)
        before = self.store.path.read_bytes()
        for name in ('', ' \t ', 'x' * 129, 'line\nbreak', None):
            with self.subTest(name=name), self.assertRaisesRegex(e.SourceError, 'invalid_channel_name'):
                e.rename_source(self.store, 'tail-a', name)
            with self.assertRaisesRegex(e.SourceError, 'invalid_channel_name'):
                e.put_source(self.store, 'tail-a', dict(self.tail, display_name=name), replace=True)
        with self.assertRaisesRegex(e.SourceError, 'source_not_found'):
            e.rename_source(self.store, 'missing', '合法名称')
        self.assertEqual(self.store.path.read_bytes(), before)


class RefreshPolicyTests(StateFixture):
    def test_refresh_dropping_a_candidate_suspends_and_restoring_resumes(self):
        primary, secondary = self.seed_subscription()
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', nodes=[primary, secondary],
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(primary):
            # The already-saved desired primary is adopted by alignment, not a PUT.
            runtime, events = self.evaluate({})
            self.assertEqual(events, [])
            self.assertEqual(runtime['target'], 0)
            # Dropping the non-selected candidate is accepted: only the saved
            # selection is protected; the policy survives and suspends instead.
            e.refresh(self.store, 'sub-a', self.provider(['one']))
            self.assertEqual([node['name'] for node in self.store.load()['cache']['sub-a']['nodes']], [primary])
            self.assertEqual(self.store.load()['auto']['candidates'][1]['node'], secondary)
            details = []
            runtime = e.auto_evaluate(self.directory, runtime,
                                      lambda kind, detail: details.append((kind, detail)))
            self.assertEqual(details, [('auto_suspended', {'reason': 'node_missing', 'rank': 1})])
            self.assertTrue(runtime['suspended'])
            # Identical definitions refresh back to identical anonymous ids.
            e.refresh(self.store, 'sub-a', self.provider(['one', 'two']))
            self.assertEqual([node['name'] for node in self.store.load()['cache']['sub-a']['nodes']],
                             [primary, secondary])
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_resumed'])
            self.assertFalse(runtime['suspended'])
            self.assertEqual(runtime['target'], 0)
        self.assertEqual(self.puts, [])
        self.assertEqual(set(self.probes), {primary, secondary})

    def test_refresh_rejecting_duplicate_names_preserves_cache_and_selection(self):
        primary, _ = self.seed_subscription(('solo-a', 'solo-b'))
        e.select(self.store, primary, deferred=True)
        before = self.store.path.read_bytes()
        with self.assertRaisesRegex(e.SourceError, 'duplicate_proxy_name'):
            e.refresh(self.store, 'sub-a', self.provider(['twin', 'twin']))
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(self.store.load()['selected'], primary)


class AllUnhealthyHoldTests(StateFixture):
    def test_all_candidates_unhealthy_holds_then_hysteresis_resumes(self):
        primary, secondary = self.seed_subscription()
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', nodes=[primary, secondary],
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(primary):
            # Alignment adopts the saved desired primary without any PUT.
            runtime, events = self.evaluate({})
            self.assertEqual((events, runtime['target']), ([], 0))
            self.failing = {primary, secondary}
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['all_unhealthy'])
            self.assertTrue(runtime['all_unhealthy'])
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, [])  # The unhealthy window latches without re-emitting.
            self.assertEqual(self.puts, [])
            self.assertEqual(runtime['target'], 0)
            self.assertEqual(self.store.load()['selected'], primary)
            # Only the primary recovers: failure counting restarts from the
            # pre-window state, so a full fail_after is still required.
            self.failing = {secondary}
            runtime, _ = self.evaluate(runtime)
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, [])
            self.assertEqual(self.puts, [])
            self.failing = {primary}
            runtime, _ = self.evaluate(runtime)
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_switch'])
            self.assertEqual((runtime['target'], self.store.load()['selected']), (1, secondary))
            self.failing = set()
            runtime, _ = self.evaluate(runtime)
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_switch'])
            self.assertEqual((runtime['target'], self.store.load()['selected']), (0, primary))
        self.assertEqual(self.puts, [secondary, primary])


class SavedNotSwitchedTests(StateFixture):
    def test_saved_selection_is_distinct_from_a_live_or_deployed_switch(self):
        primary, _ = self.seed_subscription(('one', 'two'))
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable',
                                         nodes=[primary, self.store.load()['cache']['sub-a']['nodes'][1]['name']]))
        deployed, calls = [], []
        class Controller:
            def __init__(self, value): calls.append('construct')
            def current(self):
                calls.append('current')
                return dict(type='Selector', now='REJECT', all=deployed)
            def request(self, method, body): calls.append(method)
            def delay(self, provider, node): calls.append('delay')
        with patch.object(e, 'Controller', Controller):
            view = e.public_status(self.directory, online=True)
            self.assertEqual(view['desired'], primary)
            self.assertIsNone(view['active'])
            self.assertEqual(view['controller'], 'unavailable_or_pending_apply')
            before = self.store.path.read_bytes()
            # A cached but undeployed node never reaches the live selector:
            # the rejection happens before the PUT and before any pause write.
            with self.assertRaisesRegex(e.SourceError, 'node_not_deployed'):
                e.select(self.store, primary)
            self.assertEqual(self.store.path.read_bytes(), before)
            self.assertFalse(self.store.load()['auto']['paused'])
        self.assertEqual(calls, ['construct', 'current', 'construct', 'current'])
        # Deferred saving touched no controller at all.
        self.assertNotIn('PUT', calls)
        self.assertNotIn('delay', calls)


class SetCandidatesTests(StateFixture):
    def test_set_candidates_reorders_pins_and_preserves_enabled_and_paused(self):
        primary, secondary = self.seed_subscription()
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', nodes=[primary, secondary]))
        e.select(self.store, secondary, deferred=True)  # A manual choice pauses, never re-pins.
        self.assertTrue(self.store.load()['auto']['paused'])
        e.auto_configure(self.store, dict(action='set-candidates', nodes=[secondary, primary]))
        swapped = self.store.load()['auto']
        self.assertEqual([pin['node'] for pin in swapped['candidates']], [secondary, primary])
        self.assertTrue(swapped['paused'])
        self.assertTrue(swapped['enabled'])
        self.assertEqual(e.public_status(self.directory, online=False)['selection_mode'], 'manual')
        e.auto_configure(self.store, dict(action='set-candidates', nodes=[primary, secondary]))
        self.assertEqual(e.auto_configure(self.store, dict(action='resume'))['result'], 'auto_resumed')
        resumed = self.store.load()['auto']
        self.assertEqual([pin['node'] for pin in resumed['candidates']], [primary, secondary])
        self.assertFalse(resumed['paused'])


class RuntimeViewTests(StateFixture):
    def test_derived_state_and_cooldown_follow_the_engine(self):
        primary, secondary = self.seed_subscription()
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', nodes=[primary, secondary],
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(primary):
            runtime, _ = self.evaluate({})
            self.assertEqual((runtime['target'], runtime['state'], runtime['cooldown_remaining']),
                             (0, 'active', 1))
            runtime, _ = self.evaluate(runtime)
            self.assertEqual((runtime['state'], runtime['cooldown_remaining']), ('active', 0))
            self.failing = {primary}
            runtime, _ = self.evaluate(runtime)
            self.assertEqual((runtime['state'], runtime['fails'][0]), ('failing', 1))
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_switch'])
            self.assertEqual((runtime['target'], runtime['state'], runtime['cooldown_remaining']),
                             (1, 'active', 1))
            runtime, _ = self.evaluate(runtime)
            self.assertEqual((runtime['state'], runtime['recover_count']), ('active', 0))
            self.failing = set()
            runtime, _ = self.evaluate(runtime)
            self.assertEqual((runtime['state'], runtime['recover_count']), ('recovering', 1))
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_switch'])
            self.assertEqual((runtime['target'], runtime['state'], runtime['cooldown_remaining']),
                             (0, 'active', 1))
            self.assertEqual(self.puts, [secondary, primary])

    def test_derived_state_flags_pause_all_unhealthy_and_suspension(self):
        primary, secondary = self.seed_subscription()
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', nodes=[primary, secondary],
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(primary):
            runtime, _ = self.evaluate({})
            self.assertEqual(runtime['state'], 'active')
            self.failing = {primary, secondary}
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['all_unhealthy'])
            self.assertEqual(runtime['state'], 'all_unhealthy')
            e.refresh(self.store, 'sub-a', self.provider(['one']))  # Drops only the spare candidate.
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_suspended'])
            self.assertEqual(runtime['state'], 'suspended')
            self.failing = set()
            e.refresh(self.store, 'sub-a', self.provider(['one', 'two']))
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_resumed'])
            self.assertEqual(runtime['state'], 'active')
            probes_before_pause = len(self.probes)
            e.select(self.store, secondary, deferred=True)  # A manual choice pauses; no re-pin.
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, [])
            self.assertEqual(runtime['state'], 'paused')
            self.assertEqual(len(self.probes), probes_before_pause)  # Paused and suspended probe nothing.

    def test_uncertain_switch_and_unreachable_controller_derive_their_states(self):
        primary, secondary = self.seed_subscription()
        e.auto_configure(self.store, dict(action='enable', nodes=[primary, secondary],
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(None):
            class Unreachable:
                def __init__(self, value): pass
                def current(self): raise e.SourceError('manual_selector_required')
                def delay(self, *args): raise AssertionError('no probes expected')
            with patch.object(e, 'Controller', Unreachable):
                runtime, events = self.evaluate({})  # No saved selection and no live target yet.
                self.assertEqual(events, ['controller_unreachable'])
                self.assertEqual((runtime['target'], runtime['state'], runtime['cooldown_remaining']),
                                 (None, 'engaging', 2))
            runtime, _ = self.evaluate(runtime)  # No saved selection: the engine engages via PUT.
            self.assertEqual((runtime['state'], runtime['cooldown_remaining']), ('active', 1))
            self.failing = {primary}
            runtime, _ = self.evaluate(runtime)
            self.uncertain = True
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_switch_failed'])
            self.assertEqual(runtime['pending_verify'], secondary)
            self.assertEqual(runtime['state'], 'pending_verify')

    def test_disabled_policy_has_no_derived_view(self):
        self.seed_subscription()
        runtime, events = self.evaluate({'stale': 'shape'})
        self.assertEqual((runtime, events), ({}, []))


class CandidateChainTests(StateFixture):
    def test_three_candidates_skip_dead_rank_and_recover_upward(self):
        first, second, third = self.seed_subscription(('one', 'two', 'three'))
        e.select(self.store, first, deferred=True)
        e.auto_configure(self.store, dict(action='enable', nodes=[first, second, third],
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(first):
            runtime, events = self.evaluate({})
            self.assertEqual((events, runtime['target']), ([], 0))
            details = []
            # Rank 1 is already dead when rank 0 starts failing: failover must
            # skip it and land on the next healthy candidate, not the next pin.
            self.failing = {second}
            runtime, _ = self.evaluate(runtime)
            self.failing = {first, second}
            runtime = e.auto_evaluate(self.directory, runtime,
                                      lambda kind, detail: details.append((kind, detail)))
            runtime = e.auto_evaluate(self.directory, runtime,
                                      lambda kind, detail: details.append((kind, detail)))
            self.assertEqual(details[-1], ('auto_switch', {'from': 0, 'to': 2, 'node': third,
                                                           'reason': 'candidate_unhealthy'}))
            self.assertEqual((runtime['target'], self.store.load()['selected']), (2, third))
            # Full recovery switches back to the highest-priority healthy rank.
            self.failing = set()
            runtime, _ = self.evaluate(runtime)
            self.assertEqual(runtime['state'], 'recovering')
            details.clear()
            runtime = e.auto_evaluate(self.directory, runtime,
                                      lambda kind, detail: details.append((kind, detail)))
            self.assertEqual(details, [('auto_switch', {'from': 2, 'to': 0, 'node': first,
                                                        'reason': 'candidate_recovered'})])
            self.assertEqual(runtime['target'], 0)
        self.assertEqual(self.puts, [third, first])
        # Probes cover every candidate each cycle, rank order included.
        self.assertEqual(self.probes[-3:], [first, second, third])

    def test_manual_selection_of_a_candidate_engages_its_rank(self):
        first, second = self.seed_subscription()
        e.select(self.store, first, deferred=True)
        e.auto_configure(self.store, dict(action='enable', nodes=[first, second]))
        with self.controller(first):
            runtime, _ = self.evaluate({})
            self.assertEqual(runtime['target'], 0)
            e.select(self.store, second, deferred=True)  # A manual choice pauses.
            e.auto_configure(self.store, dict(action='resume'))
            details = []
            runtime = e.auto_evaluate(self.directory, runtime,
                                      lambda kind, detail: details.append((kind, detail)))
            self.assertEqual(details, [('manual_engage', {'rank': 1, 'node': second})])
            self.assertEqual(runtime['target'], 1)
            self.assertEqual(runtime['fails'], [0, 0])


if __name__ == '__main__':
    unittest.main()
