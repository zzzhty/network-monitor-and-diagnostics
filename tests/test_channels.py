"""Channel behavior with synthetic private registries; no real configuration/network."""
import copy
import http.client
import threading
from contextlib import redirect_stdout
import io
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


class ChannelFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.directory = self.base / 'config/egress'
        self.store = e.Store(self.directory)
        env = patch.dict(os.environ, {'HOME': str(self.base / 'home'),
                                     'XDG_CONFIG_HOME': str(self.base / 'config'),
                                     'XDG_STATE_HOME': str(self.base / 'state')})
        env.start(); self.addCleanup(env.stop)
        for name in ('Controller', 'fetch_subscription'):
            guard = patch.object(e, name, side_effect=AssertionError('real network forbidden'))
            guard.start(); self.addCleanup(guard.stop)
        self.tail = {'kind': 'tailnet', 'server': '100.64.0.10', 'port': 1080}
        self.proxy = {'kind': 'proxy', 'server': '192.0.2.10', 'port': 1080,
                      'username': 'SYNTHETIC_USER', 'password': 'SYNTHETIC_PASSWORD'}
        self.subscription = {'kind': 'subscription', 'url': 'https://fixture.example.invalid/SYNTHETIC_SECRET'}

    def node(self, source):
        return self.store.load()['cache'][source]['nodes'][0]['name']

class ChannelTests(ChannelFixture):
    def test_rename_keeps_cached_node_and_selected_identity(self):
        e.put_source(self.store, 'tail-a', self.tail)
        original = self.node('tail-a')
        e.select(self.store, original, deferred=True)
        before = copy.deepcopy(self.store.load()['cache'])
        e.rename_source(self.store, 'tail-a', '香港通道')
        value = self.store.load()
        self.assertEqual(value['sources']['tail-a']['display_name'], '香港通道')
        self.assertEqual(value['selected'], original)
        self.assertEqual(value['cache'], before)
        regenerated = e.tailnet_nodes('tail-a', value['sources']['tail-a'])
        self.assertEqual(regenerated[0]['name'], original)
        # The existing update command also treats a display-only edit as rename.
        e.put_source(self.store, 'tail-a', dict(self.tail, display_name='第二名称'), replace=True)
        self.assertEqual(self.store.load()['cache'], before)

    def test_multiple_public_and_tailnet_channels_keep_connection_paths_separate(self):
        e.put_source(self.store, 'tail-a', self.tail)
        e.put_source(self.store, 'proxy-a', dict(self.proxy, display_name='公网 VPS'))
        e.put_source(self.store, 'proxy-b', dict(self.proxy, port=1081))
        value = self.store.load()
        self.assertEqual(value['cache']['tail-a']['nodes'][0]['interface-name'], 'tailscale0')
        self.assertNotIn('interface-name', value['cache']['proxy-a']['nodes'][0])
        self.assertNotEqual(self.node('proxy-a'), self.node('proxy-b'))
        view = e.public_status(self.directory, online=False, include_display=True)
        self.assertEqual(view['desired'], None)
        self.assertEqual(next(row for row in view['sources'] if row['id'] == 'proxy-a')['display_name'], '公网 VPS')
        text = json.dumps(view)
        for secret in ('SYNTHETIC_USER', 'SYNTHETIC_PASSWORD', '192.0.2.10'):
            self.assertNotIn(secret, text)
        for definition in (dict(self.tail, server='192.0.2.10'),
                           dict(self.proxy, server='100.64.0.10'),
                           dict(self.proxy, server='::ffff:100.64.0.10'),
                           dict(self.proxy, server='2001:db8::1%tailscale0'),
                           dict(self.proxy, **{'interface-name': 'tailscale0'})):
            with self.assertRaises(e.SourceError): e.validate_source(definition)

    def test_subscription_display_metadata_does_not_change_legacy_node_hash(self):
        raw = [dict(name='synthetic node', type='socks5', server='192.0.2.20', port=1080)]
        old = e.normalize_nodes('sub-a', self.subscription, raw)
        renamed = e.normalize_nodes('sub-a', dict(self.subscription, display_name='订阅二'), raw)
        self.assertEqual(old, renamed)
        e.put_source(self.store, 'sub-a', dict(self.subscription, display_name='订阅一'))
        e.put_source(self.store, 'sub-b', dict(self.subscription, url=self.subscription['url'] + '2'))
        self.assertNotIn('sub-a', self.store.load()['cache'])
        self.assertEqual(len(self.store.load()['sources']), 2)


class ChannelPolicyTests(ChannelFixture):
    def seed(self):
        e.put_source(self.store, 'tail-a', self.tail)
        e.put_source(self.store, 'sub-a', self.subscription)
        subscription_nodes = e.normalize_nodes('sub-a', self.subscription, [
            dict(name='one', type='socks5', server='192.0.2.20', port=1080),
            dict(name='two', type='socks5', server='192.0.2.21', port=1080)])
        with self.store.edit() as value:
            value['cache']['sub-a'] = dict(nodes=subscription_nodes, refreshed_at=1)
        return self.node('tail-a'), subscription_nodes[0]['name'], subscription_nodes[1]['name']

    def test_legacy_policy_reads_are_pure_and_explicit_rename_migrates_in_order(self):
        tail, subscription, _ = self.seed()
        for primary in ('tailnet', 'subscription'):
            for enabled, paused in ((True, False), (True, True), (False, False)):
                with self.subTest(primary=primary, enabled=enabled, paused=paused):
                    value = self.store.load()
                    value['selected'] = subscription
                    legacy = dict(enabled=enabled, paused=paused, primary=primary,
                                  tailnet=dict(source='tail-a', node=tail),
                                  subscription=dict(source='sub-a', node=subscription),
                                  fail_after=3, recover_after=2, cooldown=2)
                    value['auto'] = legacy
                    e.atomic_write(self.store.path, e.encode(value))
                    before = self.store.path.read_bytes()
                    view = e.public_status(self.directory, online=False)
                    self.assertEqual(self.store.path.read_bytes(), before)
                    self.assertEqual(view['auto']['version'], 2)
                    first = tail if primary == 'tailnet' else subscription
                    second = subscription if primary == 'tailnet' else tail
                    self.assertEqual(view['auto']['primary']['node'], first)
                    self.assertEqual(view['auto']['secondary']['node'], second)
                    e.rename_source(self.store, 'tail-a', '改名但不改变身份')
                    migrated = json.loads(self.store.path.read_bytes())
                    self.assertEqual(migrated['auto'], view['auto'])
                    self.assertEqual((migrated['auto']['enabled'], migrated['auto']['paused'], migrated['selected']),
                                     (enabled, paused, subscription))
                    self.assertEqual(self.node('tail-a'), tail)

    def test_explicit_candidates_allow_same_kind_and_same_channel_without_auto_additions(self):
        tail, subscription, another_subscription = self.seed()
        e.put_source(self.store, 'proxy-a', self.proxy)
        e.put_source(self.store, 'proxy-b', dict(self.proxy, port=1081))
        for primary, secondary in ((subscription, another_subscription),
                                   (self.node('proxy-a'), self.node('proxy-b')),
                                   (tail, self.node('proxy-a'))):
            with self.subTest(primary=primary, secondary=secondary):
                e.auto_configure(self.store, dict(action='enable', primary_node=primary, secondary_node=secondary))
                policy = self.store.load()['auto']
                self.assertEqual(policy['primary']['node'], primary)
                self.assertEqual(policy['secondary']['node'], secondary)
                e.put_source(self.store, 'unused', dict(self.proxy, port=1082), replace='unused' in self.store.load()['sources'])
                self.assertEqual(self.store.load()['auto'], policy)
        before = self.store.path.read_bytes()
        for payload in (dict(action='enable', primary_node=tail, secondary_node=tail),
                        dict(action='enable', primary_node=tail),
                        dict(action='enable', primary_node=tail, secondary_node='missing')):
            with self.assertRaises(e.SourceError): e.auto_configure(self.store, payload)
            self.assertEqual(self.store.path.read_bytes(), before)

    def controller(self, selected):
        test = self
        self.actual, self.puts, self.probes, self.failing = selected, [], [], set()
        self.during_delay = None
        self.uncertain = False
        class Controller:
            def current(self):
                return dict(type='Selector', now=test.actual, all=list(e.inventory(test.store.load())))
            def request(self, method, body):
                assert method == 'PUT'
                test.actual = body['name']; test.puts.append(body['name'])
                if test.uncertain:
                    test.uncertain = False
                    raise e.SourceError('synthetic_uncertain_put')
            def delay(self, provider, node):
                test.probes.append(node)
                callback = test.during_delay; test.during_delay = None
                if callback: callback()
                if node in test.failing: raise e.SourceError('delay_test_failed')
                return 10
        return patch.object(e, 'Controller', return_value=Controller())

    def evaluate(self, runtime):
        events = []
        runtime = e.auto_evaluate(self.directory, runtime, lambda kind, detail: events.append(kind))
        return runtime, events

    def test_manual_subscription_choice_pauses_without_replacing_policy_candidates(self):
        _, primary, secondary = self.seed()
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', primary_node=primary, secondary_node=secondary,
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(primary):
            runtime, _ = self.evaluate({})
            self.failing = {primary}
            runtime, _ = self.evaluate(runtime)
            self.during_delay = lambda: e.select(self.store, secondary)
            self.evaluate(runtime)
        self.assertEqual(self.puts, [secondary])
        self.assertEqual(self.actual, secondary)
        policy = self.store.load()['auto']
        self.assertTrue(policy['paused'])
        self.assertEqual((policy['primary']['node'], policy['secondary']['node']), (primary, secondary))

    def test_same_kind_failover_confirms_uncertain_switch_and_recovers_without_enrolling_new_channel(self):
        e.put_source(self.store, 'proxy-a', self.proxy)
        e.put_source(self.store, 'proxy-b', dict(self.proxy, port=1081))
        primary, secondary = self.node('proxy-a'), self.node('proxy-b')
        e.auto_configure(self.store, dict(action='enable', primary_node=primary, secondary_node=secondary,
                                         fail_after=2, recover_after=2, cooldown=2))
        with self.controller(primary):
            runtime, _ = self.evaluate({})
            self.assertEqual(self.puts, [primary])
            e.put_source(self.store, 'not-enrolled', dict(self.proxy, port=1082))
            self.failing = {primary}
            runtime, _ = self.evaluate(runtime)
            self.uncertain = True
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, ['auto_switch_failed'])
            self.assertEqual(runtime['pending_verify'], secondary)
            self.assertEqual(self.store.load()['selected'], primary)
            self.failing = set()
            runtime, events = self.evaluate(runtime)
            self.assertIn('auto_verify_adopted', events)
            self.assertEqual(self.store.load()['selected'], secondary)
            for _ in range(10): runtime, _ = self.evaluate(runtime)
        self.assertEqual((self.actual, runtime['target']), (primary, 'primary'))
        self.assertEqual(self.puts, [primary, secondary, primary])
        self.assertEqual(set(self.probes), {primary, secondary})

    def test_uncertain_manual_put_pauses_before_returning_unknown_outcome(self):
        _, primary, secondary = self.seed()
        e.select(self.store, primary, deferred=True)
        e.auto_configure(self.store, dict(action='enable', primary_node=primary, secondary_node=secondary))
        with self.controller(primary):
            self.uncertain = True
            with self.assertRaisesRegex(e.SourceError, 'selection_outcome_unknown'):
                e.select(self.store, secondary)
            self.assertEqual(self.actual, secondary)
            self.assertEqual(self.store.load()['selected'], primary)
            self.assertTrue(self.store.load()['auto']['paused'])
            self.evaluate({})
        self.assertEqual(self.puts, [secondary])
        self.assertEqual(self.probes, [])

    def test_legacy_pending_readback_is_preserved_across_policy_migration(self):
        tail, primary, _ = self.seed()
        value = self.store.load(); value['selected'] = primary
        legacy = dict(enabled=True, paused=False, primary='subscription',
                      tailnet=dict(source='tail-a', node=tail), subscription=dict(source='sub-a', node=primary),
                      fail_after=3, recover_after=2, cooldown=2)
        value['auto'] = legacy
        e.atomic_write(self.store.path, e.encode(value))
        legacy_fields = {key: legacy[key] for key in ('primary', 'tailnet', 'subscription', 'fail_after', 'recover_after', 'cooldown')}
        signature = e.hashlib.sha256(e.encode(legacy_fields)).hexdigest()[:20]
        runtime = dict(signature=signature, target='primary', primary_fail=3, primary_recover=0,
                       secondary_fail=0, cycles_since_switch=2, pending_verify=tail,
                       suspended=False, both_unhealthy=False)
        with self.controller(tail): runtime, events = self.evaluate(runtime)
        self.assertIn('auto_verify_adopted', events)
        self.assertNotIn('candidate_changed', events)
        self.assertEqual(runtime['target'], 'secondary')
        self.assertEqual(self.puts, [])
        self.assertEqual(self.store.load()['selected'], tail)
        self.assertEqual(self.store.load()['auto'], legacy)
        e.rename_source(self.store, 'tail-a', '显式写后迁移')
        self.assertEqual(self.store.load()['auto']['version'], 2)


class ChannelAPITests(ChannelFixture):
    def dashboard(self, platform='linux'):
        import observability
        platform_mock = patch.object(observability.nmd_platform, 'name', return_value=platform)
        platform_mock.start(); self.addCleanup(platform_mock.stop)
        server = observability.DashboardServer(0, self.base / 'state', self.directory)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        def stop():
            server.shutdown(); server.server_close(); worker.join(3)
        self.addCleanup(stop)
        return server

    def request(self, server, route, body, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
        try:
            head = {'Content-Type': 'application/json', **(headers or {})}
            connection.request('POST', route, body=e.encode(body), headers=head)
            response = connection.getresponse()
            return response.status, response.read()
        finally: connection.close()

    def test_add_and_rename_save_only_private_config_with_strict_route_and_fields(self):
        server = self.dashboard()
        status, body = self.request(server, '/api/channels', {'id': 'sub-a', 'definition': dict(self.subscription, display_name='订阅一')})
        self.assertEqual(status, 200, body)
        self.assertNotIn(b'SYNTHETIC_SECRET', body)
        self.assertNotIn('sub-a', self.store.load()['cache'])
        self.assertIsNone(self.store.load()['selected'])
        self.assertNotIn('auto', self.store.load())
        self.assertEqual(self.request(server, '/api/channels/rename', {'id': 'sub-a', 'display_name': '新名字'})[0], 200)
        self.assertEqual(self.store.load()['sources']['sub-a']['display_name'], '新名字')
        for route, payload in (('/api/channels', {'id': 'other', 'definition': self.subscription, 'refresh': True}),
                               ('/api/channels/rename', {'id': 'sub-a', 'display_name': 'bad', 'node': 'DIRECT'}),
                               ('/api/channels?apply=true', {})):
            self.assertEqual(self.request(server, route, payload)[0], 400)
        self.assertEqual(self.request(server, '/api/channels', {'id': 'sub-a', 'definition': self.subscription})[0], 409)
        self.assertEqual(self.request(server, '/api/channels/refresh', {'id': 'sub-a'})[0], 405)
        for headers in ({'Origin': 'https://evil.invalid'}, {'Host': 'evil.invalid'}, {'Sec-Fetch-Site': 'cross-site'}):
            self.assertEqual(self.request(server, '/api/channels/rename', {'id': 'sub-a', 'display_name': 'blocked'}, headers)[0], 403)

    def test_invalid_private_fields_are_sanitized_and_do_not_create_a_channel(self):
        server = self.dashboard()
        for definition in (dict(self.subscription, url='http://fixture.invalid/SYNTHETIC_SECRET'),
                           dict(self.proxy, **{'interface-name': 'tailscale0'}),
                           dict(self.subscription, display_name='\nSYNTHETIC_SECRET')):
            status, body = self.request(server, '/api/channels', {'id': 'bad', 'definition': definition})
            self.assertEqual(status, 409, body)
            self.assertNotIn(b'SYNTHETIC_SECRET', body)
        self.assertNotIn('bad', self.store.load()['sources'])

    def test_macos_rejects_management_before_opening_private_sources(self):
        server = self.dashboard('macos')
        with patch.object(e.Store, 'load', side_effect=AssertionError('real private sources forbidden')):
            for route, body in (('/api/channels', {'id': 'sub-a', 'definition': self.subscription}),
                                ('/api/channels/rename', {'id': 'sub-a', 'display_name': 'no'})):
                self.assertEqual(self.request(server, route, body)[0], 405)
        self.assertFalse(self.directory.exists())


class ChannelCLITests(ChannelFixture):
    def run_cli(self, args):
        output = io.StringIO()
        with redirect_stdout(output): e.main(args, directory=self.directory)
        return json.loads(output.getvalue())

    def test_rename_command_and_explicit_node_policy_keep_source_cli_compatible(self):
        e.put_source(self.store, 'proxy-a', self.proxy)
        e.put_source(self.store, 'proxy-b', dict(self.proxy, port=1081))
        self.run_cli(['rename', 'proxy-a', '--name', '新通道'])
        primary, secondary = self.node('proxy-a'), self.node('proxy-b')
        self.run_cli(['auto', 'enable', '--primary-node', primary, '--secondary-node', secondary])
        self.assertEqual(self.store.load()['auto']['primary']['node'], primary)
        self.run_cli(['auto', 'swap'])
        self.assertEqual(self.store.load()['auto']['primary']['node'], secondary)
        self.run_cli(['auto', 'disable'])
        self.assertFalse(self.store.load()['auto']['enabled'])
        import manager
        with patch.object(manager.nmd_platform, 'name', return_value='linux'), \
                patch.object(manager, 'source_directory', return_value=self.directory), \
                patch.object(e, 'main') as dispatcher:
            manager.main(['channel', 'list'])
            self.assertEqual(dispatcher.call_args.args, (['list'],))
