"""Layered egress diagnosis: verdict tree, battery assembly and the strict
dashboard endpoint. Verdict tests are pure; battery and endpoint tests inject
every side effect, so no test touches the network or a real controller."""
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import egress_sources as e
import egress_diagnose as d


def probe(ok=True, error=None, ms=100):
    return {"status": "ok" if ok else "fail", "error": error, "total_ms": ms}


def row(kind="tailnet", health="ok", tcp="ok", delay=10):
    return {"source": "tail-a" if kind == "tailnet" else "sub-a", "kind": kind,
            "node": "nmd-tail-a-0000000000000000000" if kind == "tailnet"
            else "nmd-sub-a-00000000000000000000",
            "health": health, "delay_ms": delay if health == "ok" else None, "tcp": tcp}


class VerdictTests(unittest.TestCase):
    """The decision tree runs on plain dicts; never any probe or store."""

    def healthy_probes(self):
        return {name: probe() for name, _ in d.HTTP_PROBES}

    def code(self, probes, candidates):
        return d.verdict(probes, candidates)["code"]

    def test_healthy_with_and_without_candidates(self):
        for candidates in ([row()], [row(kind="subscription"), row()], []):
            with self.subTest(candidates=candidates):
                result = d.verdict(self.healthy_probes(), candidates)
                self.assertEqual(result, {"code": "egress_healthy", "hint_key": "egress_healthy"})

    def test_direct_foreign_failure_is_local_internet_down_regardless_of_the_rest(self):
        probes = self.healthy_probes()
        probes["direct_foreign"] = probe(ok=False, error="connect_error")
        self.assertEqual(self.code(probes, []), "local_internet_down")
        self.assertEqual(self.code(probes, [row(health="fail", tcp="refused")]), "local_internet_down")

    def test_controller_fault_is_distinct_from_node_failure(self):
        probes = self.healthy_probes()
        # Even with every other candidate failing and TCP refused, a controller
        # probe fault must never be reported as node failure.
        candidates = [row(health="controller_unreachable"), row(health="fail", tcp="refused")]
        self.assertEqual(self.code(probes, candidates), "controller_unreachable")

    def test_all_candidates_failing_with_tcp_refused_is_node_service_down(self):
        probes = self.healthy_probes()
        probes["egress_foreign"] = probe(ok=False, error="timeout")
        candidates = [row(health="fail", tcp="refused"), row(kind="subscription", health="fail")]
        self.assertEqual(self.code(probes, candidates), "node_service_down")

    def test_all_candidates_failing_with_tcp_timeout_is_node_network_unreachable(self):
        probes = self.healthy_probes()
        probes["egress_foreign"] = probe(ok=False, error="timeout")
        for tcp in ("timeout", "unreachable"):
            with self.subTest(tcp=tcp):
                candidates = [row(health="fail", tcp=tcp), row(kind="subscription", health="fail")]
                self.assertEqual(self.code(probes, candidates), "node_network_unreachable")

    def test_node_up_but_domain_only_failure_is_exit_dns_poisoned(self):
        probes = self.healthy_probes()
        probes["egress_foreign"] = probe(ok=False, error="dns_error")
        # Health checks fail and the tailnet host accepts TCP, while the same
        # egress chain succeeds without DNS: poisoning at the exit side.
        candidates = [row(health="fail", tcp="ok"), row(kind="subscription", health="fail")]
        self.assertEqual(self.code(probes, candidates), "exit_dns_poisoned")

    def test_slow_foreign_egress_is_degraded_only_above_the_threshold(self):
        candidates = [row(), row(kind="subscription")]
        for total, expected in ((3000, "egress_healthy"), (3001, "egress_degraded")):
            with self.subTest(total=total):
                probes = self.healthy_probes()
                probes["egress_foreign"]["total_ms"] = total
                self.assertEqual(self.code(probes, candidates), expected)

    def test_unmatched_failures_fall_back_to_the_anomaly_code(self):
        probes = self.healthy_probes()
        probes["egress_cn"] = probe(ok=False, error="timeout")
        self.assertEqual(self.code(probes, []), "egress_anomaly")
        self.assertEqual(self.code(probes, [row()]), "egress_anomaly")


class DiagnoseFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.directory = self.base / 'config/egress'
        self.directory.parent.mkdir(mode=0o700)
        self.store = e.Store(self.directory)
        for name in ('Controller', 'fetch_subscription'):
            guard = patch.object(e, name, side_effect=AssertionError('real network forbidden'))
            guard.start(); self.addCleanup(guard.stop)
        self.tail = {'kind': 'tailnet', 'server': '100.64.0.10', 'port': 1080}
        self.subscription = {'kind': 'subscription', 'url': 'https://fixture.example.invalid/SYNTHETIC_SECRET'}

    def seed_policy(self):
        e.put_source(self.store, 'tail-a', self.tail)
        e.put_source(self.store, 'sub-a', self.subscription)
        nodes = e.normalize_nodes('sub-a', self.subscription, [
            dict(name='one', type='socks5', server='192.0.2.20', port=1080)])
        with self.store.edit() as value:
            value['cache']['sub-a'] = dict(nodes=nodes, refreshed_at=1)
        tail_node = self.store.load()['cache']['tail-a']['nodes'][0]['name']
        e.auto_configure(self.store, dict(action='enable', nodes=[tail_node, nodes[0]['name']]))
        return tail_node, nodes[0]['name']

    def fake_http(self, fail=()):
        def run(url):
            name = dict((url, key) for key, url in d.HTTP_PROBES)[url]
            return probe(ok=False, error="timeout") if name in fail else probe(ms=123)
        return run


class BatteryTests(DiagnoseFixture):
    def test_report_has_fixed_shape_and_never_leaks_node_addresses(self):
        tail, sub = self.seed_policy()
        seen_tcp = []
        def tcp(host, port):
            seen_tcp.append((host, port))
            return "ok", 33
        report = d.build_report(self.directory, http_probe=self.fake_http(), tcp_probe=tcp,
                                delay_probe=lambda source, node: 87,
                                selector_now=lambda value: tail, now=lambda: 123.5)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["generated_at"], 123.5)
        self.assertEqual(sorted(report["probes"]), ["direct_foreign", "egress_cn", "egress_exit_ip", "egress_foreign"])
        self.assertEqual(report["verdict"], {"code": "egress_healthy", "hint_key": "egress_healthy"})
        self.assertEqual(report["selector_now"], tail)
        self.assertEqual([candidate["node"] for candidate in report["candidates"]], [tail, sub])
        # Only tailnet-kind candidates get a bypass TCP probe; subscription
        # servers route through the TUN and are skipped with a reason code.
        self.assertEqual(seen_tcp, [("100.64.0.10", 1080)])
        by_source = {candidate["source"]: candidate for candidate in report["candidates"]}
        self.assertEqual((by_source["tail-a"]["tcp"], by_source["tail-a"]["tcp_ms"]), ("ok", 33))
        self.assertEqual(by_source["tail-a"]["health"], "ok")
        self.assertEqual(by_source["sub-a"]["tcp"], "skipped")
        self.assertEqual(by_source["sub-a"]["tcp_reason"], d.TCP_SKIP_REASON)
        text = json.dumps(report)
        for secret in ("100.64.0.10", "192.0.2.20", "SYNTHETIC_SECRET", "fixture.example.invalid"):
            self.assertNotIn(secret, text)

    def test_node_and_controller_faults_map_to_distinct_outcomes(self):
        tail, sub = self.seed_policy()
        def delay(source, node):
            if node == tail:
                raise e.SourceError("delay_test_failed")
            raise e.ControllerProbeError("delay_test_failed")
        report = d.build_report(self.directory, http_probe=self.fake_http(fail={"egress_foreign"}),
                                tcp_probe=lambda host, port: ("refused", None),
                                delay_probe=delay, selector_now=lambda value: None)
        by_source = {candidate["source"]: candidate for candidate in report["candidates"]}
        self.assertEqual(by_source["tail-a"]["health"], "fail")
        self.assertEqual(by_source["sub-a"]["health"], "controller_unreachable")
        self.assertEqual(report["verdict"]["code"], "controller_unreachable")
        self.assertEqual(report["selector_now"], None)

    def test_without_a_v3_policy_only_the_http_layers_run(self):
        e.put_source(self.store, 'tail-a', self.tail)
        report = d.build_report(self.directory, http_probe=self.fake_http(), tcp_probe=None,
                                delay_probe=lambda source, node: AssertionError("no candidates"),
                                selector_now=lambda value: None)
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["verdict"]["code"], "egress_healthy")


class EndpointTests(DiagnoseFixture):
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
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
        try:
            head = {'Content-Type': 'application/json', **(headers or {})}
            connection.request('POST', route, body=e.encode(body), headers=head)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def fixed_report(self):
        return {"schema_version": 1, "generated_at": 1.5,
                "probes": {name: probe(ms=42) for name, _ in d.HTTP_PROBES},
                "verdict": {"code": "egress_healthy", "hint_key": "egress_healthy"},
                "candidates": [], "selector_now": None}

    def test_diagnose_returns_battery_report_with_strict_empty_body(self):
        server = self.dashboard()
        report = self.fixed_report()
        with patch.object(d, 'build_report', return_value=report) as battery:
            status, body = self.request(server, '/api/egress/diagnose', {})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body), report)
        battery.assert_called_once_with(server.sources_dir)
        for payload in ({'node': 'nmd-sub-a-0123456789abcdef0123'}, {'x': 1},
                        {'url': 'https://evil.invalid/'}, {'action': 'enable'}):
            self.assertEqual(self.request(server, '/api/egress/diagnose', payload)[0], 400)
        for headers in ({'Origin': 'https://evil.invalid'}, {'Host': 'evil.invalid'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            self.assertEqual(self.request(server, '/api/egress/diagnose', {}, headers)[0], 403)

    def test_macos_rejects_before_running_any_probe_or_private_read(self):
        server = self.dashboard('macos')
        with patch.object(e.Store, 'load', side_effect=AssertionError('real private sources forbidden')), \
                patch.object(d, 'build_report', side_effect=AssertionError('battery must not run')):
            self.assertEqual(self.request(server, '/api/egress/diagnose', {})[0], 405)


if __name__ == "__main__":
    unittest.main()
