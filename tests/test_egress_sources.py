"""Only private temporary directories, synthetic providers and loopback controllers.

No real subscription, VPN, service manager, credentials or internet probe is used.
"""
import contextlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import egress_sources as e
import manager
import observability

FIXTURE = ROOT / "tests/fixtures/provider.yaml"
URL = "https://subscription.example.invalid/SYNTHETIC_PATH_SECRET?token=SYNTHETIC_URL_SECRET"
TAIL = {"kind": "tailnet", "server": "100.64.0.10", "port": 1080,
        "expected_egress_ip": "198.51.100.10"}


class SourceFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS /var and /tmp are symlinks; use the actual private temporary path.
        self.base = Path(self.temp.name).resolve()
        self.directory = self.base / "private-sources"
        self.store = e.Store(self.directory)
        self.addCleanup(patch.stopall)
        # A missed mock must fail instead of reaching real services/subscriptions.
        patch.object(e, "fetch_subscription", side_effect=AssertionError("real subscription forbidden")).start()

    def populate(self):
        e.put_source(self.store, "tail-a", TAIL)
        e.put_source(self.store, "tail-b", dict(TAIL, server="100.64.0.11", expected_egress_ip="198.51.100.11"))
        e.put_source(self.store, "sub-a", {"kind": "subscription", "url": URL})
        e.refresh(self.store, "sub-a", FIXTURE)
        return self.store.load()

    def node(self, source):
        return self.store.load()["cache"][source]["nodes"][0]["name"]

    def render(self):
        stage = self.base / "runtime"
        stage.mkdir(mode=0o700, exist_ok=True)
        e.render_runtime(self.directory, ROOT / "config.yaml", stage / "config.yaml")
        return json.loads((stage / "config.yaml").read_bytes()), stage


class RegistryTests(SourceFixture):
    def test_add_update_remove_and_private_atomic_storage(self):
        e.put_source(self.store, "tail-a", TAIL)
        first = self.node("tail-a")
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(e.SourceError, "already_exists"):
            e.put_source(self.store, "tail-a", TAIL)
        e.put_source(self.store, "tail-a", dict(TAIL, port=1081), replace=True)
        self.assertNotEqual(first, self.node("tail-a"))
        with contextlib.redirect_stdout(io.StringIO()):
            e.main(["remove", "tail-a"], directory=self.directory)
        self.assertEqual(self.store.load()["sources"], {})
        self.assertEqual(e.public_status(self.directory, False)["mode"], "sources")

    def test_uninitialized_view_is_read_only(self):
        with patch.object(e.Controller, "request", side_effect=AssertionError("no controller")):
            view = e.public_status(self.directory)
        self.assertEqual(view["mode"], "legacy")
        self.assertFalse(self.directory.exists())

    def test_invalid_definitions_never_write(self):
        definitions = [dict(TAIL, server="192.0.2.1"), dict(TAIL, port=True), dict(TAIL, port=65536),
                       dict(TAIL, extra="field"), dict(TAIL, expected_egress_ip="bad"),
                       {"kind": "subscription", "url": "http://example.invalid/token"},
                       {"kind": "subscription", "url": "https://user:pass@example.invalid/path"},
                       {"kind": "subscription", "url": "https://example.invalid/#secret"},
                       {"kind": "subscription", "url": "https://example.invalid/\r\nsecret"}]
        for definition in definitions:
            with self.subTest(definition=definition), self.assertRaises(e.SourceError):
                e.put_source(self.store, "tail-a", definition)
        self.assertFalse(self.directory.exists())

    def test_anytls_subscription_nodes_keep_protocol_fields(self):
        e.put_source(self.store, "sub-any", {"kind": "subscription", "url": URL})
        provider = self.base / "anytls-provider.yaml"
        provider.write_text("proxies:\n"
                            "  - name: anytls-node\n"
                            "    type: anytls\n"
                            "    server: anytls.example.invalid\n"
                            "    port: 443\n"
                            "    password: SYNTHETIC_ANYTLS_PASSWORD\n"
                            "    udp: true\n"
                            "    sni: anytls.example.invalid\n"
                            "    skip-cert-verify: true\n"
                            "    client-fingerprint: chrome\n"
                            "    alpn: [h2, http/1.1]\n", encoding="utf-8")
        provider.chmod(0o600)
        e.refresh(self.store, "sub-any", provider)
        nodes = self.store.load()["cache"]["sub-any"]["nodes"]
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertTrue(node["name"].startswith("nmd-sub-any-"))
        for key, value in (("type", "anytls"), ("password", "SYNTHETIC_ANYTLS_PASSWORD"),
                           ("udp", True), ("skip-cert-verify", True),
                           ("client-fingerprint", "chrome"), ("alpn", ["h2", "http/1.1"])):
            self.assertEqual(node[key], value)

    def test_registry_permissions_links_and_checkout_are_rejected(self):
        e.put_source(self.store, "tail-a", TAIL)
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(e.SourceError, "unsafe_private_file"):
            self.store.load()
        self.store.path.chmod(0o600)
        alias = self.base / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(e.SourceError):
            e.Store(alias).load()
        hardlink = self.base / "link"
        os.link(self.store.path, hardlink)
        with self.assertRaises(e.SourceError):
            self.store.load()
        with self.assertRaises(e.SourceError):
            e.Store(ROOT / "private-sources").load()

    def test_failed_refresh_preserves_last_cache_and_selected_node(self):
        self.populate()
        name = self.node("sub-a")
        e.select(self.store, name, deferred=True)
        original = self.store.path.read_bytes()
        for payload in ("proxies: []", "proxies: [wrong]", "proxies: [", "proxies: []\nproxies: []",
                        "proxies: &nodes [a]\nother: *nodes", "!!python/object/apply:os.system ['bad']"):
            fixture = self.base / "bad.yaml"
            fixture.write_text(payload)
            with self.subTest(payload=payload), self.assertRaises(e.SourceError):
                e.refresh(self.store, "sub-a", fixture)
            self.assertEqual(original, self.store.path.read_bytes())
        changed = self.base / "changed.yaml"
        changed.write_text("proxies: [{name: new, type: socks5, server: 192.0.2.22, port: 1080}]")
        with self.assertRaisesRegex(e.SourceError, "selected_node_would_disappear"):
            e.refresh(self.store, "sub-a", changed)
        self.assertEqual(original, self.store.path.read_bytes())

    def test_selected_source_removal_requires_explicit_alternative(self):
        self.populate()
        e.select(self.store, self.node("tail-a"), deferred=True)
        with self.assertRaisesRegex(e.SourceError, "selected_source"):
            e.main(["remove", "tail-a"], directory=self.directory)
        e.select(self.store, self.node("tail-b"), deferred=True)
        with contextlib.redirect_stdout(io.StringIO()):
            e.main(["remove", "tail-a"], directory=self.directory)
        self.assertNotIn("tail-a", self.store.load()["sources"])

    def test_scope_path_uses_receipt_not_changed_xdg(self):
        root = self.base / "managed"
        (root / ".git").mkdir(parents=True)
        settings = {"home": str(root), "scope": "user", "configDir": str(self.base / "saved-config"),
                    "stateDir": str(self.base / "saved-state")}
        with patch.object(manager, "setting", side_effect=lambda _, key: settings.get(key, "")), patch.dict(os.environ, {"XDG_CONFIG_HOME": "/new/location"}):
            self.assertEqual(manager.source_directory(root), self.base / "saved-config/egress")
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.base / "user-config")}):
            self.assertEqual(manager.source_directory(self.base / "source"), self.base / "user-config/nmd/egress")
        self.assertEqual(manager.install_scope.paths("system")["config_dir"] / "egress", Path("/etc/nmd/egress"))

    def test_missing_yaml_dependency_has_precise_sanitized_error(self):
        with patch.dict(sys.modules, {"yaml": None}), self.assertRaisesRegex(e.SourceError, "PyYAML_6_0_3"):
            e.yaml_load(b"proxies: []")


class RenderTests(SourceFixture):
    def test_only_nodes_imported_and_only_tailnet_binds_tailscale(self):
        self.populate()
        selected = self.node("sub-a")
        e.select(self.store, selected, deferred=True)
        config, stage = self.render()
        original = e.yaml_load((ROOT / "config.yaml").read_bytes())
        for key in ("tun", "dns", "sniffer", "mode"):
            self.assertEqual(config[key], original[key])
        self.assertEqual(config["rules"][:-1], original["rules"][:-1])
        self.assertEqual(config["rules"][-1], "MATCH,NMD-EXIT")
        self.assertEqual(config["proxy-groups"], [{"name": e.GROUP, "type": "select", "use": ["nmd-sub-a", "nmd-tail-a", "nmd-tail-b"]}])
        self.assertFalse(config["profile"]["store-selected"])
        self.assertFalse(config["allow-lan"])
        all_names = []
        for provider, definition in config["proxy-providers"].items():
            self.assertEqual(definition["type"], "file")
            self.assertFalse(definition["health-check"]["enable"])
            self.assertNotIn("url", definition)
            self.assertNotIn("interval", definition)
            path = stage / definition["path"]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            nodes = json.loads(path.read_bytes())["proxies"]
            for node in nodes:
                all_names.append(node["name"])
                # Readable labels are private metadata, never deployed artifacts.
                self.assertNotIn("display", node)
                if provider.startswith("nmd-tail"):
                    self.assertEqual(node["interface-name"], "tailscale0")
                else:
                    self.assertFalse(set(node) & e.FORBIDDEN)
            if provider == "nmd-sub-a":
                self.assertEqual(nodes[0]["name"], selected)
                self.assertEqual(nodes[1]["ws-opts"]["headers"]["Host"], "tls.example.invalid")
        self.assertEqual(len(all_names), len(set(all_names)))
        self.assertNotIn(URL.encode(), b"".join(path.read_bytes() for path in stage.rglob("*") if path.is_file()))
        self.assertEqual(stat.S_IMODE((stage / "config.yaml").stat().st_mode), 0o600)
        for network in ("100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.0.0.0/8", "192.168.0.0/16", "223.5.5.5/32"):
            self.assertIn(network, config["tun"]["route-exclude-address"])

    def test_render_requires_explicit_selection_and_refresh(self):
        self.populate()
        with self.assertRaisesRegex(e.SourceError, "choose_cached"):
            self.render()
        e.select(self.store, self.node("tail-a"), deferred=True)
        e.put_source(self.store, "sub-b", {"kind": "subscription", "url": URL + "2"})
        with self.assertRaisesRegex(e.SourceError, "refresh_all"):
            self.render()

    def test_source_edit_invalidates_cached_selection(self):
        self.populate()
        e.select(self.store, self.node("tail-a"), deferred=True)
        e.put_source(self.store, "tail-a", dict(TAIL, port=1081), replace=True)
        with self.assertRaisesRegex(e.SourceError, "choose_cached"):
            self.render()

    def test_identical_names_across_sources_do_not_collide(self):
        self.populate()
        e.put_source(self.store, "sub-b", {"kind": "subscription", "url": URL})
        e.refresh(self.store, "sub-b", FIXTURE)
        names = list(e.inventory(self.store.load()))
        self.assertEqual(len(names), 6)
        self.assertEqual(len(set(names)), 6)

    def test_public_exports_are_allowlists_without_credentials_or_raw_names(self):
        value = self.populate()
        view = json.dumps(e.public_status(self.directory, False))
        for secret in (URL, "SYNTHETIC_PATH_SECRET", "SYNTHETIC_URL_SECRET", "SYNTHETIC_LABEL_SECRET",
                       "SYNTHETIC_PASSWORD", "SYNTHETIC_USER", value["controller"]["secret"], "192.0.2.20", "100.64.0.10"):
            self.assertNotIn(secret, view)
        self.assertIn("[redacted]", view)
        self.assertIn("not_tested", view)
        self.assertIn("no_tailnet_exit_node_rollback", view)

    def test_display_names_follow_import_but_keep_ids_and_exports_stable(self):
        first = self.populate()
        names = [node["name"] for node in first["cache"]["sub-a"]["nodes"]]
        displays = [node["display"] for node in first["cache"]["sub-a"]["nodes"]]
        self.assertEqual(displays, ["https://label.example.invalid/SYNTHETIC_LABEL_SECRET",
                                    "same-label-as-other-provider"])
        e.refresh(self.store, "sub-a", FIXTURE)
        again = self.store.load()["cache"]["sub-a"]["nodes"]
        # The digest excludes display: identical fixture must keep every node id.
        self.assertEqual(names, [node["name"] for node in again])
        self.assertEqual(displays, [node["display"] for node in again])
        self.assertNotIn("SYNTHETIC_LABEL_SECRET", json.dumps(e.public_status(self.directory, False)))
        self.assertIn("SYNTHETIC_LABEL_SECRET",
                      json.dumps(e.public_status(self.directory, False, include_display=True)))


class LocalControllerFixture(SourceFixture):
    def setUp(self):
        super().setUp()
        self.populate()
        test = self
        self.current = self.node("tail-a")
        self.requests = []
        self.response_code = 200
        self.change_after_read = False
        self.delay_requests = []
        self.delay_code = 200
        self.delay_ms = 87
        self.failing_nodes = set()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if "/healthcheck" in self.path:
                    test.delay_requests.append((self.path, self.headers.get("Authorization")))
                    node = unquote(self.path.split("?")[0].split("/")[4])
                    code = 504 if node in test.failing_nodes else test.delay_code
                    self.send_response(code)
                    self.end_headers()
                    self.wfile.write(e.encode({"delay": test.delay_ms, "message": "SYNTHETIC_DELAY_ERROR"}))
                    return
                test.requests.append(("GET", self.path, self.headers.get("Authorization")))
                self.send_response(test.response_code)
                if test.response_code == 302:
                    self.send_header("Location", "https://must-not-follow.example.invalid/secret")
                self.end_headers()
                self.wfile.write(e.encode({"now": test.current, "all": list(e.inventory(test.store.load())), "type": "Selector",
                                          "extra": "SYNTHETIC_CONTROLLER_SECRET", "alive": True}))
                if test.change_after_read:
                    test.current = test.node("tail-b")

            def do_PUT(self):
                test.requests.append(("PUT", self.path, self.headers.get("Authorization")))
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                test.current = value["name"]
                self.send_response(204)
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        with self.store.edit() as value:
            value["controller"]["url"] = "http://127.0.0.1:" + str(self.server.server_port)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


class ControllerTests(LocalControllerFixture):
    def test_uncertain_put_is_not_retried_or_reported_as_success(self):
        original = e.Controller.request
        def uncertain(client, method, body=None):
            if method == "PUT":
                original(client, method, body)
                raise e.SourceError("controller_unavailable")
            return original(client, method, body)
        with patch.object(e.Controller, "request", new=uncertain), self.assertRaisesRegex(e.SourceError, "outcome_unknown"):
            e.select(self.store, self.node("sub-a"))
        self.assertEqual(self.current, self.node("sub-a"))
        self.assertEqual([method for method, *_ in self.requests], ["GET", "PUT"])
        self.assertIsNone(self.store.load()["selected"])

    def test_live_manual_selection_is_authenticated_and_read_back(self):
        chosen = self.node("sub-a")
        e.select(self.store, chosen)
        self.assertEqual(self.current, chosen)
        self.assertEqual(self.store.load()["selected"], chosen)
        self.assertEqual([item[0] for item in self.requests], ["GET", "PUT", "GET"])
        for _, path, auth in self.requests:
            self.assertEqual(path, "/proxies/NMD-EXIT")
            self.assertEqual(auth, "Bearer " + self.store.load()["controller"]["secret"])
        view = e.public_status(self.directory)
        self.assertEqual(view["active"], chosen)
        self.assertNotIn("SYNTHETIC_CONTROLLER_SECRET", json.dumps(view))
        self.assertEqual(view["health_check"], "disabled")
        self.assertEqual(view["ai_business"], "not_tested")

    def test_deferred_selection_sends_no_controller_requests(self):
        e.select(self.store, self.node("sub-a"), deferred=True)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.current, self.node("tail-a"))

    def test_delay_test_probes_only_cached_nodes_with_fixed_url(self):
        chosen = self.node("sub-a")
        self.assertEqual(e.delay_test(self.directory, chosen), {"node": chosen, "delay_ms": 87})
        expected = ("/providers/proxies/nmd-sub-a/" + chosen
                    + "/healthcheck?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000")
        self.assertEqual([path for path, _ in self.delay_requests], [expected])
        self.assertEqual({auth for _, auth in self.delay_requests},
                         {"Bearer " + self.store.load()["controller"]["secret"]})
        with self.assertRaisesRegex(e.SourceError, "node_not_found"):
            e.delay_test(self.directory, "DIRECT")
        self.assertEqual(len(self.delay_requests), 1)
        self.delay_code = 504
        with self.assertRaisesRegex(e.SourceError, "delay_test_failed"):
            e.delay_test(self.directory, chosen)
        with self.assertRaisesRegex(e.SourceError, "invalid_delay_timeout"):
            e.Controller(self.store.load()).delay("nmd-sub-a", chosen, 0)
        self.assertEqual(len(self.delay_requests), 2)

    def test_unknown_nodes_and_non_loopback_controllers_are_rejected(self):
        with self.assertRaisesRegex(e.SourceError, "node_not_found"):
            e.select(self.store, "DIRECT")
        self.current = "https://bad.example.invalid/SYNTHETIC_UNKNOWN_SECRET"
        view = e.public_status(self.directory)
        self.assertIsNone(view["active"])
        self.assertNotIn("SYNTHETIC_UNKNOWN_SECRET", json.dumps(view))
        for url in ("http://localhost:9090", "http://0.0.0.0:9090", "http://192.0.2.20:9090", "https://127.0.0.1/", "http://127.0.0.1/path"):
            value = self.store.load()
            value["controller"]["url"] = url
            with self.subTest(url=url), self.assertRaises(e.SourceError):
                e.Controller(value)

    def test_controller_redirect_is_not_followed(self):
        self.response_code = 302
        with self.assertRaises(e.SourceError):
            e.current_node(self.store.load())
        self.assertEqual(len(self.requests), 1)

    def test_current_source_expected_ip_and_unpinned_subscription(self):
        before = self.current
        verified = e.verify_observed(self.directory, before, "198.51.100.10")
        self.assertEqual(verified["source"], "tail-a")
        with self.assertRaisesRegex(e.SourceError, "mismatch"):
            e.verify_observed(self.directory, before, "198.51.100.11")
        self.current = self.node("sub-a")
        result = e.verify_observed(self.directory, self.current, "203.0.113.40")
        self.assertEqual(result["result"], "https_observed_identity_unpinned")
        self.assertEqual(result["ai_business"], "not_tested")

    def test_selection_change_makes_probe_inconclusive(self):
        with self.assertRaisesRegex(e.SourceError, "selection_changed"):
            e.verify_observed(self.directory, self.node("tail-b"), "198.51.100.11")

    def test_verify_shell_uses_selector_instead_of_legacy_expected_ip(self):
        script = f'''
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
systemctl() {{ return 0; }}
tailscale_checks() {{ :; }}
curl() {{ case "$*" in *baidu*) echo 200;; *cloudflare*) echo ip=198.51.100.10;; esac; }}
timeout() {{ shift; "$@"; }}
getent() {{ echo 198.18.0.5; }}
verify
'''
        result = subprocess.run(["bash", "-c", script], env=dict(os.environ, NMD_SOURCES_DIR=str(self.directory),
                                NMD_LOCAL_ENV=str(self.base / "missing.env"), NMD_VPS_PUB="203.0.113.99"),
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified_expected_ip", result.stdout)
        self.assertNotIn("PASS VPS", result.stdout)
        self.assertEqual([item[0] for item in self.requests], ["GET", "GET"])


class AutoTests(LocalControllerFixture):
    def enable(self):
        return e.auto_configure(self.store, {"action": "enable",
                                             "nodes": [self.node("sub-a"), self.node("tail-a")]})

    def evaluate(self, runtime):
        events = []
        runtime = e.auto_evaluate(self.directory, runtime, lambda kind, detail: events.append((kind, detail)))
        return runtime, [kind for kind, _ in events]

    def test_enable_requires_explicit_pins_and_valid_parameters(self):
        with self.assertRaisesRegex(e.SourceError, "auto_legacy_payload_removed"):
            e.auto_configure(self.store, {"action": "enable", "primary": "subscription",
                                          "tailnet_node": self.node("tail-a")})
        for payload in ({"action": "enable", "nodes": [self.node("tail-a")]},
                        {"action": "enable", "nodes": [self.node("tail-a"), self.node("tail-a")]},
                        {"action": "enable", "nodes": [self.node("sub-a"), "missing"]},
                        {"action": "enable", "nodes": [self.node("sub-a"), self.node("tail-a")],
                         "fail_after": 1},
                        {"action": "enable", "nodes": [self.node("sub-a"), self.node("tail-a")],
                         "extra": True}):
            with self.subTest(payload=payload), self.assertRaises(e.SourceError):
                e.auto_configure(self.store, payload)
        # The candidate list is bounded: exactly two through eight ordered pins.
        chain = {"sources": {f"s{index}": {} for index in range(9)},
                 "auto": {"version": 3, "enabled": True, "paused": False,
                          "candidates": [{"source": f"s{index}", "node": f"nmd-s{index}-{index:020x}"}
                                         for index in range(9)], **e.AUTO_DEFAULTS}}
        with self.assertRaisesRegex(e.SourceError, "invalid_auto"):
            e.validate_auto(chain)
        self.assertEqual(e.validate_auto({**chain, "auto": {**chain["auto"],
                                                             "candidates": chain["auto"]["candidates"][:8]}}),
                         {**chain["auto"], "candidates": chain["auto"]["candidates"][:8]})
        self.assertEqual(self.enable()["result"], "auto_enabled")
        view = e.public_status(self.directory, online=False)
        self.assertEqual(view["selection_mode"], "auto")
        self.assertEqual(view["auto"]["candidates"],
                         [{"source": "sub-a", "node": self.node("sub-a")},
                          {"source": "tail-a", "node": self.node("tail-a")}])
        self.assertEqual(view["auto"]["fail_after"], 3)
        with self.assertRaisesRegex(e.SourceError, "auto_not_configured"):
            e.auto_configure(e.Store(self.base / "no-auto"), {"action": "disable"})
        original = self.store.path.read_bytes()
        with self.assertRaisesRegex(e.SourceError, "invalid_auto"):
            with self.store.edit() as value:
                value["auto"]["unexpected"] = True
        self.assertEqual(self.store.path.read_bytes(), original)

    def test_failover_hysteresis_recovery_and_cooldown(self):
        self.enable()
        primary = self.node("sub-a")
        runtime, events = self.evaluate({})
        self.assertEqual(events, ["auto_switch"])
        self.assertEqual((runtime["target"], self.current, self.store.load()["selected"]),
                         (0, primary, primary))
        self.failing_nodes = {primary}
        for _ in range(2):
            runtime, events = self.evaluate(runtime)
            self.assertEqual(events, [])
            self.assertEqual(runtime["target"], 0)
        runtime, events = self.evaluate(runtime)
        self.assertEqual(runtime["target"], 1)
        self.assertEqual(events, ["auto_switch"])
        self.assertEqual(self.store.load()["selected"], self.node("tail-a"))
        self.failing_nodes = set()
        runtime, events = self.evaluate(runtime)
        self.assertEqual(runtime["recover_count"], 1)
        self.assertEqual(runtime["target"], 1)
        runtime, events = self.evaluate(runtime)
        self.assertEqual(runtime["target"], 0)
        self.assertEqual(self.current, primary)
        self.assertEqual(self.store.load()["selected"], primary)

    def test_manual_choices_pause_and_missing_pins_suspend(self):
        self.enable()
        runtime, _ = self.evaluate({})
        e.select(self.store, self.node("tail-a"))
        self.assertTrue(self.store.load()["auto"]["paused"])
        self.assertEqual(e.public_status(self.directory, online=False)["selection_mode"], "manual")
        before = len(self.delay_requests)
        runtime, events = self.evaluate(runtime)
        self.assertEqual(events, [])
        self.assertEqual(len(self.delay_requests), before)
        e.auto_configure(self.store, {"action": "resume"})
        self.assertFalse(self.store.load()["auto"]["paused"])
        e.select(self.store, self.store.load()["cache"]["sub-a"]["nodes"][1]["name"])
        self.assertEqual(self.store.load()["auto"]["candidates"][0]["node"], self.node("sub-a"))
        self.assertTrue(self.store.load()["auto"]["paused"])
        e.auto_configure(self.store, {"action": "resume"})
        e.put_source(self.store, "tail-a", dict(TAIL, port=1081), replace=True)
        runtime, events = self.evaluate(runtime)
        self.assertIn("auto_suspended", events)
        self.assertTrue(runtime["suspended"])
        e.put_source(self.store, "tail-a", TAIL, replace=True)
        runtime, events = self.evaluate(runtime)
        self.assertIn("auto_resumed", events)
        self.assertFalse(runtime["suspended"])

    def test_busy_and_uncertain_switches_never_double_put(self):
        self.enable()
        primary = self.node("sub-a")
        runtime, _ = self.evaluate({})
        self.failing_nodes = {primary}
        runtime, _ = self.evaluate(runtime)
        runtime, _ = self.evaluate(runtime)
        puts_before = sum(1 for method, *_ in self.requests if method == "PUT")
        with patch.object(e, "select", side_effect=e.SourceError("source_operation_busy")):
            runtime, events = self.evaluate(runtime)
        self.assertEqual(events, [])
        self.assertEqual(runtime["target"], 0)
        with patch.object(e, "select", side_effect=e.SourceError(
                "selection_outcome_unknown_read_status_before_retry")):
            runtime, events = self.evaluate(runtime)
        self.assertEqual(events, ["auto_switch_failed"])
        self.assertEqual(runtime["pending_verify"], self.node("tail-a"))
        self.failing_nodes = set()
        self.current = self.node("tail-a")  # the uncertain PUT actually landed
        runtime, events = self.evaluate(runtime)
        self.assertEqual(events, ["auto_verify_adopted"])
        self.assertEqual(runtime["target"], 1)
        self.assertEqual(self.store.load()["selected"], self.node("tail-a"))
        self.assertIsNone(runtime["pending_verify"])
        self.assertEqual(sum(1 for method, *_ in self.requests if method == "PUT"), puts_before)
        for _ in range(10):
            runtime, _ = self.evaluate(runtime)
        self.assertEqual((self.current, runtime["target"], self.store.load()["selected"]),
                         (primary, 0, primary))
        self.assertEqual(sum(1 for method, *_ in self.requests if method == "PUT"), puts_before + 1)


class DashboardSourceTests(LocalControllerFixture):
    def start_dashboard(self):
        dashboard = observability.DashboardServer(0, self.base / "unused-state", self.directory)
        thread = threading.Thread(target=dashboard.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(dashboard.shutdown)
        self.addCleanup(dashboard.server_close)
        self.addCleanup(thread.join, 3)
        return dashboard

    def dashboard_request(self, dashboard, method="GET", path="/api/sources", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", dashboard.server_port, timeout=5)
        try:
            head = dict(headers or {})
            payload = None
            if body is not None:
                payload = e.encode(body)
                head["Content-Type"] = "application/json"
            conn.request(method, path, body=payload, headers=head)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_read_only_view_reuses_backend_and_rejects_writes_and_cross_origin(self):
        dashboard = self.start_dashboard()
        status, body = self.dashboard_request(dashboard)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["active"], self.current)
        for secret in (b"SYNTHETIC_URL_SECRET", b"SYNTHETIC_PASSWORD", b"SYNTHETIC_CONTROLLER_SECRET"):
            self.assertNotIn(secret, body)
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            self.assertEqual(self.dashboard_request(dashboard, method)[0], 405)
        for headers in ({"Host": "evil.invalid"}, {"Origin": "https://evil.invalid"}, {"Origin": "null"}):
            self.assertEqual(self.dashboard_request(dashboard, headers=headers)[0], 403)
        with patch.object(e, "public_status", side_effect=PermissionError("SYNTHETIC_PRIVATE_SECRET")):
            status, body = self.dashboard_request(dashboard)
            self.assertEqual(status, 503)
            self.assertNotIn(b"SYNTHETIC_PRIVATE_SECRET", body)
            self.assertIsNone(json.loads(body)["active"])
        self.assertFalse((self.base / "unused-state").exists())
        self.assertTrue(all(method == "GET" for method, *_ in self.requests))

    def test_write_endpoints_switch_test_and_configure_auto(self):
        dashboard = self.start_dashboard()
        chosen = self.node("sub-a")
        status, body = self.dashboard_request(dashboard, "POST", "/api/egress/select", {"node": chosen})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body), {"result": "selected_and_observed", "active": chosen})
        self.assertEqual(self.current, chosen)
        self.assertEqual(self.store.load()["selected"], chosen)
        status, body = self.dashboard_request(dashboard, "POST", "/api/egress/delay", {"node": chosen})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body), {"node": chosen, "delay_ms": 87})
        # Strict fixed-key bodies: a client-supplied url or free-form node is rejected.
        self.assertEqual(self.dashboard_request(dashboard, "POST", "/api/egress/delay",
                                                {"node": chosen, "url": "http://127.0.0.1:1/"})[0], 400)
        self.assertEqual(self.dashboard_request(dashboard, "POST", "/api/egress/select",
                                                {"node": "DIRECT"})[0], 400)
        status, body = self.dashboard_request(dashboard, "POST", "/api/auto",
                                              {"action": "enable",
                                               "nodes": [chosen, self.node("tail-a")]})
        self.assertEqual(status, 200, body)
        self.assertIn("auto_enabled", json.loads(body)["result"])
        view = json.loads(self.dashboard_request(dashboard)[1])
        self.assertEqual(view["selection_mode"], "auto")
        self.assertTrue(any(node.get("display") for node in view["nodes"]))
        self.assertEqual(self.dashboard_request(dashboard, "POST", "/api/auto",
                                                {"action": "disable"})[0], 200)
        self.assertEqual(json.loads(self.dashboard_request(dashboard)[1])["selection_mode"], "manual")
        for headers in ({"Host": "evil.invalid"}, {"Origin": "https://evil.invalid"}):
            self.assertEqual(self.dashboard_request(dashboard, "POST", "/api/egress/select",
                                                    {"node": chosen}, headers=headers)[0], 403)
        self.assertEqual(self.dashboard_request(dashboard, "PUT", "/api/egress/select")[0], 405)


class CLITests(SourceFixture):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts/manager.py"), "source", "--sources-dir", str(self.directory), *args],
                              env=dict(os.environ, NMD_LOCAL_ENV=str(self.base / "unused.env")), capture_output=True, text=True, timeout=10)

    def test_cli_workflow_needs_no_install_or_service(self):
        definition = self.base / "input.json"
        definition.write_bytes(e.encode(TAIL))
        definition.chmod(0o600)
        self.assertEqual(self.invoke("add", "tail-a", "--file", str(definition)).returncode, 0)
        nodes = json.loads(self.invoke("nodes").stdout)["nodes"]
        self.assertEqual(len(nodes), 1)
        self.assertEqual(self.invoke("select", nodes[0]["id"], "--defer").returncode, 0)
        status = self.invoke("status", "--offline")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)["desired"], nodes[0]["id"])
        self.assertEqual(self.invoke("select", nodes[0]["id"]).returncode, 1)

    def test_nodes_cli_shows_display_but_export_stays_shareable(self):
        self.populate()
        nodes = json.loads(self.invoke("nodes").stdout)["nodes"]
        self.assertTrue(nodes and all(node["display"] for node in nodes))
        self.assertNotIn("SYNTHETIC_LABEL_SECRET", self.invoke("export").stdout)

    def test_delay_cli_without_controller_reports_sanitized_failure(self):
        self.populate()
        nodes = json.loads(self.invoke("nodes").stdout)["nodes"]
        result = self.invoke("delay", nodes[0]["id"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("delay_test_failed", result.stderr)

    def test_auto_cli_configure_and_status(self):
        self.populate()
        nodes = json.loads(self.invoke("nodes").stdout)["nodes"]
        tail = next(node["id"] for node in nodes if node["source"] == "tail-a")
        subscription = next(node["id"] for node in nodes if node["source"] == "sub-a")
        # Legacy primary/secondary flags are gone: argparse rejects them without echoing values.
        legacy = self.invoke("auto", "enable", "--primary", "subscription")
        self.assertEqual(legacy.returncode, 1)
        self.assertIn("invalid_arguments_use_source_help", legacy.stderr)
        enabled = self.invoke("auto", "enable", "--node", subscription, "--node", tail)
        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        self.assertIn("auto_enabled", enabled.stdout)
        status = json.loads(self.invoke("auto", "status").stdout)
        self.assertEqual(status["selection_mode"], "auto")
        self.assertEqual(status["auto"]["candidates"][0], {"source": "sub-a", "node": subscription})
        self.assertEqual(status["auto"]["candidates"][1], {"source": "tail-a", "node": tail})
        self.assertEqual(status["auto"]["version"], 3)
        replaced = self.invoke("auto", "set-candidates", "--nodes", f"{tail},{subscription}")
        self.assertEqual(replaced.returncode, 0, replaced.stderr)
        self.assertIn("auto_candidates_updated", replaced.stdout)
        self.assertIn("auto_disabled", self.invoke("auto", "disable").stdout)

    def test_bad_json_and_arguments_never_echo_secrets(self):
        definition = self.base / "input.json"
        definition.write_text('{"url":"' + URL + '", BROKEN')
        definition.chmod(0o600)
        for args in (("add", "sub-a", "--file", str(definition)), ("add", URL), ("refresh", "sub-a", "--url", URL)):
            result = self.invoke(*args)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("SYNTHETIC", result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_source_checkout_accepts_split_and_equals_directory_options(self):
        self.populate()
        self.assertEqual(self.invoke("list").returncode, 0)
        result = subprocess.run([sys.executable, str(ROOT / "scripts/manager.py"), "source",
                                 "--sources-dir=" + str(self.directory), "list"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["sources"]), 3)

    def test_source_checkout_rejects_abbreviated_options(self):
        self.populate()
        for prefix in ("--sources-d", "--sources"):
            for option in ([prefix, str(self.directory)], [prefix + "=" + str(self.directory)]):
                with self.subTest(option=option):
                    result = subprocess.run([sys.executable, str(ROOT / "scripts/manager.py"), "source", *option, "list"],
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 1)
        result = self.invoke("status", "--off")
        self.assertEqual(result.returncode, 1)

    def test_legacy_exit_node_actions_blocked_before_sudo_in_source_mode(self):
        self.populate()
        for command in ("cutover", "rollback"):
            result = subprocess.run(["bash", str(ROOT / "local-setup.sh"), command, "--sources-dir", str(self.directory)],
                                    env=dict(os.environ, NMD_LOCAL_ENV=str(self.base / "missing.env")), capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("多来源模式", result.stderr)


class InstalledCLITests(SourceFixture):
    """Real manager/argparse entrypoint, with a temp-only installation receipt."""
    def setUp(self):
        super().setUp()
        self.checkout = self.base / "installed-code"
        (self.checkout / "scripts").mkdir(parents=True)
        for name in ("manager.py", "install_scope.py", "egress_sources.py", "nmd_platform.py"):
            shutil.copy2(ROOT / "scripts" / name, self.checkout / "scripts" / name)
        subprocess.run(["git", "init", "--quiet", str(self.checkout)], check=True, capture_output=True)
        self.saved_config = self.base / "recorded-config"
        self.saved_config.mkdir(mode=0o700)
        for key, value in (("home", self.checkout), ("scope", "user"), ("configDir", self.saved_config),
                           ("stateDir", self.base / "recorded-state")):
            manager.setting(self.checkout, key, value)
        e.put_source(e.Store(self.saved_config / "egress"), "recorded", TAIL)
        e.put_source(self.store, "outside", TAIL)

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(self.checkout / "scripts/manager.py"), "source", *args],
                              env=dict(os.environ, HOME=str(self.base), XDG_CONFIG_HOME=str(self.base / "changed-xdg")),
                              capture_output=True, text=True, timeout=5)

    def test_installed_default_uses_recorded_scope_directory(self):
        result = self.invoke("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([source["id"] for source in json.loads(result.stdout)["sources"]], ["recorded"])

    def test_installed_scope_rejects_all_directory_option_spellings(self):
        original = self.store.path.read_bytes()
        for name in ("--sources-dir", "--sources-d", "--sources"):
            for option in ([name, str(self.directory)], [name + "=" + str(self.directory)]):
                with self.subTest(option=option):
                    result = self.invoke(*option, "list")
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn(str(self.directory), result.stdout + result.stderr)
                    self.assertEqual(self.store.path.read_bytes(), original)

    def test_installed_scope_cannot_redirect_a_mutating_command(self):
        definition = self.base / "definition.json"
        definition.write_bytes(e.encode(TAIL))
        definition.chmod(0o600)
        original = self.store.path.read_bytes()
        result = self.invoke("--sources-dir=" + str(self.directory), "add", "hijacked", "--file", str(definition))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.store.path.read_bytes(), original)
        self.assertNotIn("hijacked", e.Store(self.saved_config / "egress").load()["sources"])


class DeploymentTests(SourceFixture):
    def test_private_capture_creation_failure_never_runs_core(self):
        self.populate()
        script = f'''
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
mktemp() {{ return 17; }}
fake_core() {{ echo CORE-MUST-NOT-RUN; }}
MIHOMO=fake_core
if check_installed; then exit 99; else exit 1; fi
'''
        result = subprocess.run(["bash", "-c", script],
                                env=dict(os.environ, NMD_SOURCES_DIR=str(self.directory),
                                         NMD_LOCAL_ENV=str(self.base / "absent.env")),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("CORE-MUST-NOT-RUN", result.stdout + result.stderr)

    def test_installed_validation_uses_private_capture_and_ignores_existing_artifacts(self):
        self.populate()
        for previous in ("absent", "wide", "symlink"):
            for core_status in (0, 1):
                with self.subTest(previous=previous, core_status=core_status):
                    installed = self.base / ("installed-" + previous + str(core_status))
                    installed.mkdir(mode=0o755)
                    installed.chmod(0o755)
                    log = installed / ".nmd-validation.log"
                    victim = installed / "unrelated-file"
                    if previous == "wide":
                        log.write_text("old user artifact")
                        log.chmod(0o644)
                    elif previous == "symlink":
                        victim.write_text("untouched user artifact")
                        log.symlink_to(victim)
                    capture = installed / "observer.json"
                    core = installed / "fake-core"
                    core.write_text(f'''#!{sys.executable}
import json, os, stat, sys
from pathlib import Path
Path({str(capture)!r}).write_text(json.dumps({{"mode": stat.S_IMODE(os.fstat(1).st_mode)}}))
print("SYNTHETIC_VALIDATION_SECRET")
sys.exit({core_status})
''')
                    core.chmod(0o700)
                    private_temp = self.base / ("validation-temp-" + previous + str(core_status))
                    private_temp.mkdir(mode=0o700)
                    script = f'''
umask 022
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
MIHOMO={shlex.quote(str(core))}
CONFIG_DIR={shlex.quote(str(installed))}
check_installed
'''
                    result = subprocess.run(["bash", "-c", script],
                                            env=dict(os.environ, TMPDIR=str(private_temp), NMD_SOURCES_DIR=str(self.directory),
                                                     NMD_LOCAL_ENV=str(self.base / "absent.env")),
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, core_status, result.stderr)
                    self.assertNotIn("SYNTHETIC_VALIDATION_SECRET", result.stdout + result.stderr)
                    self.assertEqual(json.loads(capture.read_text())["mode"], 0o600)
                    if previous == "absent":
                        self.assertFalse(log.exists())
                    elif previous == "wide":
                        self.assertEqual(log.read_text(), "old user artifact")
                    else:
                        self.assertTrue(log.is_symlink())
                        self.assertEqual(victim.read_text(), "untouched user artifact")
                    self.assertEqual(list(private_temp.iterdir()), [])

    def deploy(self, reject=False):
        self.populate()
        e.select(self.store, self.node("tail-a"), deferred=True)
        source = self.base / "fixture-code"
        (source / "scripts").mkdir(parents=True)
        (source / "systemd").mkdir()
        for name in ("config.yaml", "scripts/egress_sources.py", "systemd/mihomo-override.conf", "systemd/mihomo-tailscale.conf"):
            shutil.copy2(ROOT / name, source / name)
        for name in ("geoip.metadb", "GeoSite.dat"):
            (source / name).write_text("synthetic asset")
        core = self.base / "fake-core"
        core.write_text("#!/bin/sh\necho SYNTHETIC_VALIDATION_SECRET\nexit " + ("1" if reject else "0") + "\n")
        core.chmod(0o700)
        config = self.base / "installed"
        config.mkdir(mode=0o700)
        (config / "config.yaml").write_text("old-config")
        (config / "config.yaml").chmod(0o600)
        events = self.base / "events"
        script = f'''
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
SETUP_DIR={shlex.quote(str(source))}
MIHOMO={shlex.quote(str(core))}
CONFIG_DIR={shlex.quote(str(config))}
SYSTEMD_DIR={shlex.quote(str(self.base / 'systemd'))}
RESOLVED_DIR={shlex.quote(str(self.base / 'resolved'))}
systemctl() {{ echo "$*" >> {shlex.quote(str(events))}; }}
deploy_files
'''
        result = subprocess.run(["bash", "-c", script], env=dict(os.environ, NMD_SOURCES_DIR=str(self.directory),
                                NMD_LOCAL_ENV=str(self.base / "absent.env")), capture_output=True, text=True, timeout=10)
        return result, config, events

    def test_validated_staging_deploys_private_provider_files_without_activation(self):
        result, config, events = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SYNTHETIC_VALIDATION_SECRET", result.stdout + result.stderr)
        value = json.loads((config / "config.yaml").read_bytes())
        self.assertEqual((config / "config.yaml.previous").read_text(), "old-config")
        for relative in ("config.yaml", "config.yaml.previous", *(provider["path"] for provider in value["proxy-providers"].values())):
            self.assertEqual(stat.S_IMODE((config / relative).stat().st_mode), 0o600)
        self.assertEqual(events.read_text(), "daemon-reload\n")

    def test_rejected_runtime_never_replaces_old_config_or_emits_core_error(self):
        result, config, events = self.deploy(reject=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual((config / "config.yaml").read_text(), "old-config")
        self.assertFalse(events.exists())
        self.assertFalse((config / "config.yaml.previous").exists())
        self.assertNotIn("SYNTHETIC_VALIDATION_SECRET", result.stdout + result.stderr)


class SubscriptionTransportTests(unittest.TestCase):
    def test_https_transport_does_not_follow_redirect_or_expose_url(self):
        for status in (302, 401, 500):
            connection = Mock()
            connection.getresponse.return_value.status = status
            with patch.object(e.http.client, "HTTPSConnection", return_value=connection), self.assertRaises(e.SourceError) as error:
                e.fetch_subscription(URL)
            self.assertNotIn("SYNTHETIC", str(error.exception))
            self.assertEqual(connection.request.call_count, 1)
            connection.close.assert_called_once()

    def test_bounded_payload_and_sanitized_transport_error(self):
        connection = Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read1.return_value = b"x" * 65536
        with patch.object(e.http.client, "HTTPSConnection", return_value=connection), self.assertRaisesRegex(e.SourceError, "too_large"):
            e.fetch_subscription(URL)
        connection.request.side_effect = OSError(URL)
        with patch.object(e.http.client, "HTTPSConnection", return_value=connection), self.assertRaises(e.SourceError) as error:
            e.fetch_subscription(URL)
        self.assertNotIn("SYNTHETIC", str(error.exception))


if __name__ == "__main__":
    unittest.main()
