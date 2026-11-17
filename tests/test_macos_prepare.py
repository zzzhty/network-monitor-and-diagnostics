"""Phase A of the self-managed mihomo macOS route: offline, never mutates.

Config generation is pure and byte-deterministic; the snapshot runs only
read-only commands against injected fixtures, so the macOS CI runner never
observes the host or dials anything.
"""
import contextlib
from io import BytesIO
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import macos_coexist
import macos_prepare as mod
import macos_readonly
import nmd_platform

PROFILE = json.loads((ROOT / "examples/macos-mihomo-coexist.experiment.json").read_text(encoding="utf-8"))
GOLDEN = ROOT / "examples/macos-mihomo-takeover.example.yaml"
INPUTS_EXAMPLE = ROOT / "examples/macos-mihomo-takeover.inputs.example.json"
REAL_INPUTS = {"proxy_name": "edge", "server": "fd7a:115c:a1e0::abcd", "port": 1081}
TAILSCALE = "/usr/local/bin/tailscale"

STATUS_JSON = json.dumps({
    "BackendState": "Running", "Self": {"Online": True, "HostName": "hidden-host"},
    "Peer": {"p1": {"Online": True}},
})
PREFS_JSON = json.dumps({
    "ExitNodeID": "nodekey:abc123", "ExitNodeIP": None, "CorpDNS": True,
    "RouteAll": False, "ExitNodeAllowLANAccess": False, "WantRunning": True,
    "Hostname": "hidden-host",
})
SCUTIL_DNS = (
    "DNS configuration\n\n"
    "resolver #1\n"
    "  search domain[0] : home\n"
    "  nameserver[0]     : 100.100.100.100\n"
    "  if_index         : 14 (utun7)\n"
    "resolver #2\n"
    "  nameserver[0]     : 198.18.0.2\n"
)
SCUTIL_PROXY = (
    "<dictionary> {\n"
    "  HTTPEnable : 0\n  HTTPProxy : 127.0.0.1\n  HTTPPort : 7897\n"
    "  HTTPSEnable : 0\n"
    "  SOCKSEnable : 1\n  SOCKSProxy : 127.0.0.1\n  SOCKSPort : 7897\n"
    "  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n}\n"
)
NETSTAT4 = (
    "Routing tables\n\nInternet:\n"
    "Destination        Gateway           Flags           Netif Expire\n"
    "default            192.0.2.1         UGScg             en0\n"
    "100.64/10          link#14           UCS             utun7\n"
)
NETSTAT6 = (
    "Routing tables\n\nInternet6:\n"
    "Destination        Gateway           Flags           Netif Expire\n"
    "default            fe80::%en0        UGCIg             en0\n"
)
PS_TEXT = (
    "  123 /Applications/Tailscale.app/Contents/MacOS/Tailscale\n"
    "  456 /usr/local/bin/mihomo\n"
    "  789 /usr/sbin/syslogd\n"
)
SERVICES_TEXT = (
    "An asterisk (*) denotes that a network service is disabled.\n"
    "Wi-Fi\nThunderbolt Ethernet\n*Bluetooth PAN\n"
)


def fixtures(dns_text=SCUTIL_DNS, prefs_text=PREFS_JSON):
    return {
        ("/usr/sbin/netstat", "-rn", "-f", "inet"): (0, NETSTAT4, None),
        ("/usr/sbin/netstat", "-rn", "-f", "inet6"): (0, NETSTAT6, None),
        ("/usr/sbin/scutil", "--dns"): (0, dns_text, None),
        ("/usr/sbin/scutil", "--proxy"): (0, SCUTIL_PROXY, None),
        ("/bin/ps", "-axo", "pid=,comm="): (0, PS_TEXT, None),
        ("/usr/sbin/networksetup", "-listallnetworkservices"): (0, SERVICES_TEXT, None),
        ("/usr/sbin/networksetup", "-getdnsservers", "Wi-Fi"):
            (0, "There aren't any DNS Servers set on Wi-Fi. DNS servers set to Automatic.\n", None),
        ("/usr/sbin/networksetup", "-getdnsservers", "Thunderbolt Ethernet"): (0, "192.0.2.53\n", None),
        (TAILSCALE, "status", "--json"): (0, STATUS_JSON, None),
        (TAILSCALE, "debug", "prefs"): (0, prefs_text, None),
    }


def fake_runner(table):
    def runner(argv, timeout):
        return table[tuple(argv)]
    return runner


class ConfigGoldenTests(unittest.TestCase):
    def test_render_matches_the_committed_example_byte_for_byte(self):
        text = mod.render_config(PROFILE, mod.PLACEHOLDER_INPUTS)
        self.assertEqual(text, GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(text, mod.render_config(PROFILE, mod.PLACEHOLDER_INPUTS))

    def test_example_inputs_are_exactly_the_placeholders(self):
        loaded = json.loads(INPUTS_EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(mod.validate_inputs(loaded), mod.PLACEHOLDER_INPUTS)

    def test_example_yaml_server_is_only_the_documentation_placeholder(self):
        text = GOLDEN.read_text(encoding="utf-8")
        servers = re.findall(r"^\s+server: (\S+)$", text, re.MULTILINE)
        self.assertEqual(servers, [macos_coexist.PLACEHOLDER_SOCKS_HOST])


class ConfigStructureTests(unittest.TestCase):
    def setUp(self):
        inputs = mod.validate_inputs(mod.PLACEHOLDER_INPUTS)
        self.document = mod.build_mihomo_document(PROFILE, inputs)
        self.group = PROFILE["egress"]["group"]

    def test_document_passes_every_validator(self):
        self.assertTrue(macos_coexist.mihomo_would_load(self.document))
        self.assertEqual(macos_coexist.validate_rule_order(self.document["rules"], self.group), [])
        self.assertEqual(mod.validate_document(self.document, self.group), [])

    def test_rule_placement(self):
        rules = self.document["rules"]
        suffix_lines = [f"DOMAIN-SUFFIX,{s},{self.group}" for s in macos_coexist.OVERSEAS_DOMAIN_SUFFIXES]
        self.assertEqual(rules[:4], [
            "DOMAIN-SUFFIX,tailscale.com,DIRECT",
            "DOMAIN-SUFFIX,tailscale.io,DIRECT",
            "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
            "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve",
        ])
        geosite = rules.index("GEOSITE,cn,DIRECT")
        for line in suffix_lines:
            self.assertLess(rules.index(line), geosite)
        self.assertEqual(rules[-1], f"MATCH,{self.group}")

    def test_tun_has_no_linux_only_or_pinned_fields(self):
        tun = self.document["tun"]
        for key in ("device", "iproute2-table-index", "iproute2-rule-index"):
            self.assertNotIn(key, tun)
        self.assertEqual(tun["route-exclude-address"], list(macos_coexist.TAILNET_ROUTE_EXCLUSIONS))
        self.assertEqual(tun["dns-mode"], PROFILE["dns_mode"]["selected"])
        self.assertEqual(macos_coexist.find_hardcoded_utun(self.document), [])

    def test_proxy_and_group_constraints(self):
        proxy = self.document["proxies"][0]
        self.assertEqual(proxy["type"], "socks5")
        self.assertTrue(proxy["udp"])
        self.assertNotIn("interface-name", proxy)
        group = self.document["proxy-groups"][0]
        self.assertEqual(group["name"], self.group)
        self.assertEqual(group["proxies"], [proxy["name"]])

    def test_nameserver_policy_does_not_bind_an_interface(self):
        for value in self.document["dns"]["nameserver-policy"].values():
            self.assertNotIn("#", value)

    def test_real_inputs_reach_the_document(self):
        text = mod.render_config(PROFILE, REAL_INPUTS)
        self.assertIn("fd7a:115c:a1e0::abcd", text)
        self.assertIn("name: edge", text)


class ConfigNegativeTests(unittest.TestCase):
    def test_inputs_reject_non_tailnet_or_malformed_servers(self):
        for server in ("8.8.8.8", "203.0.113.21", "vps.example.com", "", None, 123):
            with self.subTest(server=server):
                with self.assertRaises(ValueError):
                    mod.validate_inputs({"server": server, "port": 1081})

    def test_inputs_reject_bad_ports_and_keys(self):
        base = {"server": "100.64.0.8"}
        for port in (22, 0, -1, 65536, True, "1081", 1.5, None):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    mod.validate_inputs(dict(base, port=port))
        for value in ({"server": "100.64.0.8"}, {"port": 1081},
                      {"server": "100.64.0.8", "port": 1081, "extra": 1},
                      {"proxy_name": "DIRECT", "server": "100.64.0.8", "port": 1081},
                      {"proxy_name": "bad name", "server": "100.64.0.8", "port": 1081}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    mod.validate_inputs(value)

    def test_placeholder_pairing_and_real_standard_port(self):
        # The placeholder server pins the example pair; a real tailnet server
        # may use any valid port, including the standard SOCKS 1080.
        with self.assertRaisesRegex(ValueError, "placeholder_server_requires"):
            mod.validate_inputs({"server": macos_coexist.PLACEHOLDER_SOCKS_HOST, "port": 1081})
        self.assertEqual(
            mod.validate_inputs({"server": "100.64.0.8",
                                 "port": macos_coexist.PLACEHOLDER_SOCKS_PORT}),
            {"proxy_name": "VPS", "server": "100.64.0.8",
             "port": macos_coexist.PLACEHOLDER_SOCKS_PORT})

    def test_invalid_profile_is_rejected_before_any_document(self):
        broken = json.loads(json.dumps(PROFILE))
        broken["egress"]["tailscale_exit_node"] = True
        with self.assertRaisesRegex(ValueError, "invalid_experiment_profile"):
            mod.render_config(broken, mod.PLACEHOLDER_INPUTS)

    def test_write_refuses_the_repository_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            with self.assertRaisesRegex(ValueError, "output_inside_repository"):
                mod.write_config("x: 1\n", repo / "out.yaml", repo_root=repo)

    def test_write_outside_creates_private_files_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "dir" / "config.yaml"
            path = mod.write_config("x: 1\n", out, repo_root=Path(tmp) / "repo")
            self.assertEqual(path, out.resolve())
            self.assertEqual(out.read_text(encoding="utf-8"), "x: 1\n")
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(out.parent.stat().st_mode), 0o700)
            self.assertEqual(sorted(p.name for p in out.parent.iterdir()), ["config.yaml"])


class EmitterTests(unittest.TestCase):
    def test_scalar_quoting_rules(self):
        self.assertEqual(mod._scalar("any:53"), "any:53")
        self.assertEqual(mod._scalar("mode"), "mode")
        self.assertEqual(mod._scalar("+.ts.net"), "'+.ts.net'")
        self.assertEqual(mod._scalar("localhost.*"), "'localhost.*'")
        self.assertEqual(mod._scalar("true"), "'true'")
        self.assertEqual(mod._scalar("it's"), "'it''s'")
        self.assertEqual(mod._scalar(True), "true")
        self.assertEqual(mod._scalar(72), "72")

    def test_unsupported_types_are_refused(self):
        with self.assertRaises(ValueError):
            mod.dump_yaml({"ratio": 1.5})
        with self.assertRaises(ValueError):
            mod.dump_yaml({"nested": None})


class SnapshotTests(unittest.TestCase):
    def build(self, table=None, **kwargs):
        return mod.build_snapshot(
            "macos", runner=fake_runner(table or fixtures()),
            exists=lambda path: path == TAILSCALE, **kwargs)

    def test_command_sequence_is_fixed_and_read_only(self):
        snapshot = self.build()
        self.assertEqual(snapshot["commands"], [
            ["/usr/sbin/netstat", "-rn", "-f", "inet"],
            ["/usr/sbin/netstat", "-rn", "-f", "inet6"],
            ["/usr/sbin/scutil", "--dns"],
            ["/usr/sbin/scutil", "--proxy"],
            ["/bin/ps", "-axo", "pid=,comm="],
            ["/usr/sbin/networksetup", "-listallnetworkservices"],
            ["/usr/sbin/networksetup", "-getdnsservers", "Wi-Fi"],
            ["/usr/sbin/networksetup", "-getdnsservers", "Thunderbolt Ethernet"],
            [TAILSCALE, "status", "--json"],
            [TAILSCALE, "debug", "prefs"],
        ])
        for argv in snapshot["commands"]:
            self.assertNotIn("sudo", argv)
            self.assertNotIn("set", argv[1:2])

    def test_prefs_whitelist_keeps_values_and_drops_identity(self):
        prefs = self.build()["tailscale"]["prefs"]
        self.assertEqual(prefs["status"], "observed")
        self.assertEqual(prefs["ExitNodeID"], "nodekey:abc123")
        self.assertTrue(prefs["CorpDNS"])
        self.assertNotIn("Hostname", prefs)

    def test_dns_parser_keeps_resolvers_and_flags_fake_ip_range(self):
        snapshot = self.build()
        resolvers = snapshot["dns"]["resolvers"]
        self.assertEqual(resolvers[0]["nameservers"], ["100.100.100.100"])
        self.assertEqual(resolvers[0]["scope"], "scoped")
        self.assertEqual(resolvers[1]["nameservers"], ["198.18.0.2"])
        self.assertTrue(snapshot["dns"]["has_198_18"])
        self.assertFalse(snapshot["takeover_ready"]["scutil_has_no_198_18"])
        clean = self.build(fixtures(dns_text="resolver #1\n  nameserver[0]     : 100.100.100.100\n"))
        self.assertFalse(clean["dns"]["has_198_18"])
        self.assertTrue(clean["takeover_ready"]["scutil_has_no_198_18"])

    def test_proxy_parser_keeps_saved_values_and_bypass(self):
        proxy = self.build()["proxy"]
        self.assertEqual(proxy["protocols"]["HTTP"]["server"], "127.0.0.1")
        self.assertEqual(proxy["protocols"]["HTTP"]["port"], 7897)
        self.assertFalse(proxy["protocols"]["HTTP"]["enabled"])
        self.assertTrue(proxy["protocols"]["SOCKS"]["enabled"])
        self.assertEqual(proxy["bypass"], ["*.local", "169.254/16"])

    def test_routes_and_processes(self):
        snapshot = self.build()
        default = snapshot["routes"]["inet"]["default"]
        self.assertEqual(default, [{"family": 4, "interface": "en0", "gateway": "192.0.2.1"}])
        self.assertEqual(snapshot["routes"]["inet"]["tailnet"], {"interface": "utun7", "status": "observed"})
        self.assertEqual(snapshot["processes"]["mihomo"], [{"pid": 456, "comm": "mihomo"}])
        self.assertFalse(snapshot["takeover_ready"]["mihomo_absent"])
        self.assertNotIn("ps_unavailable", snapshot["takeover_ready"]["notes"])
        self.assertTrue(mod.summarize_snapshot(snapshot)["mihomo_running"])
        self.assertTrue(snapshot["takeover_ready"]["exit_node_selected"])

    def test_observed_empty_ps_means_mihomo_is_absent(self):
        table = fixtures()
        table[("/bin/ps", "-axo", "pid=,comm=")] = (0, "  1 /sbin/launchd\n", None)
        snapshot = self.build(table)
        self.assertEqual(snapshot["processes"]["mihomo"], [])
        self.assertTrue(snapshot["takeover_ready"]["mihomo_absent"])
        self.assertNotIn("ps_unavailable", snapshot["takeover_ready"]["notes"])
        self.assertFalse(mod.summarize_snapshot(snapshot)["mihomo_running"])

    def test_failed_ps_is_unknown_and_not_a_ready_signal(self):
        table = fixtures()
        table[("/bin/ps", "-axo", "pid=,comm=")] = (None, "", "output_too_large")
        snapshot = self.build(table)
        ready = snapshot["takeover_ready"]
        self.assertIsNone(ready["mihomo_absent"])
        self.assertIn("ps_unavailable", ready["notes"])
        self.assertEqual(snapshot["processes"]["mihomo"], [])
        self.assertIsNone(mod.summarize_snapshot(snapshot)["mihomo_running"])
        self.assertIsNot(ready["mihomo_absent"], True)

    def test_services_wire_first_starred_skipped_automatic_empty(self):
        services = self.build()["dns"]["services"]
        self.assertEqual([row["service"] for row in services], ["Wi-Fi", "Thunderbolt Ethernet"])
        self.assertEqual(services[0]["dnsservers"], [])
        self.assertEqual(services[1]["dnsservers"], ["192.0.2.53"])

    def test_invalid_prefs_json_is_unavailable_and_noted(self):
        snapshot = self.build(fixtures(prefs_text="{not json"))
        self.assertEqual(snapshot["tailscale"]["prefs"]["status"], "unavailable")
        self.assertIn("tailscale_prefs_unavailable", snapshot["takeover_ready"]["notes"])
        self.assertFalse(snapshot["takeover_ready"]["exit_node_selected"])

    def test_non_macos_platform_runs_nothing(self):
        def refuse(argv, timeout):
            raise AssertionError("no command may run")
        snapshot = mod.build_snapshot("linux", runner=refuse, exists=lambda path: False)
        self.assertEqual(snapshot["status"], "not_applicable")
        self.assertEqual(snapshot["commands"], [])

    def test_collect_writes_a_private_file_and_redacted_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "nmd-state"
            _, summary, path = mod.collect_snapshot(
                "macos", state, runner=fake_runner(fixtures()),
                exists=lambda p: p == TAILSCALE, now=1763369700)
            self.assertIsNotNone(path)
            self.assertTrue(str(path).startswith(str(state.resolve())))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            self.assertEqual(path.name, "pre-start-20251117T085500Z.json")
            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stored["tailscale"]["prefs"]["ExitNodeID"], "nodekey:abc123")
            blob = json.dumps(summary)
            for secret in ("nodekey:abc123", "192.0.2.53", "192.0.2.1", "100.100.100.100", "127.0.0.1"):
                self.assertNotIn(secret, blob)
            self.assertIn(summary["exit_node_id_fingerprint"], blob)

    def test_write_refuses_repo_state_dirs_even_via_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            snapshot = self.build()
            with self.assertRaisesRegex(ValueError, "state_dir_inside_repository"):
                mod.write_snapshot(snapshot, repo / "state", repo_root=repo)
            # A symlink redirecting into the checkout is refused after resolve.
            outside = Path(tmp) / "outside"
            outside.mkdir()
            link = outside / "link"
            link.symlink_to(repo)
            with self.assertRaisesRegex(ValueError, "state_dir_inside_repository"):
                mod.write_snapshot(snapshot, link / "state", repo_root=repo)


class SourceSafetyTests(unittest.TestCase):
    def test_source_has_no_write_command(self):
        source = (ROOT / "scripts/macos_prepare.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"""['"]sudo['"]""")
        self.assertNotRegex(source, r"-set[a-z]*proxy")
        self.assertNotRegex(source, r"-setnetworkserviceenabled")
        self.assertNotRegex(source, r"-setproxybypassdomains")
        self.assertNotIn("paramiko", source)
        self.assertNotRegex(source, r"tailscale['\"],\s*['\"]set")
        for banned in ("subprocess", "yaml", "socket", "urllib"):
            self.assertNotRegex(source, rf"(?m)^\s*(import|from)\s+{banned}\b", banned)
        for name in ("restore", "cutover", "watchdog", "autostart"):
            self.assertFalse(hasattr(mod, name), name)
        self.assertEqual(mod.PHASE_2_REMAINING, macos_readonly.PHASE_2_NOT_IMPLEMENTED)
        self.assertEqual(mod.PHASE_A_IMPLEMENTED, ("config_generation", "pre_start_snapshot"))

    def test_allowlist_rejects_writes_before_a_process_starts(self):
        with patch.object(macos_readonly.subprocess, "Popen", side_effect=AssertionError("spawn")):
            for argv in (
                ["/usr/sbin/networksetup", "-setwebproxystate", "Wi-Fi", "off"],
                ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "Empty"],
                ["/usr/sbin/networksetup", "-getdnsservers"],
                ["/bin/sh", "-c", "true"],
                ["/usr/bin/sudo", "/usr/sbin/scutil", "--dns"],
                ["/bin/ps", "status", "--json"],
                [TAILSCALE, "set", "--exit-node="],
                [TAILSCALE, "debug", "watch"],
            ):
                with self.subTest(argv=argv):
                    with self.assertRaisesRegex(ValueError, "command_not_allowlisted"):
                        mod.execute(argv, 2)


class CLITests(unittest.TestCase):
    script = str(ROOT / "scripts/macos_prepare.py")

    def test_config_stdout_matches_the_committed_example(self):
        result = subprocess.run(
            [sys.executable, self.script, "config", "--inputs", str(INPUTS_EXAMPLE), "--stdout"],
            check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, GOLDEN.read_text(encoding="utf-8"))

    def test_config_out_writes_privately_outside_the_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "config.yaml"
            result = subprocess.run(
                [sys.executable, self.script, "config", "--inputs", str(INPUTS_EXAMPLE),
                 "--out", str(out)], check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["result"], "config_written")
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_usage_errors_exit_two_with_the_boundary_sentence(self):
        for argv in (["restore"], ["config"], ["config", "--inputs"], ["snapshot", "--oops"]):
            with self.subTest(argv=argv):
                result = subprocess.run([sys.executable, self.script, *argv],
                                        check=False, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("no cutover", result.stderr)

    def test_snapshot_on_non_macos_never_spawns(self):
        output = io.StringIO()
        with patch.object(nmd_platform, "name", return_value="linux"), \
                patch.object(macos_readonly, "bounded_run", side_effect=AssertionError("spawn")):
            with contextlib.redirect_stdout(output):
                self.assertEqual(mod.main(["snapshot"]), 0)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["status"], "not_applicable")
        self.assertEqual(summary["command_count"], 0)


if __name__ == "__main__":
    unittest.main()
