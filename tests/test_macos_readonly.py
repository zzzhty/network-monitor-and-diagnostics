"""Read-only macOS diagnostics. Fixtures only: no real Mac, public network, or privileges."""
import hashlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import macos_readonly as mod
import nmd_monitor
import nmd_platform

NETSTAT = ("/usr/sbin/netstat", "-rn", "-f", "inet")
NETSTAT6 = ("/usr/sbin/netstat", "-rn", "-f", "inet6")
DNS = ("/usr/sbin/scutil", "--dns")
PROXY = ("/usr/sbin/scutil", "--proxy")
TAILSCALE = ("/usr/bin/tailscale", "status", "--json")
SECRET_HOST = "hidden-host"
SECRET_KEY = "secret-key"
SECRET_DNS = "secret.example.internal"
SECRET_BYPASS = "secret.bypass.invalid"
DOC_HOST = "203.0.113.20"
TAILNET_HOST = "100.64.0.8"
TAILNET6_HOST = "fd7a:115c:a1e0::8"


def status_text():
    return json.dumps({
        "BackendState": "Running",
        "Self": {"Online": True, "HostName": SECRET_HOST, "TailscaleIPs": ["100.64.0.2"]},
        "AuthURL": "https://login.example/secret-token",
        "Peer": {"node-a": {"Online": True, "DNSName": "a.example.ts.net", "PublicKey": SECRET_KEY}},
        "Padding": "x" * 2500,
    })


def route_text():
    return "\n".join([
        "Routing tables",
        "",
        "Internet:",
        "Destination        Gateway            Flags               Netif Expire",
        "default            192.0.2.1          UGScg                 en0",
        "100.64/10          link#8             UGSc                utun7",
        "127                127.0.0.1          UCS                   lo0",
        "",
    ])


def route6_text():
    return "\n".join([
        "Routing tables",
        "",
        "Internet6:",
        "Destination                       Gateway                       Flags         Netif Expire",
        "default                           fe80::1%en0                   UGc             en0",
        "fd7a:115c:a1e0::/48               link#9                        UC            utun3",
        "",
    ])


def dns_text():
    return "\n".join([
        "resolver #1",
        "  nameserver[0] : 198.18.0.2",
        "  nameserver[1] : 100.100.100.100",
        "  search domain[0] : " + SECRET_DNS,
        "",
    ])


def proxy_text(socks="0", http="0", https="0"):
    return "\n".join([
        "<dictionary> {",
        "  HTTPEnable : " + http,
        "  HTTPProxy : 127.0.0.1",
        "  HTTPPort : 7897",
        "  HTTPSEnable : " + https,
        "  HTTPSProxy : 127.0.0.1",
        "  HTTPSPort : 7897",
        "  SOCKSEnable : " + socks,
        "  SOCKSProxy : 127.0.0.1",
        "  SOCKSPort : 7897",
        "  ExceptionsList : <array> {",
        "    0 : " + SECRET_BYPASS,
        "    1 : *.local",
        "  }",
        "}",
        "",
    ])


SETUP = "/usr/sbin/networksetup"
SETUP_LIST = (SETUP, "-listallnetworkservices")
FTP_ONLY_PROXY = "<dictionary> {\n  FTP passive : 1\n}\n"


def setup_get(flag, service="Wi-Fi"):
    return (SETUP, flag, service)


def service_list(services=("Wi-Fi",)):
    lines = ["An asterisk (*) denotes that a network service is disabled."]
    lines.extend(services)
    return "\n".join(lines) + "\n"


def setup_proxy_text(enabled="No", server="127.0.0.1", port="7897"):
    return "\n".join([
        "Enabled: " + enabled,
        "Server: " + server,
        "Port: " + port,
        "Authenticated Proxy Enabled: 0",
        "",
    ])


def setup_outputs(http="No", https="No", socks="No", server="127.0.0.1", port="7897", services=("Wi-Fi",)):
    values = {"http": http, "https": https, "socks": socks}
    flags = {
        "http": "-getwebproxy",
        "https": "-getsecurewebproxy",
        "socks": "-getsocksfirewallproxy",
    }
    scripted = {SETUP_LIST: (0, service_list(services), None)}
    for name, flag in flags.items():
        for service in services:
            if str(service).startswith("*"):
                continue
            scripted[setup_get(flag, service)] = (
                0, setup_proxy_text(values[name], server, port), None,
            )
    return scripted


def read_commands(ipv6=False, service="Wi-Fi"):
    commands = [NETSTAT]
    if ipv6:
        commands.append(NETSTAT6)
    commands.extend([
        DNS,
        PROXY,
        SETUP_LIST,
        setup_get("-getwebproxy", service),
        setup_get("-getsecurewebproxy", service),
        setup_get("-getsocksfirewallproxy", service),
        TAILSCALE,
    ])
    return commands


def outputs(overrides=None):
    base = {
        NETSTAT: (0, route_text(), None),
        NETSTAT6: (0, route6_text(), None),
        DNS: (0, dns_text(), None),
        PROXY: (0, proxy_text(), None),
        TAILSCALE: (0, status_text(), None),
    }
    base.update(setup_outputs())
    if overrides:
        base.update(overrides)
    return base


def collect(settings, scripted=None, tcp=None, exists=None):
    calls = []

    def runner(argv, timeout):
        calls.append((tuple(argv), timeout))
        key = tuple(argv)
        if scripted is None or key not in scripted:
            raise AssertionError("unexpected command " + repr(key))
        return scripted[key]

    report = mod.collect(
        "macos",
        settings,
        runner=runner,
        tcp=tcp or (lambda host, port, timeout: {"status": "timeout", "elapsed_ms": 50}),
        exists=exists or (lambda path: path == TAILSCALE[0]),
    )
    return report, calls


def enabled(vps=None):
    return {"enabled": True, "vps": vps}


class SettingsTests(unittest.TestCase):
    def test_example_monitor_config_stays_disabled(self):
        config = nmd_monitor.load_config(ROOT / "examples/monitor-local.json")
        self.assertFalse(config["macos_readonly"]["enabled"])
        self.assertIsNone(config["macos_readonly"]["vps"])

    def test_rejected_targets_never_start_a_sample(self):
        for value, message in (
            ({"enabled": True, "vps": {"host": "vpn.example", "port": 1080}}, "invalid_macos_readonly"),
            ({"enabled": True, "vps": {"host": DOC_HOST, "port": 22}}, "ssh_port_not_allowed"),
            ({"enabled": "true"}, "invalid_macos_readonly"),
            ({"enabled": True, "command": "networksetup"}, "invalid_macos_readonly"),
            ({"enabled": True, "vps": {"host": DOC_HOST, "port": True}}, "invalid_macos_readonly"),
        ):
            with self.subTest(value=value), patch.object(nmd_monitor, "_run", side_effect=AssertionError("sample")):
                with self.assertRaisesRegex(ValueError, message):
                    nmd_monitor.sample_probe({"macos_readonly": value})

    def test_default_sample_does_not_spawn_readonly_commands(self):
        with patch.object(nmd_monitor, "_run", return_value=(None, "", "tool_missing")), \
                patch.object(mod, "bounded_run", side_effect=AssertionError("spawn")), \
                patch.object(mod, "tcp_connect", side_effect=AssertionError("dial")):
            sample = nmd_monitor.sample_probe({})[0]
        expected = "not_enabled" if nmd_platform.name() == "macos" else "not_applicable"
        self.assertEqual(sample["macos_readonly"]["status"], expected)
        self.assertEqual(sample["macos_readonly"]["commands"], [])
        self.assertFalse(sample["macos_readonly"]["real_machine_verified"])
        self.assertFalse(sample["macos_readonly"]["overnight_23s_root_cause_fixed"])


class PlatformBoundaryTests(unittest.TestCase):
    def test_linux_and_windows_do_not_run_macos_commands_or_dial(self):
        dials = []

        def tcp(host, port, timeout):
            dials.append((host, port))
            raise AssertionError("dial")

        for platform in ("linux", "windows", "unsupported"):
            with self.subTest(platform=platform), \
                    patch.object(mod, "bounded_run", side_effect=AssertionError("spawn")):
                report = mod.collect(
                    platform,
                    enabled({"host": DOC_HOST, "port": 1080}),
                    tcp=tcp,
                )
            self.assertEqual(report["status"], "not_applicable")
            self.assertEqual(report["commands"], [])
            self.assertEqual(report["system_proxy"]["effect"], "not_applicable")
            self.assertEqual(report["system_proxy"]["sources"]["networksetup"]["status"], "not_applicable")
            self.assertFalse(report["mutates_network"])
            self.assertNotIn(DOC_HOST, json.dumps(report))
        self.assertEqual(dials, [])

    def test_sample_probe_on_linux_and_windows_keeps_the_old_command(self):
        for platform, argv_head in (("linux", "/usr/bin/systemctl"), ("windows", None)):
            with self.subTest(platform=platform), \
                    patch.object(nmd_platform, "name", return_value=platform), \
                    patch.object(nmd_monitor, "_run", return_value=(None, "", "tool_missing")) as run, \
                    patch.object(mod, "bounded_run", side_effect=AssertionError("spawn")), \
                    patch.object(mod, "tcp_connect", side_effect=AssertionError("dial")):
                sample = nmd_monitor.sample_probe({"macos_readonly": enabled({"host": DOC_HOST, "port": 1080})})[0]
            self.assertEqual(sample["macos_readonly"]["status"], "not_applicable")
            self.assertNotIn(DOC_HOST, json.dumps(sample["macos_readonly"]))
            self.assertGreaterEqual(run.call_count, 1)
            if argv_head is not None:
                self.assertEqual(run.call_args.args[0][0], argv_head)
            blob = str(run.call_args_list)
            self.assertNotIn("scutil", blob)
            self.assertNotIn("networksetup", blob)
            self.assertNotIn("/usr/bin/tailscale", blob)
            self.assertNotIn("status', '--json'", blob)


class ReadOnlyReportTests(unittest.TestCase):
    def test_complete_status_over_2000_bytes_is_whitelisted(self):
        text = status_text()
        self.assertGreater(len(text.encode()), 2000)
        report, calls = collect(enabled(), outputs())
        tailscale = report["tailscale"]
        self.assertEqual(tailscale["availability"], "healthy")
        self.assertEqual(tailscale["backend_state"], "Running")
        self.assertTrue(tailscale["self_online"])
        self.assertEqual(tailscale["peer_count"], 1)
        self.assertEqual(tailscale["peers_online"], 1)
        blob = json.dumps(report)
        for secret in (SECRET_HOST, SECRET_KEY, "secret-token", "a.example.ts.net", "100.64.0.2"):
            self.assertNotIn(secret, blob)
        self.assertEqual([item[0] for item in calls], read_commands())
        self.assertEqual([item[1] for item in calls], [2, 2, 2, 2, 2, 2, 2, 3])
        self.assertFalse(report["report_is_health"])
        self.assertFalse(report["business_stable"])
        self.assertEqual(report["actions"], [])
        self.assertFalse(report["phase_2_implemented"])
        self.assertFalse(report["real_machine_verified"])
        self.assertFalse(report["overnight_23s_root_cause_fixed"])
        self.assertFalse(report["uses_sudo"])

    def test_overlimit_truncated_invalid_and_command_failures_are_not_healthy(self):
        huge = json.dumps({
            "BackendState": "Running",
            "Self": {"Online": True, "HostName": SECRET_HOST},
            "Padding": "x" * (mod._PARSE_LIMIT + 1),
        })
        self.assertGreater(len(huge.encode()), mod._PARSE_LIMIT)
        cases = {
            "overlimit": (0, huge, None),
            "ignored_prefix": (0, status_text(), "output_too_large"),
            "truncated": (0, status_text(), "truncated"),
            "invalid": (0, "{", None),
            "failed": (1, status_text(), None),
            "permission": (None, "AuthURL secret-token", "permission_denied"),
            "missing-field": (0, '{"BackendState":"Running"}', None),
        }
        expected = {
            "overlimit": ("unavailable", "output_too_large"),
            "ignored_prefix": ("unavailable", "output_too_large"),
            "truncated": ("unavailable", "pre_parse_truncation"),
            "invalid": ("unavailable", "invalid_json"),
            "failed": ("unavailable", "command_failed"),
            "permission": ("unavailable", "permission_denied"),
            "missing-field": ("unknown", "missing_field"),
        }
        for name, response in cases.items():
            with self.subTest(name=name):
                report, _calls = collect(enabled(), outputs({TAILSCALE: response}))
                tailscale = report["tailscale"]
                self.assertEqual((tailscale["availability"], tailscale["reason"]), expected[name])
                self.assertNotEqual(tailscale["availability"], "healthy")
                blob = json.dumps(report)
                self.assertNotIn(SECRET_HOST, blob)
                self.assertNotIn("secret-token", blob)
                self.assertNotEqual(report["status"], "healthy")

    def test_missing_tailscale_command_does_not_invent_health(self):
        scripted = outputs()
        del scripted[TAILSCALE]
        report, calls = collect(enabled(), scripted, exists=lambda _path: False)
        self.assertEqual(report["tailscale"]["availability"], "unavailable")
        self.assertEqual(report["tailscale"]["reason"], "tool_missing")
        self.assertNotIn(TAILSCALE, [item[0] for item in calls])
        self.assertEqual(report["status"], "partial")

    def test_failed_route_and_dns_bodies_are_not_parsed(self):
        secret_route = "default 203.0.113.9 UGSc en9 secret.route.invalid\n"
        report, _calls = collect(enabled(), outputs({
            NETSTAT: (1, "Destination Gateway Flags Netif\n" + secret_route, None),
            DNS: (1, "nameserver[0] : 198.18.0.2\n" + SECRET_DNS + "\n", None),
        }))
        self.assertEqual(report["routes"]["status"], "unavailable")
        self.assertEqual(report["routes"]["reason"], "command_failed")
        self.assertEqual(report["routes"]["default_interfaces"], [])
        self.assertIsNone(report["dns"]["fake_ip_resolver_present"])
        self.assertEqual(report["dns"]["reason"], "command_failed")
        blob = json.dumps(report)
        self.assertNotIn("secret.route.invalid", blob)
        self.assertNotIn(SECRET_DNS, blob)
        self.assertNotIn("198.18.0.2", blob)
        self.assertNotIn("en9", blob)

    def test_dynamic_route_selects_the_longest_match_without_storing_addresses(self):
        report, _calls = collect(enabled({"host": TAILNET_HOST, "port": 9}), outputs())
        routes = report["routes"]
        self.assertEqual(routes["interface_discovery"], "dynamic")
        self.assertEqual(routes["default_interfaces"], ["en0"])
        self.assertEqual(routes["default_route_count"], 1)
        self.assertEqual(routes["tailnet_interface"], "utun7")
        self.assertEqual(routes["tailnet_route_status"], "observed")
        self.assertEqual(report["vps_tcp"]["status"], "timeout")
        self.assertEqual(report["vps_tcp"]["address_class"], "tailnet_ipv4")
        self.assertEqual(report["vps_tcp"]["port"], 9)
        self.assertFalse(report["vps_tcp"]["business_stable"])
        self.assertFalse(report["vps_tcp"]["means_tailnet_online"])
        self.assertFalse(report["vps_tcp"]["means_route_ok"])
        self.assertFalse(report["vps_tcp"]["means_dns_ok"])
        self.assertFalse(report["vps_tcp"]["means_app_ok"])
        self.assertEqual(report["tailscale"]["availability"], "healthy")
        fingerprint = hashlib.sha256(TAILNET_HOST.encode()).hexdigest()[:16]
        self.assertEqual(report["vps_tcp"]["host_fingerprint"], fingerprint)
        blob = json.dumps(report)
        for hidden in (TAILNET_HOST, "192.0.2.1", "link#8", SECRET_DNS, SECRET_BYPASS):
            self.assertNotIn(hidden, blob, hidden)

    def test_documentation_address_uses_the_default_route_and_is_not_stored(self):
        seen = []

        def tcp(host, port, timeout):
            seen.append((host, port, timeout))
            return {"status": "ok", "elapsed_ms": 5, "business_stable": True, "host": host}

        report, _calls = collect(enabled({"host": DOC_HOST, "port": 1080}), outputs(), tcp=tcp)
        self.assertEqual(seen, [(DOC_HOST, 1080, 2)])
        self.assertEqual(report["routes"]["tailnet_interface"], "en0")
        self.assertEqual(report["vps_tcp"]["status"], "ok")
        self.assertEqual(report["vps_tcp"]["address_class"], "other")
        self.assertFalse(report["vps_tcp"]["business_stable"])
        self.assertNotEqual(report["status"], "healthy")
        self.assertFalse(report["report_is_health"])
        self.assertNotIn(DOC_HOST, json.dumps(report))

    def test_ipv6_tailnet_route_is_separate_from_the_ipv4_default(self):
        report, calls = collect(enabled({"host": TAILNET6_HOST, "port": 1080}), outputs())
        self.assertEqual([item[0] for item in calls], read_commands(ipv6=True))
        self.assertEqual(report["routes"]["default_interfaces"], ["en0"])
        self.assertEqual(report["routes"]["tailnet_interface"], "utun3")
        self.assertEqual(report["routes"]["ipv6_default_status"], "observed")
        self.assertEqual(report["vps_tcp"]["address_class"], "tailnet_ipv6")
        blob = json.dumps(report)
        self.assertNotIn(TAILNET6_HOST, blob)
        self.assertNotIn("fe80::1%en0", blob)
        self.assertNotIn("fd7a:115c:a1e0::/48", blob)

    def test_ambiguous_tailnet_route_stays_unknown(self):
        text = "\n".join([
            "Destination Gateway Flags Netif",
            "default 192.0.2.1 UGSc en0",
            "100.64/10 link#1 UGSc en0",
            "100.64/10 link#2 UGSc utun7",
        ])
        report, _calls = collect(enabled({"host": TAILNET_HOST, "port": 9}), outputs({NETSTAT: (0, text, None)}))
        self.assertEqual(report["routes"]["status"], "unknown")
        self.assertEqual(report["routes"]["reason"], "ambiguous_route")
        self.assertIsNone(report["routes"]["tailnet_interface"])
        self.assertNotIn("192.0.2.1", json.dumps(report))

    def test_dns_keeps_booleans_and_drops_search_domains(self):
        report, _calls = collect(enabled(), outputs())
        dns = report["dns"]
        self.assertEqual(dns["status"], "observed")
        self.assertEqual(dns["nameserver_count"], 2)
        self.assertTrue(dns["fake_ip_resolver_present"])
        self.assertTrue(dns["native_tun_resolver_present"])
        self.assertTrue(dns["magic_dns_present"])
        blob = json.dumps(report)
        self.assertNotIn(SECRET_DNS, blob)
        self.assertNotIn("198.18.0.2", blob)
        self.assertNotIn("100.100.100.100", blob)

    def test_disabled_saved_proxy_is_not_a_fault_and_bypass_is_not_reset(self):
        def tcp(*_args):
            raise AssertionError("disabled proxy must not be dialed")

        report, _calls = collect(enabled(), outputs(), tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["warnings"], [])
        self.assertFalse(proxy["disabled_saved_address_is_fault"])
        self.assertEqual(proxy["bypass_count"], 2)
        self.assertFalse(proxy["bypass_reset"])
        self.assertFalse(proxy["auto_disable"])
        self.assertEqual(proxy["actions"], [])
        self.assertEqual(
            sorted(item["endpoint"] for item in proxy["disabled_saved"]),
            ["127.0.0.1:7897", "127.0.0.1:7897", "127.0.0.1:7897"],
        )
        blob = json.dumps(report)
        self.assertNotIn(SECRET_BYPASS, blob)
        self.assertNotIn("*.local", blob)

    def test_enabled_dead_proxy_warns_without_changing_it(self):
        dials = []

        def tcp(host, port, timeout):
            dials.append((host, port, timeout))
            return {"status": "refused", "elapsed_ms": 3}

        scripted = outputs({PROXY: (0, proxy_text("1"), None)})
        scripted.update(setup_outputs(socks="Yes"))
        report, _calls = collect(enabled(), scripted, tcp=tcp)
        warnings = report["system_proxy"]["warnings"]
        self.assertEqual(dials, [("127.0.0.1", 7897, 1)])
        self.assertEqual(warnings, [{
            "code": "dead_proxy",
            "protocol": "socks",
            "endpoint": "127.0.0.1:7897",
            "read_only": True,
            "priority": "high",
            "affects_system_proxy_clients": True,
            "tailscale_success_does_not_clear": True,
        }])
        self.assertEqual(report["system_proxy"]["actions"], [])
        self.assertFalse(report["system_proxy"]["auto_disable"])
        self.assertFalse(report["system_proxy"]["bypass_reset"])
        self.assertEqual(len(report["system_proxy"]["disabled_saved"]), 2)

    def test_non_loopback_enabled_proxy_is_not_dialed(self):
        text = "\n".join([
            "HTTPEnable : 1",
            "HTTPProxy : 198.51.100.9",
            "HTTPPort : 8080",
            "HTTPSEnable : 0",
            "SOCKSEnable : 0",
        ])

        def tcp(*_args):
            raise AssertionError("non-loopback proxy must not be dialed")

        report, _calls = collect(enabled(), outputs({PROXY: (0, text, None)}), tcp=tcp)
        self.assertEqual(report["system_proxy"]["warnings"], [{
            "code": "proxy_enabled_unchecked", "protocol": "http", "endpoint": None, "read_only": True,
        }])
        self.assertNotIn("198.51.100.9", json.dumps(report))

    def test_missing_proxy_fields_stay_unknown_when_neither_source_confirms(self):
        text = "HTTPProxy : 198.51.100.9\nHTTPSProxy : 198.51.100.9\n"
        scripted = outputs({
            PROXY: (0, text, None),
            setup_get("-getwebproxy"): (0, "Server: 198.51.100.9\nPort: 8080\n", None),
            setup_get("-getsecurewebproxy"): (0, "Server: 198.51.100.9\nPort: 8080\n", None),
            setup_get("-getsocksfirewallproxy"): (0, "Server: 198.51.100.9\nPort: 8080\n", None),
        })
        report, _calls = collect(enabled(), scripted)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["status"], "unknown")
        self.assertEqual(proxy["reason"], "missing_field")
        self.assertEqual(proxy["disabled_saved"], [])
        self.assertEqual(proxy["sources"]["scutil"]["status"], "missing_field")
        self.assertEqual(proxy["sources"]["networksetup"]["status"], "unknown")
        self.assertNotIn("198.51.100.9", json.dumps(report))

    def test_scutil_without_http_keys_keeps_networksetup_disabled_saved_address(self):
        def tcp(*_args):
            raise AssertionError("disabled proxy must not be dialed")

        scripted = outputs({PROXY: (0, FTP_ONLY_PROXY, None)})
        report, calls = collect(enabled(), scripted, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["status"], "observed")
        self.assertIsNone(proxy["reason"])
        self.assertEqual(proxy["effect"], "not_a_fault")
        self.assertEqual(proxy["warnings"], [])
        self.assertFalse(proxy["disabled_saved_address_is_fault"])
        self.assertEqual(proxy["missing_protocols"], [])
        self.assertEqual(
            sorted((item["protocol"], item["endpoint"]) for item in proxy["disabled_saved"]),
            [("http", "127.0.0.1:7897"), ("https", "127.0.0.1:7897"), ("socks", "127.0.0.1:7897")],
        )
        self.assertEqual(proxy["sources"]["scutil"]["status"], "missing_field")
        self.assertEqual(proxy["sources"]["networksetup"]["status"], "observed")
        for protocol in ("http", "https", "socks"):
            item = proxy["protocols"][protocol]
            self.assertEqual(item["state"], "disabled")
            self.assertEqual(item["scutil"], "missing")
            self.assertEqual(item["networksetup"], "disabled")
            self.assertEqual(item["established_by"], ["networksetup"])
            self.assertTrue(item["sources_agree"])
            self.assertFalse(item["saved_address_is_fault"])
        self.assertEqual(proxy["services_read"], ["Wi-Fi"])
        self.assertFalse(proxy["auto_disable"])
        self.assertFalse(proxy["monitoring_prevents_reenable"])
        self.assertFalse(report["dead_proxy_blocks_health_claim"])
        self.assertIn(SETUP_LIST, [item[0] for item in calls])

    def test_enabled_refused_proxy_is_not_cleared_by_tailscale(self):
        dials = []

        def tcp(host, port, timeout):
            dials.append((host, port, timeout))
            return {"status": "refused", "elapsed_ms": 4}

        scripted = outputs({PROXY: (0, FTP_ONLY_PROXY, None)})
        scripted.update(setup_outputs(http="Yes", https="Yes", socks="Yes"))
        report, _calls = collect(enabled(), scripted, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(dials, [("127.0.0.1", 7897, 1)])
        self.assertEqual(
            [(item["protocol"], item["code"], item["priority"]) for item in proxy["warnings"]],
            [("http", "dead_proxy", "high"), ("https", "dead_proxy", "high"), ("socks", "dead_proxy", "high")],
        )
        for warning in proxy["warnings"]:
            self.assertTrue(warning["affects_system_proxy_clients"])
            self.assertTrue(warning["tailscale_success_does_not_clear"])
            self.assertEqual(warning["endpoint"], "127.0.0.1:7897")
        self.assertEqual(proxy["effect"], "system_proxy_clients_blocked")
        self.assertEqual(proxy["dead_proxy_priority"], "high")
        self.assertEqual(proxy["disabled_saved"], [])
        self.assertEqual(proxy["actions"], [])
        self.assertFalse(proxy["auto_disable"])
        self.assertFalse(proxy["bypass_reset"])
        self.assertFalse(proxy["curl_reads_system_proxy"])
        self.assertFalse(proxy["tailscale_reachable_means_apps_ok"])
        self.assertFalse(proxy["monitoring_prevents_reenable"])
        self.assertEqual(report["tailscale"]["availability"], "healthy")
        self.assertTrue(report["dead_proxy_blocks_health_claim"])
        self.assertFalse(report["report_is_health"])
        self.assertNotEqual(report["status"], "healthy")

    def test_partial_enable_warns_only_for_the_enabled_protocol(self):
        def tcp(host, port, timeout):
            self.assertEqual((host, port, timeout), ("127.0.0.1", 7897, 1))
            return {"status": "refused", "elapsed_ms": 2}

        scripted = outputs({PROXY: (0, FTP_ONLY_PROXY, None)})
        scripted.update(setup_outputs(http="No", https="No", socks="Yes"))
        report, _calls = collect(enabled(), scripted, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual([item["protocol"] for item in proxy["warnings"]], ["socks"])
        self.assertEqual(proxy["warnings"][0]["code"], "dead_proxy")
        self.assertEqual(
            sorted(item["protocol"] for item in proxy["disabled_saved"]),
            ["http", "https"],
        )
        self.assertEqual(proxy["protocols"]["http"]["state"], "disabled")
        self.assertEqual(proxy["protocols"]["socks"]["state"], "enabled")
        self.assertEqual(proxy["effect"], "system_proxy_clients_blocked")
        self.assertFalse(report["report_is_health"])

    def test_enabled_and_reachable_is_not_the_dead_proxy_fault(self):
        def tcp(host, port, timeout):
            self.assertEqual((host, port, timeout), ("127.0.0.1", 7897, 1))
            return {"status": "ok", "elapsed_ms": 2}

        scripted = outputs({PROXY: (0, proxy_text(http="1", https="1", socks="1"), None)})
        scripted.update(setup_outputs(http="Yes", https="Yes", socks="Yes"))
        report, _calls = collect(enabled(), scripted, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["warnings"], [])
        self.assertEqual(proxy["effect"], "enabled_and_reachable")
        self.assertIsNone(proxy["dead_proxy_priority"])
        self.assertFalse(report["dead_proxy_blocks_health_claim"])
        self.assertFalse(proxy["monitoring_prevents_reenable"])
        self.assertFalse(report["report_is_health"])

    def test_sources_that_disagree_do_not_hide_an_enabled_dead_proxy(self):
        def tcp(*_args):
            return {"status": "refused", "elapsed_ms": 1}

        scripted = outputs({PROXY: (0, proxy_text("0"), None)})
        scripted.update(setup_outputs(socks="Yes"))
        report, _calls = collect(enabled(), scripted, tcp=tcp)
        socks = report["system_proxy"]["protocols"]["socks"]
        self.assertEqual(socks["state"], "enabled")
        self.assertFalse(socks["sources_agree"])
        self.assertEqual(report["system_proxy"]["warnings"][0]["code"], "dead_proxy")
        self.assertNotIn("socks", [item["protocol"] for item in report["system_proxy"]["disabled_saved"]])

    def test_one_failed_source_does_not_erase_the_other(self):
        secret = "secret.service.invalid"

        def tcp(*_args):
            raise AssertionError("disabled proxy must not be dialed")

        listed = outputs({
            SETUP_LIST: (1, "Wi-Fi\nEnabled: Yes\n" + secret + "\n", None),
        })
        report, calls = collect(enabled(), listed, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["sources"]["networksetup"]["status"], "unavailable")
        self.assertEqual(proxy["sources"]["scutil"]["status"], "observed")
        self.assertEqual(proxy["effect"], "not_a_fault")
        self.assertEqual(len(proxy["disabled_saved"]), 3)
        self.assertEqual(proxy["protocols"]["http"]["established_by"], ["scutil"])
        self.assertNotIn(setup_get("-getwebproxy"), [item[0] for item in calls])
        self.assertNotIn(secret, json.dumps(report))

        failed_scutil = outputs({
            PROXY: (1, "HTTPEnable : 1\nHTTPProxy : 198.51.100.9\nHTTPPort : 8080\n" + secret + "\n", None),
        })
        report, _calls = collect(enabled(), failed_scutil, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["sources"]["scutil"]["status"], "unavailable")
        self.assertEqual(proxy["sources"]["networksetup"]["status"], "observed")
        self.assertEqual(proxy["effect"], "not_a_fault")
        self.assertEqual(len(proxy["disabled_saved"]), 3)
        self.assertEqual(proxy["protocols"]["http"]["established_by"], ["networksetup"])
        self.assertNotIn("198.51.100.9", json.dumps(report))
        self.assertNotIn(secret, json.dumps(report))

        both = outputs({
            PROXY: (1, "HTTPEnable : 1\nHTTPProxy : 198.51.100.9\n", None),
            SETUP_LIST: (1, "Enabled: Yes\nServer: 198.51.100.9\n", None),
        })
        report, calls = collect(enabled(), both, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["status"], "unavailable")
        self.assertEqual(proxy["effect"], "unknown")
        self.assertEqual(proxy["disabled_saved"], [])
        self.assertEqual(proxy["warnings"], [])
        self.assertFalse(report["report_is_health"])
        self.assertNotEqual(report["status"], "healthy")
        self.assertNotIn(setup_get("-getwebproxy"), [item[0] for item in calls])
        self.assertNotIn("198.51.100.9", json.dumps(report))

    def test_one_protocol_read_failing_does_not_drop_the_confirmed_protocols(self):
        secret = "secret.proxy.invalid"

        def tcp(*_args):
            raise AssertionError("dial")

        scripted = outputs({PROXY: (0, FTP_ONLY_PROXY, None)})
        scripted[setup_get("-getwebproxy")] = (1, "Enabled: Yes\nServer: " + secret + "\n", None)
        report, _calls = collect(enabled(), scripted, tcp=tcp)
        proxy = report["system_proxy"]
        self.assertEqual(proxy["status"], "partial")
        self.assertEqual(proxy["protocols"]["http"]["state"], "unknown")
        self.assertEqual(proxy["protocols"]["https"]["state"], "disabled")
        self.assertEqual(proxy["protocols"]["socks"]["state"], "disabled")
        self.assertEqual(
            sorted(item["protocol"] for item in proxy["disabled_saved"]),
            ["https", "socks"],
        )
        self.assertNotEqual(proxy["status"], "unknown")
        self.assertNotIn(secret, json.dumps(report))

    def test_inactive_services_are_not_queried_and_wifi_survives_the_cap(self):
        starred = outputs({
            SETUP_LIST: (0, service_list(("Wi-Fi", "*Thunderbolt Bridge")), None),
        })
        report, calls = collect(enabled(), starred)
        argv = [item[0] for item in calls]
        self.assertIn(setup_get("-getwebproxy", "Wi-Fi"), argv)
        self.assertNotIn(setup_get("-getwebproxy", "Thunderbolt Bridge"), argv)
        self.assertEqual(report["system_proxy"]["inactive_service_count"], 1)
        names = tuple("Lan{}".format(index) for index in range(8)) + ("Wi-Fi",)
        capped = outputs()
        capped.update(setup_outputs(services=names))
        report, calls = collect(enabled(), capped)
        argv = [item[0] for item in calls]
        self.assertTrue(report["system_proxy"]["services_capped"])
        self.assertEqual(report["system_proxy"]["services_read"][0], "Wi-Fi")
        self.assertNotIn("Lan7", report["system_proxy"]["services_read"])
        self.assertNotIn(setup_get("-getwebproxy", "Lan7"), argv)
        self.assertEqual(report["system_proxy"]["status"], "partial")

    def test_unconfigured_vps_is_not_a_dial_or_a_scan(self):
        def tcp(*_args):
            raise AssertionError("dial")

        report, _calls = collect(enabled(), outputs(), tcp=tcp)
        self.assertEqual(report["vps_tcp"]["status"], "not_configured")
        self.assertEqual(report["routes"]["tailnet_route_status"], "not_configured")
        self.assertIsNone(report["vps_tcp"]["host_fingerprint"])


class CommandBoundTests(unittest.TestCase):
    def test_allowlist_rejects_writes_before_a_process_starts(self):
        with patch.object(mod.subprocess, "Popen", side_effect=AssertionError("spawn")):
            for argv in (
                ["/usr/sbin/networksetup", "-setwebproxystate", "Wi-Fi", "off"],
                ["/usr/sbin/networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "7897"],
                ["/usr/sbin/networksetup", "-getwebproxy", "-Wi-Fi"],
                ["/bin/sh", "-c", "true"],
                ["/usr/bin/sudo", "/usr/sbin/scutil", "--dns"],
                ["/tmp/not-a-tailscale", "status", "--json"],
                ["tailscale", "set", "--exit-node="],
            ):
                with self.subTest(argv=argv):
                    with self.assertRaisesRegex(ValueError, "command_not_allowlisted"):
                        mod.execute(argv, 1)

    def test_known_tailscale_path_uses_the_parser_limit_not_a_2000_byte_slice(self):
        with patch.object(mod, "_executable", return_value=True), \
                patch.object(mod, "bounded_run", return_value=(0, status_text().encode(), None)) as run:
            code, text, error = mod.execute(list(TAILSCALE), 3)
        self.assertEqual((code, error), (0, None))
        self.assertGreater(len(text.encode()), 2000)
        self.assertEqual(run.call_args.args[2], mod._PARSE_LIMIT)
        with patch.object(mod, "_executable", return_value=False), \
                patch.object(mod, "bounded_run", side_effect=AssertionError("spawn")):
            with self.assertRaisesRegex(ValueError, "command_not_allowlisted"):
                mod.execute(list(TAILSCALE), 3)

    def test_source_has_no_write_command(self):
        source = (ROOT / "scripts/macos_readonly.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"""['"]sudo['"]""")
        self.assertNotRegex(source, r"-set[a-z]*proxy")
        self.assertNotRegex(source, r"-setnetworkserviceenabled")
        self.assertNotRegex(source, r"-setproxybypassdomains")
        self.assertIn('"/usr/sbin/networksetup"', source)
        self.assertNotIn("paramiko", source)
        self.assertNotRegex(source, r"tailscale['\"],\s*['\"]set")
        for name in ("restore", "cutover", "watchdog", "autostart"):
            self.assertFalse(hasattr(mod, name))
        self.assertEqual(mod.PHASE_2_NOT_IMPLEMENTED, ())

    def test_bounded_reader_keeps_a_complete_body_and_drops_overlimit_or_timeout(self):
        payload = b"A" * 3000
        code, data, error = mod.bounded_run(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'A'*3000)"],
            5,
            mod._PARSE_LIMIT,
        )
        self.assertEqual((code, error, data), (0, None, payload))
        self.assertGreater(len(data), 2000)
        code, data, error = mod.bounded_run(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'B'*8000)"],
            5,
            100,
        )
        self.assertEqual((code, data, error), (None, b"", "output_too_large"))
        code, data, error = mod.bounded_run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            0.4,
            1000,
        )
        self.assertEqual((code, data, error), (None, b"", "timeout"))

    def test_missing_command_and_permission_are_distinct(self):
        code, data, error = mod.bounded_run(["/tmp/nmd-readonly-missing-2919"], 2, 100)
        self.assertEqual((code, data, error), (None, b"", "tool_missing"))
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "noexec"
            script.write_text("#!/bin/sh\necho no\n", encoding="utf-8")
            script.chmod(0o644)
            code, data, error = mod.bounded_run([str(script)], 2, 100)
        self.assertEqual((code, data, error), (None, b"", "permission_denied"))

    def test_loopback_connect_and_ssh_port_policy(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        try:
            opened = mod.tcp_connect("127.0.0.1", port, 1)
        finally:
            sock.close()
        self.assertEqual(opened["status"], "ok")
        refused = mod.tcp_connect("127.0.0.1", port, 1)
        self.assertEqual(refused["status"], "refused")
        with patch.object(mod.socket, "socket", side_effect=AssertionError("dial")):
            blocked = mod.tcp_connect(DOC_HOST, 22, 1)
        self.assertEqual(blocked["status"], "refused_by_policy")


class EntryTests(unittest.TestCase):
    def test_cli_on_linux_is_not_applicable_and_has_no_control_command(self):
        stdout = io.StringIO()
        with patch.object(nmd_platform, "name", return_value="linux"), \
                patch.object(mod, "bounded_run", side_effect=AssertionError("spawn")), \
                redirect_stdout(stdout):
            code = mod.main(["observe"])
        self.assertEqual(code, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["status"], "not_applicable")
        self.assertEqual(report["invocation"], "cli")
        self.assertEqual(report["commands"], [])
        for command in ("restore", "cutover", "watchdog"):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(mod.main([command]), 2)

    def test_cli_config_supplies_only_the_explicit_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "monitor.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "macos_readonly": {"enabled": False, "vps": {"host": DOC_HOST, "port": 1080}},
            }), encoding="utf-8")
            seen = {}

            def fake_collect(platform, settings, invocation="collector"):
                seen["platform"] = platform
                seen["settings"] = settings
                seen["invocation"] = invocation
                return {"status": "not_applicable"}

            stdout = io.StringIO()
            with patch.object(mod, "collect", fake_collect), \
                    patch.object(nmd_platform, "name", return_value="linux"), \
                    redirect_stdout(stdout):
                code = mod.main(["observe", "--config", str(path)])
            self.assertEqual(code, 0)
            self.assertTrue(seen["settings"]["enabled"])
            self.assertEqual(seen["settings"]["vps"], {"host": DOC_HOST, "port": 1080})
            self.assertEqual(seen["invocation"], "cli")
            path.write_text(json.dumps({
                "schema_version": 1,
                "macos_readonly": {"enabled": True, "vps": {"host": DOC_HOST, "port": 22}},
            }), encoding="utf-8")
            with patch.object(mod, "collect", side_effect=AssertionError("collect")), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(mod.main(["observe", "--config", str(path)]), 2)

    def test_collector_hook_uses_the_injected_reader(self):
        calls = []

        def execute(argv, timeout):
            calls.append(tuple(argv))
            return outputs()[tuple(argv)]

        ifconfig = (ROOT / "tests/fixtures/macos-ifconfig.txt").read_text(encoding="utf-8")
        routes = (ROOT / "tests/fixtures/macos-routes.txt").read_text(encoding="utf-8")
        with patch.object(nmd_platform, "name", return_value="macos"), \
                patch.object(nmd_monitor, "_run", side_effect=[(0, ifconfig, None), (0, routes, None)]) as run, \
                patch.object(mod, "_executable", lambda path: path == TAILSCALE[0]), \
                patch.object(mod, "execute", execute), \
                patch.object(mod, "tcp_connect", return_value={"status": "timeout", "elapsed_ms": 20}):
            sample = nmd_monitor.sample_probe({"macos_readonly": enabled({"host": TAILNET_HOST, "port": 9})})[0]
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["/sbin/ifconfig", "-a"], ["/usr/sbin/netstat", "-rn", "-f", "inet"],
        ])
        self.assertEqual(calls, read_commands())
        self.assertEqual(sample["interfaces"], ["en0", "en1", "lo0", "utun2"])
        self.assertEqual(sample["macos_readonly"]["tailscale"]["availability"], "healthy")
        self.assertEqual(sample["macos_readonly"]["routes"]["tailnet_interface"], "utun7")
        self.assertEqual(sample["macos_readonly"]["vps_tcp"]["status"], "timeout")
        blob = json.dumps(sample)
        for hidden in ("192.0.2.10", "192.0.2.1", "02:00:00:00:00:01", "fe80::1", TAILNET_HOST, SECRET_HOST):
            self.assertNotIn(hidden, blob)

    def test_record_documents_the_dependency_and_phase_two_list(self):
        text = (ROOT / "docs/macos-mihomo-tailscale.md").read_text(encoding="utf-8")
        for phrase in (
            "python3 scripts/macos_readonly.py observe",
            "not_applicable",
            "先合并 PR #4",
            "macos_readonly.enabled",
            "business_stable",
            "real_machine_verified",
            "不要使用 sudo",
            "开机自启已由常驻 daemon 提供",
            "scripts/macos_prepare.py",
            "scripts/macos_takeover.py",
            "scripts/nmd_daemon.py",
            "此次新代码没有在实机运行",
            "4044472",
            "不能只信可能缺键的 `scutil --proxy`",
            "dead_proxy_blocks_health_claim",
            "monitoring_prevents_reenable",
            "挡不住有人再次启用一个失效代理",
            "根因未定",
        ):
            self.assertIn(phrase, text, phrase)
        self.assertNotIn("/Users/", text)


if __name__ == "__main__":
    unittest.main()
