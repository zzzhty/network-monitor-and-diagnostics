"""Static checks for the experimental macOS mihomo + Tailscale notes.

No network, process, or host configuration. GeoIP and GeoSite hits below are
fixture marks, not a copy of a database or of the user machine.
"""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import macos_coexist as m

CN_FIXTURE = "198.51.100.10"
OTHER_FIXTURE = "203.0.113.50"
GROUP = "NMD-EXIT"


def rules():
    return m.insert_overseas_domain_rules(list(m.STRUCTURAL_RULES_BEFORE_DOMAIN_FIX), GROUP)


def tun_sample(**overrides):
    sample = {
        "label": "tun-example",
        "route_ok": True,
        "dns_ok": True,
        "rc": 0,
        "http_status": 200,
        "tls_valid": True,
        "aaaa_present": True,
        "ping_ok": True,
        "remote_ip": None,
        "controls": {},
    }
    sample.update(overrides)
    return sample


class RuleOrderTests(unittest.TestCase):
    def test_suffix_rules_are_inserted_before_domestic_geo_rules(self):
        before = list(m.STRUCTURAL_RULES_BEFORE_DOMAIN_FIX)
        updated = rules()
        self.assertEqual(updated, m.overseas_domain_rules(GROUP) + before)
        self.assertEqual(before, list(m.STRUCTURAL_RULES_BEFORE_DOMAIN_FIX))
        self.assertEqual(m.insert_overseas_domain_rules(updated, GROUP), updated)
        self.assertEqual(m.validate_rule_order(updated, GROUP), [])
        self.assertLess(updated.index("DOMAIN-SUFFIX,oaiusercontent.com,NMD-EXIT"),
                        updated.index("GEOSITE,cn,DIRECT"))
        self.assertLess(updated.index("GEOSITE,cn,DIRECT"),
                        updated.index("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"))
        self.assertLess(updated.index("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"),
                        updated.index("GEOIP,CN,DIRECT"))
        self.assertLess(updated.index("GEOIP,CN,DIRECT"), updated.index("MATCH,NMD-EXIT"))

    def test_ip_and_geo_lines_stay_byte_for_byte(self):
        before = list(m.STRUCTURAL_RULES_BEFORE_DOMAIN_FIX)
        updated = rules()
        self.assertEqual(m.ip_and_geo_rules(before), m.ip_and_geo_rules(updated))
        self.assertEqual(updated.count("GEOIP,CN,DIRECT"), 1)
        self.assertNotIn("GEOIP,CN,DIRECT,no-resolve", updated)
        self.assertNotIn("GEOSITE,cn,NMD-EXIT", updated)
        self.assertTrue(all(rule.startswith("DOMAIN-SUFFIX,") for rule in m.overseas_domain_rules(GROUP)))

    def test_retargeting_geoip_or_placing_suffixes_late_fails(self):
        updated = rules()
        retargeted = ["GEOIP,CN,NMD-EXIT" if rule == "GEOIP,CN,DIRECT" else rule for rule in updated]
        self.assertTrue(any("DIRECT" in item for item in m.validate_rule_order(retargeted, GROUP)))
        late = list(m.STRUCTURAL_RULES_BEFORE_DOMAIN_FIX) + m.overseas_domain_rules(GROUP)
        self.assertTrue(any("not before" in item for item in m.validate_rule_order(late, GROUP)))
        with self.assertRaises(ValueError):
            m.insert_overseas_domain_rules(
                ["DOMAIN-SUFFIX,chatgpt.com,DIRECT", *m.STRUCTURAL_RULES_BEFORE_DOMAIN_FIX], GROUP)
        with self.assertRaises(ValueError):
            m.overseas_domain_rules("DIRECT")

    def test_cn_marked_fixture_hits_suffix_before_geoip(self):
        updated = rules()
        before = list(m.STRUCTURAL_RULES_BEFORE_DOMAIN_FIX)
        missed = m.match_rule(before, "ws.chatgpt.com", ip=CN_FIXTURE, geoip_cn_ips=[CN_FIXTURE])
        self.assertEqual(missed, "GEOIP,CN,DIRECT")
        for host, suffix in {
            "chatgpt.com": "chatgpt.com",
            "ws.chatgpt.com": "chatgpt.com",
            "WS.ChatGPT.com.": "chatgpt.com",
            "a.b.chatgpt.com": "chatgpt.com",
            "api.openai.com": "openai.com",
            "cdn.oaistatic.com": "oaistatic.com",
            "files.oaiusercontent.com": "oaiusercontent.com",
        }.items():
            matched = m.match_rule(updated, host, ip=CN_FIXTURE, geoip_cn_ips=[CN_FIXTURE],
                                   geosite_cn=["baidu.com"])
            self.assertEqual(matched, f"DOMAIN-SUFFIX,{suffix},NMD-EXIT", host)

    def test_suffix_does_not_capture_lookalikes_or_domestic_names(self):
        updated = rules()
        for host in ("notchatgpt.com", "chatgpt.com.evil.test", "chatgpt.co",
                     "prefixopenai.com", "openai.com.evil.test", "example.com",
                     "oaistatic.com.example"):
            matched = m.match_rule(updated, host, ip=CN_FIXTURE, geoip_cn_ips=[CN_FIXTURE])
            self.assertEqual(matched, "GEOIP,CN,DIRECT", host)
            self.assertFalse(any(m.domain_suffix_matches(suffix, host)
                                 for suffix in m.OVERSEAS_DOMAIN_SUFFIXES))
        domestic = m.match_rule(updated, "www.baidu.com", ip=CN_FIXTURE,
                                geosite_cn=["baidu.com"], geoip_cn_ips=[CN_FIXTURE])
        self.assertEqual(domestic, "GEOSITE,cn,DIRECT")
        direct_ip = m.match_rule(updated, "example.com", ip=OTHER_FIXTURE, geoip_cn_ips=[CN_FIXTURE])
        self.assertEqual(direct_ip, "MATCH,NMD-EXIT")
        self.assertEqual(m.match_rule(updated, "printer.internal", ip="192.168.1.20"),
                         "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
        self.assertEqual(m.match_rule(updated, "printer.internal", ip="10.1.2.3"),
                         "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")


class ProfileTests(unittest.TestCase):
    def test_profile_stays_opt_in_and_uses_dynamic_tailnet_binding(self):
        profile = m.build_experiment_profile()
        self.assertEqual(m.validate_experiment_profile(profile), [])
        self.assertFalse(profile["nmd_experiment"]["auto_enable"])
        self.assertFalse(profile["nmd_experiment"]["production_stable"])
        self.assertTrue(profile["nmd_experiment"]["linux_home_default_unchanged"])
        self.assertEqual(profile["nmd_experiment"]["windows"], "deferred")
        self.assertFalse(profile["nmd_experiment"]["directly_loadable_by_mihomo"])
        self.assertFalse(profile["nmd_experiment"]["starts_processes"])
        self.assertFalse(profile["nmd_experiment"]["mutates_network"])
        self.assertFalse(m.mihomo_would_load(profile))
        self.assertFalse(m.mihomo_would_load({"rules": ["MATCH,DIRECT"]}))
        self.assertTrue(m.mihomo_would_load({"mode": "rule", "rules": ["MATCH,DIRECT"]}))
        self.assertEqual(profile["egress"]["kind"], "socks5-over-tailnet")
        self.assertFalse(profile["egress"]["tailscale_exit_node"])
        self.assertEqual(profile["egress"]["interface_discovery"], "dynamic")
        self.assertNotIn("interface-name", profile["egress"])
        self.assertEqual(profile["egress"]["server"], "203.0.113.20")
        self.assertTrue(profile["egress"]["server_placeholder"])
        self.assertEqual(profile["tun"]["route_exclude_address"],
                         ["100.64.0.0/10", "fd7a:115c:a1e0::/48"])
        self.assertEqual(profile["tun"]["observed_address"], "198.18.0.1/30")
        self.assertEqual(profile["dns_mode"]["system_dns"], "198.18.0.2")
        self.assertEqual(profile["dns_mode"]["native_scutil_order"], 1)
        self.assertFalse(profile["dns_mode"]["resolv_conf_sufficient"])
        self.assertFalse(profile["dns_mode"]["scoped_dns_covers_all_queries"])
        self.assertFalse(profile["ipv6"]["real_ipv6_path_verified"])
        self.assertEqual(profile["domain_fix"]["live_short_test"], "not_run")
        self.assertEqual(profile["domain_fix"]["user_isolated_short_test"],
                         "observed_outside_this_repository")
        self.assertFalse(profile["rollback_policy"]["implemented_in_this_repository"])
        self.assertTrue(all(value is False for value in profile["unverified_claims"].values()))
        text = m.dump_profile(profile)
        self.assertIsNone(m._UTUN_LITERAL.search(text))
        self.assertNotIn("/Users/", text)

    def test_checked_in_example_matches_the_builder(self):
        path = ROOT / "examples/macos-mihomo-coexist.experiment.json"
        self.assertEqual(path.read_text(encoding="utf-8"), m.dump_profile(m.build_experiment_profile()))
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(m.validate_experiment_profile(loaded), [])

    def test_system_dns_must_exist_on_the_observed_prefix(self):
        prefix = "198.18.0.1/30"
        self.assertEqual(m.system_dns_problems(prefix, "native", "198.18.0.2"), [])
        self.assertTrue(m.usable_tun_host(prefix, "198.18.0.1"))
        self.assertFalse(m.usable_tun_host(prefix, "198.18.0.0"))
        self.assertFalse(m.usable_tun_host(prefix, "198.18.0.3"))
        self.assertFalse(m.usable_tun_host(prefix, "198.18.0.5"))
        for mode, address in (
            ("native", "198.18.0.5"),
            ("native", "198.18.0.1"),
            ("native", None),
            ("disabled", "198.18.0.2"),
            ("redirect", "198.18.0.2"),
        ):
            self.assertTrue(m.system_dns_problems(prefix, mode, address), (mode, address))
        self.assertEqual(m.system_dns_problems(prefix, "disabled", None), [])
        self.assertTrue(m.system_dns_problems("10.0.0.0/8", "native", "198.18.0.2"))

    def test_linux_template_is_not_modified_by_this_profile(self):
        text = (ROOT / "config.yaml").read_text(encoding="utf-8")
        for suffix in m.OVERSEAS_DOMAIN_SUFFIXES:
            self.assertNotIn(suffix, text)
        module = (ROOT / "scripts/macos_coexist.py").read_text(encoding="utf-8")
        self.assertNotIn("config.yaml", module)
        for banned in ("subprocess", "socket", "urllib", "paramiko"):
            self.assertNotRegex(module, rf"(?m)^\s*(import|from)\s+{banned}\b")
        for path in (ROOT / "scripts").glob("*.py"):
            if path.name == "macos_coexist.py":
                continue
            source = path.read_text(encoding="utf-8")
            if path.name == "macos_readonly.py":
                self.assertIn("import macos_coexist", source)
                continue
            self.assertNotIn("import macos_coexist", source)
            self.assertNotIn("macos_coexist.", source)

    def test_hardcoded_utun_literals_are_rejected(self):
        self.assertEqual(m.find_hardcoded_utun({"bind": "utun4"}), ["$.bind"])
        self.assertEqual(m.find_hardcoded_utun(["utun5"]), ["$[0]"])
        self.assertEqual(m.find_hardcoded_utun({"bind": "dynamic"}), [])


class TunProbeTests(unittest.TestCase):
    def test_completed_http_200_still_needs_an_app_check(self):
        result = m.classify_tun_sample(tun_sample(remote_ip="203.0.113.9"))
        other = m.classify_tun_sample(tun_sample(remote_ip="198.51.100.9"))
        self.assertEqual(result["classification"], "tun_network_ok_needs_app_confirm")
        self.assertEqual(other["classification"], result["classification"])
        self.assertTrue(result["transfer_complete"])
        self.assertFalse(result["app_confirmed"])
        self.assertFalse(result["whole_network_critical"])
        self.assertFalse(result["remote_ip_decides_fake_site"])
        self.assertEqual(result["tls_status"], "valid")
        self.assertEqual(result["http_application"], "2xx")
        self.assertFalse(result["legacy_blanket_review"])
        self.assertTrue(result["fully_ok"])
        self.assertEqual(result["notes"], [])
        self.assertNotEqual(result["classification"], "needs_manual_tls_review")

    def test_rc_28_with_success_status_and_valid_tls_is_incomplete(self):
        result = m.classify_tun_sample(tun_sample(label="tun-chatgpt", rc=28, http_status=200))
        self.assertEqual(result["classification"],
                         "tun_network_incomplete_transfer_needs_app_confirm")
        self.assertFalse(result["transfer_complete"])
        self.assertFalse(result["app_confirmed"])
        self.assertFalse(result["whole_network_critical"])
        self.assertEqual(result["tls_status"], "valid")
        self.assertEqual(result["http_application"], "2xx")
        self.assertFalse(result["fully_ok"])
        self.assertEqual(result["notes"], ["chatgpt_incomplete_transfer"])
        redirected = m.classify_tun_sample(tun_sample(rc=28, http_status=302))
        self.assertEqual(redirected["classification"], result["classification"])
        self.assertEqual(redirected["http_application"], "3xx")

    def test_tls_and_transport_failures_are_not_success(self):
        cases = (
            tun_sample(rc=28, http_status=200, tls_valid=False),
            tun_sample(rc=35, tls_valid=False),
            tun_sample(rc=60, tls_valid=None, http_status=None),
            tun_sample(rc=0, http_status=200, tls_valid=False),
            tun_sample(rc=7, http_status=None),
            tun_sample(rc=28, http_status=None),
        )
        for sample in cases:
            result = m.classify_tun_sample(sample)
            self.assertEqual(result["classification"], "tun_tls_or_transport_issues", sample["rc"])
            self.assertFalse(result["transfer_complete"])
            self.assertTrue(result["site_issue"])
            self.assertFalse(result["whole_network_critical"])
            self.assertFalse(result["legacy_blanket_review"])

    def test_missing_tls_evidence_is_not_the_old_blanket_label(self):
        result = m.classify_tun_sample(tun_sample(tls_valid=None))
        self.assertEqual(result["classification"], "tun_tls_evidence_missing")
        self.assertNotEqual(result["classification"], "needs_manual_tls_review")
        self.assertFalse(result["transfer_complete"])
        blocked = m.classify_tun_sample(tun_sample(route_ok=False, rc=0))
        self.assertEqual(blocked["classification"], "tun_route_or_dns_not_ready")
        self.assertFalse(blocked["whole_network_critical"])

    def test_single_site_statuses_and_control_flags_are_not_network_faults(self):
        for status in (401, 403, 404, 429, 503):
            result = m.classify_tun_sample(tun_sample(http_status=status))
            self.assertEqual(result["classification"], "tun_network_ok_needs_app_confirm", status)
            self.assertIn(f"http_{status}", result["non_faults"])
            self.assertFalse(result["whole_network_critical"])
            self.assertEqual(result["tls_status"], "valid")
            self.assertNotEqual(result["http_application"], "2xx")
        noisy = m.classify_tun_sample(tun_sample(
            aaaa_present=False, ping_ok=False,
            controls={"system_proxy_disabled": True, "local_7897_connection_refused": True}))
        quiet = m.classify_tun_sample(tun_sample(
            controls={"system_proxy_disabled": False, "local_7897_connection_refused": False}))
        self.assertEqual(noisy["classification"], quiet["classification"])
        self.assertFalse(noisy["controls_are_faults"])
        self.assertFalse(noisy["whole_network_critical"])
        for name in ("no_aaaa", "single_ping_failure", "system_proxy_disabled",
                     "local_7897_connection_refused"):
            self.assertIn(name, noisy["non_faults"])
        self.assertFalse(noisy["curl_reads_macos_system_proxy"])

    def test_contradictory_tls_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            m.classify_tun_sample(tun_sample(rc=35, tls_valid=True))
        with self.assertRaises(ValueError):
            m.classify_tun_sample(tun_sample(label="google"))


class DeadProxyTests(unittest.TestCase):
    def snapshot(self, enabled, listening):
        entry = {"enabled": enabled, "server": "127.0.0.1", "port": 7897}
        return {
            "http": dict(entry),
            "https": dict(entry),
            "socks": dict(entry),
            "bypass": ["<local>", "192.168.0.0/16"],
            "listener_open": {"127.0.0.1:7897": listening},
        }

    def test_enabled_closed_listener_warns_without_an_action(self):
        result = m.classify_system_proxies(self.snapshot("Yes", False))
        self.assertEqual([item["code"] for item in result["warnings"]],
                         ["dead_proxy", "dead_proxy", "dead_proxy"])
        self.assertEqual({item["protocol"] for item in result["warnings"]},
                         {"http", "https", "socks"})
        self.assertEqual(result["actions"], [])
        self.assertFalse(result["mutates_network"])
        self.assertFalse(result["restore_reenables_proxies"])
        self.assertFalse(result["curl_success_means_app_ok"])
        self.assertFalse(result["curl_success_means_overseas_direct"])
        self.assertNotIn("networksetup", json.dumps(result))

    def test_disabled_saved_address_and_bypass_are_not_faults(self):
        original = self.snapshot("No", False)
        snapshot = json.loads(json.dumps(original))
        result = m.classify_system_proxies(snapshot)
        self.assertEqual(snapshot, original)
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["bypass_retained"], ["<local>", "192.168.0.0/16"])
        self.assertEqual(
            {item["protocol"] for item in result["disabled_saved_addresses"]},
            {"http", "https", "socks"})
        self.assertFalse(result["disabled_saved_address_is_fault"])
        alive = m.classify_system_proxies(self.snapshot("Yes", True))
        self.assertEqual(alive["warnings"], [])
        unknown = self.snapshot("Yes", False)
        unknown["listener_open"] = {}
        codes = [item["code"] for item in m.classify_system_proxies(unknown)["warnings"]]
        self.assertEqual(codes, ["listener_unknown", "listener_unknown", "listener_unknown"])


class EvidenceBoundaryTests(unittest.TestCase):
    def test_measured_socks_window_does_not_pick_a_root_cause(self):
        window = m.MEASURED_SOCKS_WINDOW
        self.assertEqual(window["failure_count"], 29)
        self.assertEqual(window["network_unreachable"], 4)
        self.assertEqual(window["timeout"], 25)
        self.assertEqual(window["timeout_tcp"] + window["timeout_udp"], 25)
        self.assertEqual(window["auto_health_checks"], 5)
        self.assertFalse(window["sleep_or_wake"])
        self.assertFalse(window["tun_or_default_interface_change"])
        conclusion = m.bound_socks_window(window)
        self.assertEqual(conclusion["root_cause"], "undetermined")
        self.assertFalse(conclusion["claim_vps_process_crash"])
        self.assertFalse(conclusion["claim_dual_tun_conflict"])
        self.assertFalse(conclusion["both_ends_covered"])
        self.assertFalse(conclusion["ssh_used"])
        self.assertEqual(conclusion["needs"], [
            "route", "interface", "tailscale_state", "port_1080_timeline", "optional_vps_log"])
        marked = dict(window)
        marked["evidence"] = dict(window["evidence"], ssh=True)
        self.assertFalse(m.bound_socks_window(marked)["ssh_used"])

    def test_stronger_evidence_is_not_the_measured_window(self):
        crash = m.bound_socks_window({
            "tun_or_default_interface_change": False,
            "evidence": {
                "home_log": True,
                "vps_log": True,
                "vps_process_exit_observed": True,
                "mechanism_identified": False,
            },
        })
        self.assertTrue(crash["claim_vps_process_crash"])
        self.assertFalse(crash["claim_dual_tun_conflict"])
        self.assertTrue(crash["both_ends_covered"])
        changed = m.bound_socks_window({
            "tun_or_default_interface_change": True,
            "evidence": {"mechanism_identified": False},
        })
        self.assertFalse(changed["claim_dual_tun_conflict"])
        identified = m.bound_socks_window({
            "tun_or_default_interface_change": True,
            "evidence": {"mechanism_identified": True, "vps_log": False},
        })
        self.assertTrue(identified["claim_dual_tun_conflict"])
        self.assertFalse(identified["both_ends_covered"])

    def test_ipv6_mapping_and_missing_aaaa_are_not_a_passed_path(self):
        missing = m.assess_ipv6({"aaaa_present": False})
        self.assertFalse(missing["aaaa_absent_is_fault"])
        self.assertFalse(missing["real_ipv6_path_verified"])
        mapped = m.assess_ipv6({
            "aaaa_present": True, "curl6_rc": 0,
            "curl6_peer_is_v4_mapped": True, "peer_is_ipv6": False,
        })
        self.assertFalse(mapped["curl6_mapped_counts_as_ipv6"])
        self.assertFalse(mapped["real_ipv6_path_verified"])
        explicit = m.assess_ipv6({
            "aaaa_present": True, "curl6_rc": 0,
            "curl6_peer_is_v4_mapped": False, "peer_is_ipv6": True,
        })
        self.assertTrue(explicit["real_ipv6_path_verified"])
        self.assertFalse(m.UNVERIFIED_CLAIMS["real_ipv6_passed"])

    def test_rollback_policy_is_a_checklist_and_not_a_launcher(self):
        self.assertEqual(m.validate_rollback_policy(m.ROLLBACK_POLICY), [])
        self.assertFalse(m.ROLLBACK_POLICY["implemented_in_this_repository"])
        self.assertEqual(m.ROLLBACK_POLICY["short_test_minutes"], 10)
        self.assertEqual(m.ROLLBACK_POLICY["overnight_max_hours"], 8)
        self.assertFalse(m.ROLLBACK_POLICY["renew_deadline"])
        self.assertEqual(m.ROLLBACK_POLICY["consecutive_critical_failures_before_rollback"], 3)
        self.assertFalse(m.ROLLBACK_POLICY["guarantees_restore_if_watchdog_and_sampler_die"])
        self.assertFalse(m.WATCHDOG_UNHEALTHY_OBSERVATION["required_fix"])
        self.assertFalse(m.WATCHDOG_UNHEALTHY_OBSERVATION["logic_conflict_established"])
        for key, flipped in (
            ("implemented_in_this_repository", True),
            ("changes_system_proxy", True),
            ("changes_bypass", True),
            ("consecutive_critical_failures_before_rollback", 1),
            ("guarantees_restore_if_watchdog_and_sampler_die", True),
            ("requires_watchdog_unhealthy_logic_change", True),
        ):
            policy = dict(m.ROLLBACK_POLICY)
            policy[key] = flipped
            self.assertTrue(m.validate_rollback_policy(policy), key)
        extra = dict(m.ROLLBACK_POLICY)
        extra["install_daemon"] = True
        self.assertTrue(any("unknown" in item for item in m.validate_rollback_policy(extra)))

    def test_record_keeps_the_verification_boundary(self):
        text = (ROOT / "docs/macos-mihomo-tailscale.md").read_text(encoding="utf-8")
        for phrase in (
            "用户本机实测",
            "不自动启用",
            "不是生产稳定",
            "Linux Home",
            "Windows 延期",
            "198.18.0.1/30",
            "198.18.0.2",
            "100.64.0.0/10",
            "fd7a:115c:a1e0::/48",
            "127.0.0.1:7897",
            "Enabled No",
            "根因未定",
            "不能声称 VPS 进程崩溃",
            "不能声称双 TUN 冲突",
            "不启动 SSH",
            "真实 IPv6",
            "无 AAAA",
            "App 实际发送",
            "睡眠唤醒",
            "Linux CI 通过不能标成 macOS 运行通过",
            "本 PR 代码尚未在实机运行",
            "本仓库没有实验启动器",
            "用户隔离配置",
            "不是本 PR 的代码或安装包",
            "RESTORED",
            "12:14:30",
            "仓库实现尚未验证",
            "55/55",
            "2000",
            "23 秒",
            "mihomo -f",
            "python3 scripts/macos_coexist.py profile",
            "不构成必须修复",
            "不是用户机器的完整配置",
        ):
            self.assertIn(phrase, text, phrase)
        self.assertNotIn("/Users/", text)


def status_document(**overrides):
    document = {
        "BackendState": "Running",
        "Self": {"Online": True, "HostName": "hidden-host", "TailscaleIPs": ["100.64.0.2"]},
        "Peer": {
            "node-a": {"Online": True, "DNSName": "a.example.ts.net", "TailscaleIPs": ["100.64.0.3"]},
            "node-b": {"Online": False, "HostName": "other-host", "PublicKey": "secret-key"},
        },
    }
    document.update(overrides)
    return document


class TailscaleStatusTests(unittest.TestCase):
    def document_text(self, **overrides):
        body = status_document(**overrides)
        body["Padding"] = "x" * 2500
        return json.dumps(body)

    def test_complete_document_over_2000_bytes_keeps_only_the_whitelist(self):
        text = self.document_text()
        self.assertGreater(len(text), 2000)
        result = m.normalize_tailscale_status(text, returncode=0)
        self.assertEqual(result, {
            "availability": "healthy",
            "reason": None,
            "backend_state": "Running",
            "self_online": True,
            "peer_summary": "known",
            "peer_count": 2,
            "peers_online": 1,
        })
        rendered = json.dumps(result)
        for secret in ("hidden-host", "other-host", "a.example.ts.net", "100.64.0.2",
                       "100.64.0.3", "secret-key", "Padding"):
            self.assertNotIn(secret, rendered)
        self.assertLess(len(rendered), 500)

    def test_slice_invalid_json_and_failed_command_are_not_healthy(self):
        text = self.document_text()
        sliced = m.normalize_tailscale_status(text[:2000], returncode=0)
        self.assertEqual(sliced["availability"], "unavailable")
        self.assertEqual(sliced["reason"], "invalid_json")
        self.assertIsNone(sliced["backend_state"])
        self.assertIsNone(sliced["self_online"])
        self.assertEqual(sliced["peer_summary"], "unknown")
        declared = m.normalize_tailscale_status(text, returncode=0, truncated=True)
        self.assertEqual(declared["reason"], "pre_parse_truncation")
        self.assertNotEqual(declared["availability"], "healthy")
        failed = m.normalize_tailscale_status(text, returncode=1)
        self.assertEqual(failed["availability"], "unavailable")
        self.assertEqual(failed["reason"], "command_failed")
        self.assertIsNone(failed["backend_state"])
        missing = m.normalize_tailscale_status(
            json.dumps({"Self": {"Online": True, "HostName": "hidden-host"}, "Padding": "y" * 2500}),
            returncode=0)
        self.assertEqual(missing["availability"], "unknown")
        self.assertEqual(missing["reason"], "missing_field")
        self.assertIsNone(missing["backend_state"])
        self.assertTrue(missing["self_online"])
        self.assertNotEqual(missing["availability"], "offline")
        stopped = m.normalize_tailscale_status(
            json.dumps({"BackendState": "Stopped", "Self": {"Online": False}}), returncode=0)
        self.assertEqual(stopped["availability"], "offline")
        self.assertEqual(stopped["reason"], "not_running")
        huge = "x" * (m.TAILSCALE_STATUS_PARSE_LIMIT + 1)
        self.assertEqual(m.normalize_tailscale_status(huge, returncode=0)["reason"], "output_too_large")
        with self.assertRaises(ValueError):
            m.normalize_tailscale_status(text, returncode=0, limit=m.BROKEN_COLLECTOR_SLICE)
        self.assertNotIn("[:2000]", (ROOT / "scripts/macos_coexist.py").read_text(encoding="utf-8"))

    def test_offline_cli_prints_the_whitelist_and_refuses_unknown_commands(self):
        script = ROOT / "scripts/macos_coexist.py"
        profile = subprocess.run([sys.executable, str(script), "profile"],
                                 check=False, capture_output=True, text=True)
        self.assertEqual(profile.returncode, 0, profile.stderr)
        loaded = json.loads(profile.stdout)
        self.assertFalse(loaded["nmd_experiment"]["directly_loadable_by_mihomo"])
        self.assertFalse(m.mihomo_would_load(loaded))
        status = subprocess.run([sys.executable, str(script), "normalize-status", "--returncode", "0"],
                                input=self.document_text(), check=False, capture_output=True, text=True)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)["availability"], "healthy")
        self.assertNotIn("hidden-host", status.stdout)
        unknown = subprocess.run([sys.executable, str(script), "restore"],
                                 check=False, capture_output=True, text=True)
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("no cutover or restore command", unknown.stdout)
        self.assertEqual(
            [step["status"] for step in m.DEVELOPMENT_STEPS],
            ["in_this_pr", "wired", "wired", "not_in_product"],
        )
        self.assertEqual(m.DEVELOPMENT_STEPS[-1]["id"], "cutover-controller")
        self.assertEqual(m.DEVELOPMENT_STEPS[-1]["status"], "not_in_product")
        self.assertTrue(all(step["mutates_network"] is False for step in m.DEVELOPMENT_STEPS[:-1]))


class ProbeBatchTests(unittest.TestCase):
    def test_one_incomplete_transfer_keeps_the_batch_from_being_fully_ok(self):
        ok = m.classify_tun_sample(tun_sample(label="tun-baidu"))
        incomplete = m.classify_tun_sample(tun_sample(
            label="tun-chatgpt", rc=28, http_status=200))
        recovered = m.classify_tun_sample(tun_sample(label="tun-google"))
        batch = m.summarize_probe_batch([ok, incomplete, recovered])
        self.assertFalse(batch["fully_ok"])
        self.assertFalse(batch["critical"])
        self.assertEqual(batch["app_status"], "not_inferred")
        self.assertEqual(batch["notes"], ["chatgpt_incomplete_transfer"])
        self.assertEqual(batch["counts"]["tun_network_ok_needs_app_confirm"], 2)
        self.assertEqual(batch["counts"]["tun_network_incomplete_transfer_needs_app_confirm"], 1)
        wide = [ok] * 39 + [incomplete]
        summary = m.summarize_probe_batch(wide)
        self.assertEqual(summary["requests"], 40)
        self.assertFalse(summary["fully_ok"])
        self.assertFalse(summary["critical"])
        self.assertEqual(m.summarize_probe_batch([])["fully_ok"], False)

    def test_isolated_short_test_numbers_stay_outside_this_repository(self):
        observed = m.USER_ISOLATED_SHORT_TEST
        self.assertFalse(observed["this_repository_ran_it"])
        self.assertFalse(observed["repo_restore_implementation_verified"])
        self.assertEqual(observed["restore_mark"], "RESTORED")
        self.assertEqual(observed["restore_at"], "12:14:30")
        self.assertEqual(observed["restore_calls_in_deadline_second"], 2)
        self.assertTrue(observed["both_restore_calls_succeeded"])
        self.assertEqual(observed["tcp_1080_ok"], observed["tcp_1080_attempts"])
        self.assertEqual(sum(observed["suffix_hits"].values()), 55)
        self.assertEqual(observed["ws_geoip_direct_hits"], 0)
        self.assertEqual(observed["probe_ok"] + observed["probe_incomplete_transfer"], 40)
        self.assertEqual(observed["probe_transport_fail"], 0)
        self.assertEqual(observed["probe_critical"], 0)
        self.assertFalse(observed["overnight_23s_root_cause_fixed"])
        self.assertFalse(observed["vps_collection"])
        self.assertIn("2000", observed["tailscale_status_fields"])
        self.assertTrue(all(value is False for value in m.UNVERIFIED_CLAIMS.values()))
