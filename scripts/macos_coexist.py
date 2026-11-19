"""Opt-in checks for the experimental macOS mihomo + official Tailscale path.

The functions are pure: they do not start processes, open connections, read host
configuration, or change routes, DNS, Tailscale, or system proxies. Nothing in
the Linux gateway imports this module. The JSON profile is not a mihomo
config and is not auto-enabled.

Measured facts belong to the user's machine. See
docs/macos-mihomo-tailscale.md. This module does not rerun that machine.
"""

from __future__ import annotations

from collections.abc import Sequence
import ipaddress
import json
import re
import sys

EXPERIMENT_ID = "macos-mihomo-official-tailscale"
DEFAULT_EXIT_GROUP = "NMD-EXIT"
MIHOMO_VERSION_OBSERVED = "1.19.34"

# Domain rules go to the existing overseas group. They are not a new egress.
OVERSEAS_DOMAIN_SUFFIXES = (
    "chatgpt.com",
    "openai.com",
    "oaistatic.com",
    "oaiusercontent.com",
)

# Tailnet ranges excluded from the TUN. Interface names stay dynamic.
TAILNET_ROUTE_EXCLUSIONS = (
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
)

# Observed TUN prefix on the user machine. This is the interface prefix,
# not a fake-ip pool and not a license to invent another system DNS address.
OBSERVED_TUN_ADDRESS = "198.18.0.1/30"
NATIVE_SYSTEM_DNS = "198.18.0.2"

# RFC 5737 documentation address. Not an endpoint from the user machine.
PLACEHOLDER_SOCKS_HOST = "203.0.113.20"
PLACEHOLDER_SOCKS_PORT = 1080

DOMESTIC_RULE_MARKERS = ("GEOSITE,cn,", "GEOIP,CN,")
IP_OR_GEO_KINDS = {"IP-CIDR", "IP-CIDR6", "GEOIP", "GEOSITE"}
SINGLE_SITE_HTTP_NON_CRITICAL = {401, 403, 404, 429, 503}
CURL_TLS_RC = {35, 60}
_UTUN_LITERAL = re.compile(r"utun\d+")
_EXIT_GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
_PROXY_PROTOCOLS = ("http", "https", "socks")

# Structural stand-in for the order described with the two direct misses.
# It is not a copy of the machine config. Intranet CIDRs stand in for the
# direct rules that sat between GEOSITE,cn and GEOIP,CN. GEOIP,CN stays
# without no-resolve; the domain rules are the fix, not an IP-rule edit.
STRUCTURAL_RULES_BEFORE_DOMAIN_FIX = (
    "GEOSITE,cn,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "GEOIP,CN,DIRECT",
    "MATCH,NMD-EXIT",
)

# Claims this repository must not upgrade to "passed on macOS".
UNVERIFIED_CLAIMS = {
    "rerun_by_repository_ci": False,
    "macos_runtime_passed_in_this_change": False,
    "real_ipv6_passed": False,
    "socks_1080_root_cause_known": False,
    "vps_process_crash": False,
    "dual_tun_conflict": False,
    "both_ends_logged": False,
    "ssh_used": False,
    "domain_fix_live_short_test": False,
    "app_send_path_verified": False,
    "sleep_wake_verified": False,
    "rollback_after_short_test_verified": False,
    "watchdog_unhealthy_required_fix": False,
    "pr_code_ran_on_real_machine": False,
    "repo_restore_verified": False,
    "overnight_23s_root_cause_fixed": False,
    "tailscale_status_series_recovered": False,
    "vps_log_collected": False,
}

# Numbers from the user's isolated 10-minute run. They are not results of this
# repository's code. Host names, addresses and the machine path stay out.
USER_ISOLATED_SHORT_TEST = {
    "scope": "user_isolated_config",
    "this_repository_ran_it": False,
    "date": "2026-11-17",
    "timezone": "Asia/Shanghai",
    "watchdog_start": "12:04:28",
    "mihomo_start": "12:04:29",
    "deadline": "12:14:28",
    "restore_rc": 0,
    "restore_mark": "RESTORED",
    "restore_at": "12:14:30",
    "post_check_at": "12:17:43",
    "test_processes_remaining": False,
    "experimental_tun_left": False,
    "scutil_198_18_left": False,
    "system_proxies_left_enabled": False,
    "official_tailscale_default_route": True,
    "exit_allow_lan_corpdns_restored": True,
    "restore_calls_in_deadline_second": 2,
    "both_restore_calls_succeeded": True,
    "repo_restore_implementation_verified": False,
    "tcp_1080_attempts": 55,
    "tcp_1080_ok": 55,
    "tcp_1080_ms_min": 75,
    "tcp_1080_ms_max": 164,
    "suffix_hits": {"chatgpt": 42, "openai": 8, "oaiusercontent": 3, "oaistatic": 2},
    "ws_proxy_hits": 7,
    "ws_geoip_direct_hits": 0,
    "warnings": 2,
    "errors": 0,
    "probe_rounds": 10,
    "probe_requests": 40,
    "probe_ok": 39,
    "probe_incomplete_transfer": 1,
    "probe_transport_fail": 0,
    "probe_critical": 0,
    "user_confirmed_apps_and_web_at": "12:07",
    "tailscale_status_samples": 55,
    "tailscale_status_fields": "unavailable_after_2000_byte_slice",
    "vps_collection": False,
    "overnight_23s_reproduced": False,
    "overnight_23s_root_cause_fixed": False,
}

# Later macOS work starts at the pure checks. Nothing here turns a network on.
DEVELOPMENT_STEPS = (
    {"id": "pure-checks", "status": "in_this_pr", "mutates_network": False},
    {"id": "read-only-status-adapter", "status": "wired", "mutates_network": False},
    {"id": "opt-in-macos-sample", "status": "wired", "mutates_network": False},
    {"id": "config-and-snapshot", "status": "in_this_pr", "mutates_network": False},
    {"id": "cutover-controller", "status": "in_this_pr", "mutates_network": True},
    {"id": "persistent-daemon", "status": "in_this_pr", "mutates_network": True},
)

# Parse bound for a complete status document. The isolated collector sliced at
# 2000 bytes before parsing; this module rejects that limit instead of copying it.
BROKEN_COLLECTOR_SLICE = 2000
TAILSCALE_STATUS_PARSE_LIMIT = 1024 * 1024
_STATUS_KEYS = (
    "availability", "reason", "backend_state", "self_online",
    "peer_summary", "peer_count", "peers_online",
)

# One observed window. Root cause stays open; do not fill it in.
MEASURED_SOCKS_WINDOW = {
    "date": "2026-11-17",
    "timezone": "Asia/Shanghai",
    "start": "04:06:50.261",
    "end": "04:07:13.720",
    "port": 1080,
    "transport": "socks5-over-tailnet",
    "failure_count": 29,
    "network_unreachable": 4,
    "timeout": 25,
    "timeout_tcp": 21,
    "timeout_udp": 4,
    "auto_health_checks": 5,
    "success_before": "04:06:40.685",
    "success_after": "04:07:15.272",
    "sleep_or_wake": False,
    "tun_or_default_interface_change": False,
    "evidence": {
        "home_log": True,
        "vps_log": False,
        "vps_process_exit_observed": False,
        "mechanism_identified": False,
    },
}

# Policy text for a future isolated tool. This repository does not run it.
ROLLBACK_POLICY = {
    "snapshot_before_start": True,
    "watchdog_alive_before_cutover": True,
    "short_test_minutes": 10,
    "overnight_max_hours": 8,
    "renew_deadline": False,
    "stop_or_deadline_restores": True,
    "kills_only_own_processes": True,
    "confirm_scutil_has_no_198_18_after_native_cleanup": True,
    "restores_tailscale_exit_allow_lan_accept_dns": True,
    "restores_nic_dns": True,
    "changes_system_proxy": False,
    "changes_bypass": False,
    "consecutive_critical_failures_before_rollback": 3,
    "self_heal_loop": False,
    "installs_daemon_or_autostart": False,
    "changes_power_management": False,
    "sleep_wake_keeps_absolute_deadline": True,
    # Wake re-reads managed state and restores when it is wrong. CI injects
    # the clocks; sleep_wake_verified stays false until a real Mac sleeps.
    "sleep_wake_revalidates_or_restores": True,
    # The accept sentinel is another process. It is not a hard guarantee,
    # and this checklist must not say that it is.
    "guarantees_restore_if_watchdog_dies": False,
    "guarantees_restore_if_watchdog_and_sampler_die": False,
    "requires_watchdog_unhealthy_logic_change": False,
    "implemented_in_this_repository": True,
}

# Phase C persistent-daemon policy: the daemon replaces the one-shot absolute
# deadline with continuous supervision. The one-shot ROLLBACK_POLICY above keeps
# describing `sudo nmd macos takeover` sessions exactly as before.
DAEMON_POLICY = {
    "absolute_deadline": False,
    "snapshot_before_every_start_including_boot": True,
    "never_restores_from_a_previous_session_snapshot": True,
    "stop_restores": True,
    "health_rollback_consecutive_critical_failures": 3,
    "auto_retry_after_rollback": False,
    "takeover_on_boot_default": False,
    "same_boot_keepalive_restart_never_resumes": True,
    "supervisor_keepalive_recovers_leftovers": True,
    "mihomo_exit_restores_immediately": True,
    "kills_only_own_processes": True,
    "confirm_scutil_has_no_198_18_after_native_cleanup": True,
    "restores_tailscale_exit_allow_lan_accept_dns": True,
    "restores_nic_dns": True,
    "changes_system_proxy": False,
    "changes_bypass": False,
    "changes_power_management": False,
    "sleep_wake_revalidates_or_restores": True,
    # A wake never starts a takeover and never flips on_boot.
    "wake_does_not_start_takeover": True,
    "panel_may_start_takeover": False,
    "requires_explicit_install": True,
    # An unfinished restore is retried. A finished one does not start again.
    "retries_incomplete_rollback": True,
    "vps_tcp_is_critical_health_check": True,
    "independent_rollback_stops_recorded_mihomo": True,
    "startup_validation_confined_to_workdir": True,
    "implemented_in_this_repository": True,
}

WATCHDOG_UNHEALTHY_OBSERVATION = {
    "count": "1/3",
    "heartbeat_seconds": 8,
    "check_seconds": 20,
    "logic_conflict_established": False,
    "root_cause": "undetermined",
    "required_fix": False,
}


def _exit_group(value: str) -> str:
    if not isinstance(value, str) or not _EXIT_GROUP.fullmatch(value):
        raise ValueError("exit group must be a short token")
    if value in {"DIRECT", "REJECT"}:
        raise ValueError("overseas domains must use the existing exit group")
    return value


def _split_rule(rule: str) -> list[str]:
    if not isinstance(rule, str) or not rule or rule != rule.strip():
        raise ValueError("rule must be a single trimmed line")
    parts = rule.split(",")
    if len(parts) < 2 or any(part == "" for part in parts):
        raise ValueError("malformed rule")
    return parts


def _normalize_host(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("host must be a string")
    host = value.strip().rstrip(".").lower()
    if not host or "://" in host or "/" in host or " " in host:
        raise ValueError("host must be a domain name")
    return host


def domain_suffix_matches(suffix: str, host: str) -> bool:
    """DOMAIN-SUFFIX semantics: the apex and its subdomains, not a prefix."""
    host_name = _normalize_host(host)
    suffix_name = _normalize_host(suffix)
    return host_name == suffix_name or host_name.endswith("." + suffix_name)


def overseas_domain_rules(exit_group: str) -> list[str]:
    group = _exit_group(exit_group)
    return [f"DOMAIN-SUFFIX,{suffix},{group}" for suffix in OVERSEAS_DOMAIN_SUFFIXES]


def _overseas_suffix(rule: str) -> str | None:
    parts = _split_rule(rule)
    if parts[0] == "DOMAIN-SUFFIX" and parts[1] in OVERSEAS_DOMAIN_SUFFIXES:
        return parts[1]
    return None


def _domestic(rule: str) -> bool:
    return rule.startswith(DOMESTIC_RULE_MARKERS)


def insert_overseas_domain_rules(rules: list[str], exit_group: str) -> list[str]:
    """Place the four DOMAIN-SUFFIX lines immediately before domestic geo rules.

    IP-CIDR, GEOIP, and GEOSITE lines are copied unchanged. A suffix that
    already targets another policy is an error, not a silent rewrite.
    """
    group = _exit_group(exit_group)
    if isinstance(rules, str) or not isinstance(rules, Sequence):
        raise ValueError("rules must be a list of strings")
    if any(not isinstance(rule, str) for rule in rules):
        raise ValueError("rules must be a list of strings")
    wanted = overseas_domain_rules(group)
    kept: list[str] = []
    for rule in rules:
        suffix = _overseas_suffix(rule)
        if suffix is None:
            kept.append(rule)
            continue
        target = _split_rule(rule)[2]
        if target != group:
            raise ValueError("overseas domain suffix targets a different policy")
    anchors = [index for index, rule in enumerate(kept) if _domestic(rule)]
    if not anchors:
        raise ValueError("missing domestic geosite/geoip anchor")
    pivot = min(anchors)
    return kept[:pivot] + wanted + kept[pivot:]


def ip_and_geo_rules(rules: list[str]) -> list[str]:
    return [rule for rule in rules if _split_rule(rule)[0] in IP_OR_GEO_KINDS]


def validate_rule_order(rules: list[str], exit_group: str) -> list[str]:
    """Static order check. Empty means the four suffixes win before CN geo rules."""
    group = _exit_group(exit_group)
    if isinstance(rules, str) or not isinstance(rules, Sequence):
        return ["rules must be a list"]
    errors: list[str] = []
    try:
        domestic_at = [index for index, rule in enumerate(rules) if _domestic(rule)]
    except ValueError as exc:
        return [str(exc)]
    if not any(rules[index].startswith("GEOSITE,cn,") for index in domestic_at):
        errors.append("missing GEOSITE,cn")
    if not any(rules[index].startswith("GEOIP,CN,") for index in domestic_at):
        errors.append("missing GEOIP,CN")
    first_domestic = min(domestic_at) if domestic_at else None
    for suffix in OVERSEAS_DOMAIN_SUFFIXES:
        expected = f"DOMAIN-SUFFIX,{suffix},{group}"
        hits = [index for index, rule in enumerate(rules) if rule == expected]
        if len(hits) != 1:
            errors.append(f"{suffix} must appear once as DOMAIN-SUFFIX to {group}")
            continue
        if first_domestic is not None and hits[0] >= first_domestic:
            errors.append(f"{suffix} is not before domestic geosite/geoip")
    for rule in rules:
        try:
            parts = _split_rule(rule)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if parts[0] in {"GEOIP", "GEOSITE"} and (len(parts) < 3 or parts[2] != "DIRECT"):
            errors.append("geo rules must stay DIRECT")
        if parts[0] in {"IP-CIDR", "IP-CIDR6"} and len(parts) >= 3 and parts[2] == group:
            errors.append("ip rules must not be retargeted at the exit group")
    return errors


def match_rule(rules: list[str], host: str, ip: str | None = None,
               geosite_cn: tuple[str, ...] | list[str] = (),
               geoip_cn_ips: tuple[str, ...] | list[str] = ()) -> str | None:
    """Walk rules in order. Geo sets are fixtures, not a GeoIP or GeoSite database."""
    host_name = _normalize_host(host)
    address = ipaddress.ip_address(ip) if ip is not None else None
    cn_names = {_normalize_host(item) for item in geosite_cn}
    cn_ips = {ipaddress.ip_address(item) for item in geoip_cn_ips}
    for rule in rules:
        parts = _split_rule(rule)
        kind, value = parts[0], parts[1]
        if kind == "DOMAIN-SUFFIX" and domain_suffix_matches(value, host_name):
            return rule
        if kind == "DOMAIN" and _normalize_host(value) == host_name:
            return rule
        if kind == "GEOSITE" and value == "cn" and any(
                domain_suffix_matches(name, host_name) for name in cn_names):
            return rule
        if kind in {"IP-CIDR", "IP-CIDR6"} and address is not None:
            if address in ipaddress.ip_network(value, strict=False):
                return rule
        if kind == "GEOIP" and value == "CN" and address is not None and address in cn_ips:
            return rule
        if kind == "GEOIP" and value == "private" and address is not None and address.is_private:
            return rule
        if kind == "MATCH":
            return rule
    return None


def usable_tun_host(prefix: str, address: str) -> bool:
    """True when address is a host inside prefix, excluding network and broadcast."""
    network = ipaddress.ip_network(prefix, strict=False)
    ip = ipaddress.ip_address(address)
    if ip not in network:
        return False
    if network.prefixlen < network.max_prefixlen:
        if ip == network.network_address or ip == network.broadcast_address:
            return False
    return True


def system_dns_problems(prefix: str, mode: str, system_dns: str | None) -> list[str]:
    """disabled does not install a system resolver; native only accepts 198.18.0.2."""
    if mode == "disabled":
        if system_dns:
            return ["disabled dns-mode does not take over system DNS"]
        return []
    if mode != "native":
        return ["dns-mode must be native or disabled"]
    if not system_dns:
        return ["native system DNS must be 198.18.0.2 on the observed TUN prefix"]
    try:
        exists = usable_tun_host(prefix, system_dns)
    except (TypeError, ValueError):
        return ["system DNS is not a host on the observed TUN prefix"]
    if not exists:
        return ["system DNS is not a host on the observed TUN prefix"]
    if system_dns != NATIVE_SYSTEM_DNS:
        return ["native system DNS must be 198.18.0.2"]
    return []


def _tls_status(value: bool | None) -> str:
    if value is True:
        return "valid"
    if value is False:
        return "invalid"
    return "unknown"


def _http_application(status: int | None) -> str:
    if status is None:
        return "absent"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if status in {401, 403, 404}:
        return "client_status"
    if status == 429:
        return "rate_limited"
    if status == 503:
        return "unavailable"
    return "other"


def _require_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be bool")
    return value


def classify_tun_sample(sample: dict) -> dict:
    """Classify one tun- probe from its own results.

    route/DNS success no longer collapses to a blanket manual TLS review.
    rc other than 0 is not a completed transfer. rc 28 with a 2xx/3xx status
    and a valid TLS result is an incomplete transfer. TLS validity and the
    HTTP status stay separate fields. One site, a missing AAAA record, or one
    ping failure does not become a whole-network critical fault. remote_ip is
    recorded and is not a fake-site verdict. Control flags are not faults.
    """
    if not isinstance(sample, dict):
        raise ValueError("sample must be a dict")
    label = sample.get("label")
    if not isinstance(label, str) or not label.startswith("tun-"):
        raise ValueError("tun sample label must start with tun-")
    route_ok = _require_bool(sample.get("route_ok"), "route_ok")
    dns_ok = _require_bool(sample.get("dns_ok"), "dns_ok")
    controls = sample.get("controls") or {}
    if not isinstance(controls, dict):
        raise ValueError("controls must be a dict")
    for key in ("system_proxy_disabled", "local_7897_connection_refused"):
        if key in controls:
            _require_bool(controls[key], key)
    http_status = sample.get("http_status")
    if http_status is not None and (isinstance(http_status, bool) or not isinstance(http_status, int)):
        raise ValueError("http_status must be an int")
    tls_valid = sample.get("tls_valid", None)
    if tls_valid is not None and not isinstance(tls_valid, bool):
        raise ValueError("tls_valid must be bool or absent")
    non_faults: list[str] = []
    if sample.get("aaaa_present") is False:
        non_faults.append("no_aaaa")
    if sample.get("ping_ok") is False:
        non_faults.append("single_ping_failure")
    for key in ("system_proxy_disabled", "local_7897_connection_refused"):
        if controls.get(key) is True:
            non_faults.append(key)
    if http_status in SINGLE_SITE_HTTP_NON_CRITICAL:
        non_faults.append(f"http_{http_status}")
    result = {
        "label": label,
        "classification": "",
        "transfer_complete": False,
        "app_confirmed": False,
        "whole_network_critical": False,
        "site_issue": False,
        "tls_status": _tls_status(tls_valid),
        "http_application": _http_application(http_status),
        "http_status": http_status,
        "remote_ip": sample.get("remote_ip"),
        "remote_ip_decides_fake_site": False,
        "controls_are_faults": False,
        "non_faults": non_faults,
        "curl_reads_macos_system_proxy": False,
        "legacy_blanket_review": False,
        "fully_ok": False,
        "notes": [],
    }
    if not route_ok or not dns_ok:
        result["classification"] = "tun_route_or_dns_not_ready"
        result["site_issue"] = True
        return result
    rc = sample.get("rc")
    if isinstance(rc, bool) or not isinstance(rc, int):
        raise ValueError("rc must be an int once route and dns pass")
    if rc in CURL_TLS_RC and tls_valid is True:
        raise ValueError("rc reports TLS failure while tls_valid is true")
    if tls_valid is False or rc in CURL_TLS_RC:
        result["classification"] = "tun_tls_or_transport_issues"
        result["site_issue"] = True
        return result
    if tls_valid is None:
        result["classification"] = "tun_tls_evidence_missing"
        result["site_issue"] = True
        return result
    if rc == 28 and http_status is not None and 200 <= http_status < 400:
        result["classification"] = "tun_network_incomplete_transfer_needs_app_confirm"
        result["notes"] = [label.removeprefix("tun-") + "_incomplete_transfer"]
        return result
    if rc != 0:
        result["classification"] = "tun_tls_or_transport_issues"
        result["site_issue"] = True
        return result
    result["classification"] = "tun_network_ok_needs_app_confirm"
    result["transfer_complete"] = True
    result["fully_ok"] = True
    return result


def _enabled_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"yes", "true", "1"}:
        return True
    if isinstance(value, str) and value.strip().lower() in {"no", "false", "0"}:
        return False
    raise ValueError("enabled must be yes or no")


def classify_system_proxies(snapshot: dict) -> dict:
    """Read-only dead-proxy warning.

    An enabled proxy whose listener is closed is a warning. A saved address
    with Enabled No is not a fault. Bypass entries are retained and are not
    faults. The result has no enable, disable, or restore action.
    """
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be a dict")
    listeners = snapshot.get("listener_open") or {}
    if not isinstance(listeners, dict):
        raise ValueError("listener_open must be a dict")
    bypass = snapshot.get("bypass") or []
    if not isinstance(bypass, list):
        raise ValueError("bypass must be a list")
    warnings: list[dict] = []
    saved_disabled: list[dict] = []
    for protocol in _PROXY_PROTOCOLS:
        item = snapshot.get(protocol) or {}
        if not isinstance(item, dict):
            raise ValueError("proxy entry must be a dict")
        if not item:
            continue
        enabled = _enabled_flag(item.get("enabled", "No"))
        server = item.get("server")
        port = item.get("port")
        endpoint = None if server is None or port is None else f"{server}:{port}"
        if not enabled:
            if endpoint is not None:
                saved_disabled.append({"protocol": protocol, "endpoint": endpoint})
            continue
        if endpoint is None or listeners.get(endpoint) is False:
            warnings.append({
                "code": "dead_proxy",
                "protocol": protocol,
                "endpoint": endpoint,
                "read_only": True,
            })
        elif listeners.get(endpoint) is not True:
            warnings.append({
                "code": "listener_unknown",
                "protocol": protocol,
                "endpoint": endpoint,
                "read_only": True,
            })
    return {
        "warnings": warnings,
        "actions": [],
        "bypass_retained": list(bypass),
        "disabled_saved_addresses": saved_disabled,
        "disabled_saved_address_is_fault": False,
        "restore_reenables_proxies": False,
        "mutates_network": False,
        "curl_reads_macos_system_proxy": False,
        "curl_success_means_app_ok": False,
        "curl_success_means_overseas_direct": False,
    }


def assess_ipv6(observation: dict) -> dict:
    """A missing AAAA record is not a fault. An IPv4-mapped curl -6 is not IPv6."""
    if not isinstance(observation, dict):
        raise ValueError("observation must be a dict")
    verified = (
        observation.get("aaaa_present") is True
        and observation.get("curl6_rc") == 0
        and observation.get("curl6_peer_is_v4_mapped") is False
        and observation.get("peer_is_ipv6") is True
    )
    return {
        "aaaa_absent_is_fault": False,
        "curl6_mapped_counts_as_ipv6": False,
        "real_ipv6_path_verified": verified,
    }


def bound_socks_window(window: dict) -> dict:
    """State only what the window evidence supports. SSH is never part of this."""
    if not isinstance(window, dict):
        raise ValueError("window must be a dict")
    evidence = window.get("evidence") or {}
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a dict")
    crash = evidence.get("vps_process_exit_observed") is True and evidence.get("vps_log") is True
    dual = (
        window.get("tun_or_default_interface_change") is True
        and evidence.get("mechanism_identified") is True
    )
    both_ends = evidence.get("home_log") is True and evidence.get("vps_log") is True
    return {
        "root_cause": "undetermined" if not crash and not dual else "constrained_by_evidence",
        "claim_vps_process_crash": crash,
        "claim_dual_tun_conflict": dual,
        "both_ends_covered": both_ends,
        "ssh_used": False,
        "needs": [
            "route",
            "interface",
            "tailscale_state",
            "port_1080_timeline",
            "optional_vps_log",
        ],
    }


def validate_rollback_policy(policy: dict) -> list[str]:
    """Check the written policy. This does not snapshot, start, or restore."""
    if not isinstance(policy, dict):
        return ["policy must be a dict"]
    errors = [f"missing {key}" for key in ROLLBACK_POLICY if key not in policy]
    for key, expected in ROLLBACK_POLICY.items():
        if key in policy and policy[key] != expected:
            errors.append(f"{key} must be {expected!r}")
    unknown = sorted(set(policy) - set(ROLLBACK_POLICY))
    errors.extend(f"unknown policy key {key}" for key in unknown)
    return errors


def validate_daemon_policy(policy: dict) -> list[str]:
    """Check the persistent-daemon policy; same static rules, no execution."""
    if not isinstance(policy, dict):
        return ["policy must be a dict"]
    errors = [f"missing {key}" for key in DAEMON_POLICY if key not in policy]
    for key, expected in DAEMON_POLICY.items():
        if key in policy and policy[key] != expected:
            errors.append(f"{key} must be {expected!r}")
    unknown = sorted(set(policy) - set(DAEMON_POLICY))
    errors.extend(f"unknown policy key {key}" for key in unknown)
    return errors


def _documentation_server(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(network) for network in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def find_hardcoded_utun(value: object, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if _UTUN_LITERAL.search(value):
            found.append(path)
        return found
    if isinstance(value, dict):
        for key, item in value.items():
            found.extend(find_hardcoded_utun(item, f"{path}.{key}"))
        return found
    if isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(find_hardcoded_utun(item, f"{path}[{index}]"))
    return found


def validate_experiment_profile(profile: dict) -> list[str]:
    """Static checks for the wrapper profile. No process and no network."""
    if not isinstance(profile, dict):
        return ["profile must be a dict"]
    errors: list[str] = []
    meta = profile.get("nmd_experiment")
    if not isinstance(meta, dict):
        return ["missing nmd_experiment wrapper"]
    expected_meta = {
        "id": EXPERIMENT_ID,
        "platform": "macos",
        "status": "experimental",
        "auto_enable": False,
        "production_stable": False,
        "linux_home_default_unchanged": True,
        "windows": "deferred",
        "mihomo_version_observed": MIHOMO_VERSION_OBSERVED,
        "evidence": "user-machine-summary",
        "directly_loadable_by_mihomo": False,
        "starts_processes": False,
        "mutates_network": False,
    }
    for key, expected in expected_meta.items():
        if meta.get(key) != expected:
            errors.append(f"nmd_experiment.{key} must be {expected!r}")
    egress = profile.get("egress")
    if not isinstance(egress, dict):
        errors.append("missing egress")
    else:
        if egress.get("kind") != "socks5-over-tailnet":
            errors.append("egress must be socks5 over tailnet")
        if egress.get("tailscale_exit_node") is not False:
            errors.append("tailscale exit node must stay off")
        if egress.get("interface_discovery") != "dynamic":
            errors.append("tailnet interface must be discovered dynamically")
        if "interface-name" in egress or "device" in egress:
            errors.append("egress must not name a tun device")
        if egress.get("server_placeholder") is not True or not _documentation_server(str(egress.get("server"))):
            errors.append("server must stay a documentation placeholder")
        if egress.get("port") != PLACEHOLDER_SOCKS_PORT:
            errors.append("placeholder port must stay 1080")
        group = egress.get("group")
        rules = profile.get("rules")
        if isinstance(group, str) and isinstance(rules, list):
            errors.extend(validate_rule_order(rules, group))
            match_targets = []
            for rule in rules:
                try:
                    parts = _split_rule(rule)
                except ValueError:
                    continue
                if parts[0] == "MATCH":
                    match_targets.append(parts[1])
            if match_targets != [group]:
                errors.append("MATCH must target the same existing exit group")
        else:
            errors.append("rules must be checked against the egress group")
    tun = profile.get("tun")
    if not isinstance(tun, dict):
        errors.append("missing tun")
    else:
        excludes = tun.get("route_exclude_address")
        if list(excludes or []) != list(TAILNET_ROUTE_EXCLUSIONS):
            errors.append("tun must exclude the two tailnet prefixes")
        if tun.get("observed_address") != OBSERVED_TUN_ADDRESS:
            errors.append("observed tun prefix must stay 198.18.0.1/30")
        if tun.get("auto_detect_interface") is not True:
            errors.append("interface detection must stay dynamic")
    dns_mode = profile.get("dns_mode")
    if not isinstance(dns_mode, dict):
        errors.append("missing dns_mode")
    else:
        errors.extend(system_dns_problems(
            str(dns_mode.get("observed_tun_prefix")),
            str(dns_mode.get("selected")),
            dns_mode.get("system_dns"),
        ))
        if dns_mode.get("disabled_takes_over_system_dns") is not False:
            errors.append("disabled dns-mode must not be described as taking over system DNS")
        if dns_mode.get("native_scutil_order") != 1:
            errors.append("native resolver order must stay 1")
        if dns_mode.get("resolv_conf_sufficient") is not False:
            errors.append("resolv.conf alone cannot decide the resolver")
        if dns_mode.get("scoped_dns_covers_all_queries") is not False:
            errors.append("scoped DNS does not cover every query")
        if dns_mode.get("magic_dns_direct_retained") is not True:
            errors.append("MagicDNS direct reachability stays on")
        if dns_mode.get("domestic_direct_retained") is not True:
            errors.append("domestic direct must stay on")
    ipv6 = profile.get("ipv6")
    if not isinstance(ipv6, dict) or ipv6.get("real_ipv6_path_verified") is not False:
        errors.append("this profile must not claim a real IPv6 path")
    elif ipv6.get("aaaa_absent_is_fault") is not False or ipv6.get("curl6_may_be_v4_mapped") is not True:
        errors.append("IPv6 limits must stay explicit")
    domain_fix = profile.get("domain_fix")
    if not isinstance(domain_fix, dict):
        errors.append("missing domain_fix")
    elif domain_fix.get("live_short_test") != "not_run":
        errors.append("this profile's live short test has not run")
    elif domain_fix.get("user_isolated_short_test") != "observed_outside_this_repository":
        errors.append("user isolated short test must stay outside this repository")
    elif domain_fix.get("isolated_mihomo_check_on_user_machine") != "passed_not_rerun_here":
        errors.append("isolated mihomo check must stay marked as not rerun here")
    errors.extend(f"hardcoded tun interface at {item}" for item in find_hardcoded_utun(profile))
    errors.extend(validate_rollback_policy(profile.get("rollback_policy")))
    if profile.get("unverified_claims") != UNVERIFIED_CLAIMS:
        errors.append("unverified claims must stay false")
    return errors


def build_experiment_profile(rules: list[str] | None = None,
                             exit_group: str = DEFAULT_EXIT_GROUP) -> dict:
    """Build the reviewable JSON wrapper. It does not load or start mihomo."""
    group = _exit_group(exit_group)
    base_rules = list(STRUCTURAL_RULES_BEFORE_DOMAIN_FIX if rules is None else rules)
    updated = insert_overseas_domain_rules(base_rules, group)
    profile = {
        "nmd_experiment": {
            "id": EXPERIMENT_ID,
            "platform": "macos",
            "status": "experimental",
            "auto_enable": False,
            "production_stable": False,
            "linux_home_default_unchanged": True,
            "windows": "deferred",
            "mihomo_version_observed": MIHOMO_VERSION_OBSERVED,
            "evidence": "user-machine-summary",
            "directly_loadable_by_mihomo": False,
            "starts_processes": False,
            "mutates_network": False,
        },
        "egress": {
            "kind": "socks5-over-tailnet",
            "tailscale_exit_node": False,
            "group": group,
            "server_placeholder": True,
            "server": PLACEHOLDER_SOCKS_HOST,
            "port": PLACEHOLDER_SOCKS_PORT,
            "interface_discovery": "dynamic",
        },
        "tun": {
            "enable": True,
            "auto_route": True,
            "auto_detect_interface": True,
            "observed_address": OBSERVED_TUN_ADDRESS,
            "route_exclude_address": list(TAILNET_ROUTE_EXCLUSIONS),
        },
        "dns_mode": {
            "field": "tun.dns-mode",
            "selected": "native",
            "disabled_takes_over_system_dns": False,
            "system_dns": NATIVE_SYSTEM_DNS,
            "native_scutil_order": 1,
            "observed_tun_prefix": OBSERVED_TUN_ADDRESS,
            "resolv_conf_sufficient": False,
            "scoped_dns_covers_all_queries": False,
            "magic_dns_direct_retained": True,
            "domestic_direct_retained": True,
        },
        "ipv6": {
            "aaaa_absent_is_fault": False,
            "curl6_may_be_v4_mapped": True,
            "real_ipv6_path_verified": False,
        },
        "domain_fix": {
            "suffixes": list(OVERSEAS_DOMAIN_SUFFIXES),
            "live_short_test": "not_run",
            "user_isolated_short_test": "observed_outside_this_repository",
            "isolated_mihomo_check_on_user_machine": "passed_not_rerun_here",
        },
        "rules": updated,
        "rollback_policy": dict(ROLLBACK_POLICY),
        "unverified_claims": dict(UNVERIFIED_CLAIMS),
    }
    errors = validate_experiment_profile(profile)
    if errors:
        raise ValueError("; ".join(errors))
    return profile


def _status_view(availability: str, reason: str | None, backend_state: str | None = None,
                 self_online: bool | None = None, peer_summary: str = "unknown",
                 peer_count: int | None = None, peers_online: int | None = None) -> dict:
    view = {
        "availability": availability,
        "reason": reason,
        "backend_state": backend_state,
        "self_online": self_online,
        "peer_summary": peer_summary,
        "peer_count": peer_count,
        "peers_online": peers_online,
    }
    if tuple(view) != _STATUS_KEYS:
        raise RuntimeError("status view drifted from the whitelist")
    return view


def normalize_tailscale_status(stdout: str | bytes, *, returncode: int | None,
                               truncated: bool = False,
                               limit: int = TAILSCALE_STATUS_PARSE_LIMIT) -> dict:
    """Turn one complete status document into a whitelist record.

    Parse only after the caller has kept the whole stdout. A pre-parse slice,
    a command failure, invalid JSON, or a missing field stays unavailable or
    unknown. None of those are reported as healthy or offline. The record has
    no host names, addresses, keys, or the original document.
    """
    if not isinstance(truncated, bool):
        raise ValueError("truncated must be bool")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= BROKEN_COLLECTOR_SLICE:
        raise ValueError("parse limit must stay above the 2000-byte slice")
    if truncated:
        return _status_view("unavailable", "pre_parse_truncation")
    if returncode is None:
        return _status_view("unavailable", "command_not_run")
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise ValueError("returncode must be an int or None")
    if isinstance(stdout, bytes):
        try:
            text = stdout.decode("utf-8")
        except UnicodeDecodeError:
            return _status_view("unavailable", "invalid_text")
    elif isinstance(stdout, str):
        text = stdout
    else:
        raise ValueError("stdout must be str or bytes")
    if len(text.encode("utf-8")) > limit:
        return _status_view("unavailable", "output_too_large")
    if returncode != 0:
        return _status_view("unavailable", "command_failed")
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, UnicodeError):
        return _status_view("unavailable", "invalid_json")
    if not isinstance(document, dict):
        return _status_view("unavailable", "invalid_shape")
    backend = document.get("BackendState")
    if not isinstance(backend, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", backend):
        backend = None
    self_online = None
    self_record = document.get("Self")
    if isinstance(self_record, dict) and isinstance(self_record.get("Online"), bool):
        self_online = self_record["Online"]
    peer_summary = "unknown"
    peer_count = None
    peers_online = None
    peers = document.get("Peer")
    if isinstance(peers, dict):
        peer_summary = "known"
        peer_count = len(peers)
        peers_online = sum(
            isinstance(peer, dict) and peer.get("Online") is True for peer in peers.values())
    if backend is None or self_online is None:
        return _status_view("unknown", "missing_field", backend, self_online,
                            peer_summary, peer_count, peers_online)
    if backend == "Running" and self_online is True:
        return _status_view("healthy", None, backend, self_online,
                            peer_summary, peer_count, peers_online)
    return _status_view("offline", "not_running", backend, self_online,
                        peer_summary, peer_count, peers_online)


def summarize_probe_batch(samples: Sequence[dict]) -> dict:
    """Combine classified probes. One incomplete transfer keeps fully_ok false.

    App confirmation is not inferred from these rows. A batch with no rows is
    not treated as a clean run.
    """
    if isinstance(samples, (str, bytes)) or not isinstance(samples, Sequence):
        raise ValueError("samples must be a list")
    counts: dict[str, int] = {}
    notes: list[str] = []
    critical = False
    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("sample must be a dict")
        kind = sample.get("classification")
        if not isinstance(kind, str) or not kind:
            raise ValueError("classification missing")
        counts[kind] = counts.get(kind, 0) + 1
        if sample.get("whole_network_critical") is True:
            critical = True
        if kind == "tun_network_incomplete_transfer_needs_app_confirm":
            label = sample.get("label")
            if isinstance(label, str) and label.startswith("tun-"):
                notes.append(label.removeprefix("tun-") + "_incomplete_transfer")
            else:
                notes.append("incomplete_transfer")
    fully_ok = bool(samples) and all(
        sample.get("classification") == "tun_network_ok_needs_app_confirm"
        and sample.get("transfer_complete") is True
        for sample in samples)
    return {"requests": len(samples), "fully_ok": fully_ok, "critical": critical,
            "counts": counts, "notes": notes, "app_status": "not_inferred"}


def dump_profile(profile: dict) -> str:
    return json.dumps(profile, indent=2, ensure_ascii=False) + "\n"


HELP = """\
usage: python3 scripts/macos_coexist.py <command>

commands:
  profile
      Print the experiment wrapper JSON. It is not a mihomo config.
  normalize-status --returncode N [--truncated]
      Read one complete status document from stdin and print whitelist fields.
      This command does not run tailscale.

Do not pass the wrapper to mihomo -f. There is no cutover or restore command.
"""


def main(argv: list[str] | None = None) -> int:
    """Offline helpers only. No network and no Tailscale invocation."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        sys.stdout.write(HELP)
        return 0 if args else 2
    if args == ["profile"]:
        sys.stdout.write(dump_profile(build_experiment_profile()))
        return 0
    if args[0] != "normalize-status":
        sys.stdout.write(HELP)
        return 2
    returncode = None
    truncated = False
    rest = args[1:]
    while rest:
        item = rest.pop(0)
        if item == "--truncated":
            truncated = True
            continue
        if item == "--returncode" and rest:
            raw = rest.pop(0)
            if not re.fullmatch(r"-?\d+", raw):
                sys.stdout.write(HELP)
                return 2
            returncode = int(raw)
            continue
        sys.stdout.write(HELP)
        return 2
    if returncode is None:
        sys.stdout.write(HELP)
        return 2
    chunks = []
    size = 0
    while size <= TAILSCALE_STATUS_PARSE_LIMIT:
        block = sys.stdin.read(65536)
        if not block:
            break
        chunks.append(block)
        size += len(block)
        if size > TAILSCALE_STATUS_PARSE_LIMIT:
            break
    result = normalize_tailscale_status("".join(chunks), returncode=returncode, truncated=truncated)
    sys.stdout.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return 0


def mihomo_would_load(profile: dict) -> bool:
    """Whether the document has a bare mihomo-like shape.

    The experiment wrapper returns false. A true result is only a shape check
    and is not permission to start mihomo.
    """
    if not isinstance(profile, dict) or "nmd_experiment" in profile:
        return False
    return profile.get("mode") == "rule" and isinstance(profile.get("rules"), list)


if __name__ == "__main__":
    raise SystemExit(main())
