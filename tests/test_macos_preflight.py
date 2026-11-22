"""Tiered macOS preflight. Offline fixtures only.

These tests do not install software, sudo, load a LaunchDaemon, or change
routes, DNS, proxy, or Tailscale. Probes that would talk to a real binary
or the host snapshot are patched. A passing result here is not real-Mac
acceptance, and it does not cover sleep, wake, or watchdog restore.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import macos_geodata as geodata
import macos_preflight as pf
import macos_readonly
import macos_takeover
import manager
import nmd_daemon
import nmd_platform

TOKEN = "NMDPREFLIGHTTOKEN"
TAILNET = "fd7a:115c:a1e0::abcd"
CLEAR = {"status": "pass", "reason": None, "has_198_18": False, "mihomo_running": False}
CLI_OK = {"status": "pass", "path": "/usr/bin/tailscale", "reason": None}
CLI_MISSING = {"status": "fail", "path": None, "reason": "missing"}
VERSION_OK = {"status": "pass", "parsed": (1, 19, 33), "reason": None}
TS_OK = {"status": "pass", "availability": "healthy", "reason": None}
GEO_OK = {"status": "pass", "reason": "ok", "missing": []}
INACTIVE = {"state": "inactive", "reason": "socket_absent", "on_boot": None}


def _valid_geosite():
    return (b"\x0a" + b"\x1d" + b"geosite-fixture-bytes-ok!!").ljust(32, b"\x00")


def _valid_mmdb():
    return b"\x00" * 128 + b"\xab\xcd\xefMaxMind.com"


def one(report, check_id):
    found = [item for item in report["checks"] if item["id"] == check_id]
    if len(found) != 1:
        raise AssertionError(f"{check_id}: { [item['id'] for item in report['checks']] }")
    return found[0]


def daemon_facts(**overrides):
    facts = {
        "platform": "macos",
        "config": {"takeover": {"on_boot": False}},
        "config_problem": None,
        "require_daemon_config": True,
        "document": {"status": "pass", "reason": "ok", "dns_mode": "native",
                     "needs_site": True, "needs_ip": True, "listen_port": 1053},
        "mihomo": {"status": "pass", "path": "/usr/local/bin/mihomo", "reason": None},
        "version": dict(VERSION_OK),
        "tailscale_cli": dict(CLI_OK),
        "tailscale_status": dict(TS_OK),
        "geodata": dict(GEO_OK),
        "state_dir": {"status": "pass", "reason": "ok"},
        "listen": {1053: "free"},
        "snapshot": dict(CLEAR),
        "activity": dict(INACTIVE),
        "on_boot": False,
        "expand_takeover": False,
    }
    facts.update(overrides)
    return facts


def takeover_facts(**overrides):
    facts = daemon_facts(require_daemon_config=False, config=None, config_problem=None,
                         activity=None, on_boot=None, expand_takeover=False)
    facts.update(overrides)
    return facts


class AssessTests(unittest.TestCase):
    def test_readonly_ignores_takeover_dependencies(self):
        report = pf.assess("readonly", {
            "platform": "macos",
            "collector": {"status": "pass", "reason": "ok", "path": "/tmp/collector"},
            "mihomo": {"status": "fail", "reason": "missing", "path": None},
            "geodata": {"status": "fail", "reason": "geodata_missing",
                        "missing": ["geosite.dat"]},
            "tailscale_cli": dict(CLI_MISSING),
        })
        self.assertEqual(report["result"], "pass")
        self.assertFalse(report["blocking"])
        self.assertFalse(report["effects"]["blocked_by_takeover_dependencies"])
        self.assertFalse(report["effects"]["preflight_mutates"])
        ids = [item["id"] for item in report["checks"]]
        self.assertEqual(ids, ["collector_directory", "dashboard_port"])
        self.assertIn("不检查接管组件", one(report, "dashboard_port")["summary"])

    def test_readonly_collector_failure_does_not_mention_installing_mihomo(self):
        report = pf.assess("readonly", {
            "platform": "macos",
            "collector": {"status": "fail", "reason": "collector_state_unusable", "path": None},
        })
        self.assertEqual(report["result"], "fail")
        self.assertEqual(pf.exit_code(report), 1)
        text = json.dumps(report, ensure_ascii=False)
        self.assertIn("不需要 mihomo", text)
        self.assertNotIn("不会自动下载", text)

    def test_dashboard_port_busy_fails_and_unknown_stays_unknown(self):
        busy = pf.assess("readonly", {
            "platform": "macos",
            "collector": {"status": "pass", "reason": "ok", "path": "/tmp/collector"},
            "dashboard_port": 8765, "listen": {8765: "busy"},
        })
        self.assertEqual(one(busy, "dashboard_port")["status"], "fail")
        self.assertEqual(busy["result"], "fail")
        self.assertIn("不会结束那个进程", one(busy, "dashboard_port")["remediation"])
        unknown = pf.assess("readonly", {
            "platform": "macos",
            "collector": {"status": "pass", "reason": "ok", "path": "/tmp/collector"},
            "dashboard_port": 8765, "listen": {8765: "unknown"},
        })
        self.assertEqual(unknown["result"], "unknown")
        self.assertEqual(pf.exit_code(unknown), 3)
        self.assertTrue(unknown["blocking"])

    def test_matching_collector_is_expected_and_other_owners_are_not(self):
        collector = {"status": "pass", "reason": "ok", "path": "/tmp/collector"}
        match = pf.assess("readonly", {
            "platform": "macos", "collector": collector,
            "dashboard_port": 8765, "listen": {8765: "busy"},
            "dashboard_owner": {"status": "match", "reason": "running"},
        })
        check = one(match, "dashboard_port")
        self.assertEqual(check["status"], "pass")
        self.assertEqual(check["reason"], "collector_running")
        self.assertIn("采集器已运行", check["summary"])
        self.assertNotIn("remediation", check)
        self.assertEqual(match["result"], "pass")
        self.assertNotIn("停掉", json.dumps(match, ensure_ascii=False))

        foreign = pf.assess("readonly", {
            "platform": "macos", "collector": collector,
            "dashboard_port": 8765, "listen": {8765: "busy"},
            "dashboard_owner": {"status": "other", "reason": "busy"},
        })
        self.assertEqual(one(foreign, "dashboard_port")["status"], "fail")
        self.assertIn("停掉占用它的程序", one(foreign, "dashboard_port")["remediation"])
        self.assertNotIn("采集器已运行", one(foreign, "dashboard_port")["summary"])

        wrong = pf.assess("readonly", {
            "platform": "macos", "collector": collector,
            "dashboard_port": 8765, "listen": {8765: "busy"},
            "dashboard_owner": {"status": "other", "reason": "wrong_config"},
        })
        self.assertEqual(one(wrong, "dashboard_port")["reason"], "wrong_config")
        self.assertEqual(wrong["result"], "fail")
        self.assertNotIn("采集器已运行", one(wrong, "dashboard_port")["summary"])

        forged = pf.assess("readonly", {
            "platform": "macos", "collector": collector,
            "dashboard_port": 8765, "listen": {8765: "busy"},
            "dashboard_owner": {"status": "other", "reason": "wrong_instance"},
        })
        self.assertEqual(forged["result"], "fail")
        self.assertNotIn("采集器已运行", one(forged, "dashboard_port")["summary"])

        unclear = pf.assess("readonly", {
            "platform": "macos", "collector": collector,
            "dashboard_port": 8765, "listen": {8765: "busy"},
            "dashboard_owner": {"status": "unknown", "reason": "job_unreadable"},
        })
        self.assertEqual(unclear["result"], "unknown")
        self.assertEqual(pf.exit_code(unclear), 3)
        self.assertNotIn("采集器已运行", json.dumps(unclear, ensure_ascii=False))
        self.assertNotIn("停掉", one(unclear, "dashboard_port")["remediation"])

        unhealthy = pf.assess("readonly", {
            "platform": "macos",
            "collector": {"status": "fail", "reason": "not_private", "path": "/tmp/collector"},
            "dashboard_port": 8765, "listen": {8765: "busy"},
            "dashboard_owner": {"status": "match", "reason": "running"},
        })
        self.assertEqual(one(unhealthy, "dashboard_port")["reason"], "collector_unhealthy")
        self.assertEqual(unhealthy["result"], "fail")
        self.assertNotIn("采集器已运行", one(unhealthy, "dashboard_port")["summary"])
        self.assertNotIn("停掉", one(unhealthy, "dashboard_port")["remediation"])

    def test_takeover_stays_strict_when_a_collector_matches(self):
        report = pf.assess("takeover", takeover_facts(
            listen={1053: "busy"},
            dashboard_port=8765,
            dashboard_owner={"status": "match", "reason": "running"},
            collector={"status": "pass", "reason": "ok", "path": "/tmp/collector"},
        ))
        self.assertEqual(one(report, "dns_listen")["status"], "fail")
        self.assertEqual(one(report, "dns_listen")["reason"], "busy")
        self.assertNotIn("dashboard_port", [item["id"] for item in report["checks"]])
        self.assertNotIn("采集器已运行", json.dumps(report, ensure_ascii=False))

    def test_daemon_tier_does_not_require_takeover_checks(self):
        report = pf.assess("daemon", daemon_facts(
            geodata={"status": "fail", "reason": "geodata_missing", "missing": ["geosite.dat"]},
            snapshot={"status": "pass", "reason": None, "has_198_18": True,
                      "mihomo_running": True},
            version={"status": "pass", "parsed": (1, 0, 0), "reason": None},
        ))
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["required_tiers"], ["daemon"])
        ids = [item["id"] for item in report["checks"]]
        self.assertNotIn("geodata", ids)
        self.assertNotIn("mihomo_version", ids)
        self.assertNotIn("tun_dns", ids)
        self.assertIn("会话若停在 active、starting 或 needs_rollback",
                      one(report, "network_effect")["summary"])
        self.assertFalse(report["effects"]["later_restart_may_roll_back_active_takeover"])
        self.assertFalse(report["effects"]["later_start_may_takeover_on_new_boot"])
        self.assertTrue(report["effects"]["later_start_may_finish_a_pending_rollback"])

    def test_on_boot_pulls_takeover_checks_into_the_daemon_tier(self):
        report = pf.assess("daemon", daemon_facts(
            on_boot=True, expand_takeover=True,
            geodata={"status": "fail", "reason": "geodata_missing", "missing": ["geosite.dat"]},
        ))
        self.assertEqual(report["result"], "fail")
        self.assertEqual(report["required_tiers"], ["daemon", "takeover"])
        self.assertEqual(one(report, "geodata")["status"], "fail")
        self.assertIn("nmd macos geodata ensure", one(report, "geodata")["remediation"])
        self.assertIn("只读预检", one(report, "geodata")["remediation"])
        self.assertTrue(report["effects"]["later_start_may_takeover_on_new_boot"])
        self.assertIn("可能开始接管", one(report, "network_effect")["summary"])

    def test_unknown_activity_blocks_and_does_not_claim_the_network_is_unchanged(self):
        report = pf.assess("daemon", daemon_facts(
            activity={"state": "unknown", "reason": "timeout", "on_boot": None},
            expand_takeover=True,
        ))
        self.assertEqual(report["result"], "unknown")
        self.assertEqual(one(report, "daemon_activity")["status"], "unknown")
        self.assertIn("不会 stop", one(report, "daemon_activity")["remediation"])
        self.assertIn("不会假定网络保持不变", one(report, "network_effect")["summary"])
        self.assertIsNone(report["effects"]["later_restart_may_roll_back_active_takeover"])

    def test_active_takeover_is_not_a_failure_and_names_the_rollback(self):
        report = pf.assess("daemon", daemon_facts(
            activity={"state": "active", "reason": None, "on_boot": False},
        ))
        self.assertEqual(report["result"], "pass")
        self.assertIn("路由、DNS 或 Tailscale exit node 会变",
                      one(report, "network_effect")["summary"])
        self.assertTrue(report["effects"]["later_restart_may_roll_back_active_takeover"])

    def test_mihomo_missing_nonexecutable_and_unknown(self):
        missing = pf.assess("daemon", daemon_facts(
            mihomo={"status": "fail", "path": None, "reason": "missing"}))
        self.assertEqual(one(missing, "mihomo_executable")["status"], "fail")
        self.assertIn("不会自动下载", one(missing, "mihomo_executable")["remediation"])
        plain = pf.assess("daemon", daemon_facts(
            mihomo={"status": "fail", "path": "/tmp/mihomo", "reason": "not_executable"}))
        self.assertIn("不能执行", one(plain, "mihomo_executable")["summary"])
        self.assertIn("不会改权限", one(plain, "mihomo_executable")["remediation"])
        unknown = pf.assess("daemon", daemon_facts(
            mihomo={"status": "unknown", "path": "/usr/local/bin/mihomo", "reason": "stat_failed"}))
        self.assertEqual(unknown["result"], "unknown")
        self.assertIn("不会当成已安装", one(unknown, "mihomo_executable")["remediation"])

    def test_version_floor_is_only_the_documented_native_requirement(self):
        old = pf.assess("takeover", takeover_facts(
            version={"status": "pass", "parsed": (1, 19, 32), "reason": None}))
        self.assertEqual(one(old, "mihomo_version")["status"], "fail")
        self.assertEqual(one(old, "mihomo_version")["version"], "1.19.32")
        self.assertIn("1.19.33", one(old, "mihomo_version")["remediation"])
        self.assertIn("不是把曾经观测到的 1.19.34 当成最低版本",
                      one(old, "mihomo_version")["remediation"])
        self.assertNotIn(TOKEN, json.dumps(old))
        floor = pf.assess("takeover", takeover_facts(
            version={"status": "pass", "parsed": (1, 19, 33), "reason": None}))
        self.assertEqual(one(floor, "mihomo_version")["status"], "pass")
        disabled = pf.assess("takeover", takeover_facts(
            document={"status": "pass", "reason": "ok", "dns_mode": "disabled",
                      "needs_site": False, "needs_ip": False, "listen_port": None},
            version={"status": "pass", "parsed": (1, 19, 32), "reason": None}))
        self.assertEqual(one(disabled, "mihomo_version")["status"], "pass")
        self.assertIn("没有额外的版本下限", one(disabled, "mihomo_version")["summary"])
        for reason in ("timeout", "unparsed", "command_failed", "probe_error"):
            unknown = pf.assess("takeover", takeover_facts(
                version={"status": "unknown", "parsed": (1, 0, 0), "reason": reason}))
            self.assertEqual(unknown["result"], "unknown", reason)
            self.assertEqual(one(unknown, "mihomo_version")["status"], "unknown", reason)
            self.assertNotEqual(one(unknown, "mihomo_version")["status"], "fail", reason)

    def test_placeholder_config_fails_without_echoing_the_address(self):
        report = pf.assess("takeover", takeover_facts(
            document={"status": "fail", "reason": "placeholder_inputs", "dns_mode": None,
                      "needs_site": False, "needs_ip": False, "listen_port": None}))
        self.assertEqual(one(report, "mihomo_config")["status"], "fail")
        self.assertIn("不会写入", one(report, "mihomo_config")["remediation"])
        self.assertNotIn("203.0.113.20", json.dumps(report))
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_port_conflict_permission_and_snapshot_unknown(self):
        busy = pf.assess("takeover", takeover_facts(listen={1053: "busy"}))
        self.assertEqual(one(busy, "dns_listen")["status"], "fail")
        self.assertIn("不会结束那个进程", one(busy, "dns_listen")["remediation"])
        unsafe = pf.assess("daemon", daemon_facts(
            state_dir={"status": "fail", "reason": "unsafe_path_parent"}))
        self.assertEqual(one(unsafe, "state_directory")["status"], "fail")
        self.assertIn("不会改权限", one(unsafe, "state_directory")["remediation"])
        unknown = pf.assess("takeover", takeover_facts(
            snapshot={"status": "unknown", "reason": "not_observed",
                      "has_198_18": None, "mihomo_running": None}))
        self.assertEqual(unknown["result"], "unknown")
        self.assertEqual(one(unknown, "tun_dns")["status"], "unknown")
        self.assertEqual(one(unknown, "mihomo_process")["status"], "unknown")
        self.assertIn("不会当成没有冲突", one(unknown, "tun_dns")["remediation"])

    def test_active_daemon_keeps_its_own_takeover_resources_when_on_boot_rechecks(self):
        active = {"state": "active", "reason": None, "on_boot": True}
        held = {"status": "pass", "reason": None, "has_198_18": True, "mihomo_running": True}
        report = pf.assess("daemon", daemon_facts(
            on_boot=True, expand_takeover=True, activity=active,
            snapshot=held, listen={1053: "busy"}))
        self.assertEqual(report["result"], "pass")
        self.assertFalse(report["blocking"])
        for check_id in ("tun_dns", "mihomo_process", "dns_listen"):
            item = one(report, check_id)
            self.assertEqual(item["status"], "pass", check_id)
            self.assertEqual(item["reason"], "owned_by_daemon", check_id)
        self.assertIn("不是另一份", one(report, "tun_dns")["summary"])
        self.assertIn("按快照回退", one(report, "mihomo_process")["summary"])
        self.assertIn("会变", one(report, "network_effect")["summary"])
        blocked = pf.assess("daemon", daemon_facts(
            on_boot=True, expand_takeover=True, activity=active, snapshot=held,
            listen={1053: "busy"},
            geodata={"status": "fail", "reason": "geodata_missing", "missing": ["geosite.dat"]}))
        self.assertEqual(blocked["result"], "fail")
        self.assertEqual(one(blocked, "geodata")["status"], "fail")
        self.assertEqual(one(blocked, "tun_dns")["reason"], "owned_by_daemon")

    def test_inactive_on_boot_still_rejects_another_instances_resources(self):
        report = pf.assess("daemon", daemon_facts(
            on_boot=True, expand_takeover=True,
            snapshot={"status": "pass", "reason": None, "has_198_18": True,
                      "mihomo_running": True},
            listen={1053: "busy"}))
        self.assertEqual(report["result"], "fail")
        self.assertEqual(one(report, "tun_dns")["reason"], "conflict")
        self.assertEqual(one(report, "mihomo_process")["status"], "fail")
        self.assertEqual(one(report, "dns_listen")["reason"], "busy")

    def test_takeover_tier_does_not_treat_a_running_daemon_as_the_owner(self):
        report = pf.assess("takeover", takeover_facts(
            activity={"state": "active", "reason": None, "on_boot": True},
            snapshot={"status": "pass", "reason": None, "has_198_18": True,
                      "mihomo_running": True},
            listen={1053: "busy"}))
        self.assertEqual(one(report, "tun_dns")["status"], "fail")
        self.assertEqual(one(report, "mihomo_process")["status"], "fail")
        self.assertEqual(one(report, "dns_listen")["status"], "fail")
        self.assertNotEqual(one(report, "tun_dns").get("reason"), "owned_by_daemon")

    def test_unknown_conflict_stays_unknown_while_the_daemon_is_active(self):
        report = pf.assess("daemon", daemon_facts(
            on_boot=True, expand_takeover=True,
            activity={"state": "active", "reason": None, "on_boot": True},
            snapshot={"status": "unknown", "reason": "not_observed",
                      "has_198_18": None, "mihomo_running": None},
            listen={1053: "unknown"}))
        self.assertEqual(report["result"], "unknown")
        self.assertEqual(one(report, "tun_dns")["status"], "unknown")
        self.assertEqual(one(report, "dns_listen")["status"], "unknown")
        self.assertNotEqual(one(report, "tun_dns").get("reason"), "owned_by_daemon")

    def test_positive_conflicts_fail_and_clear_conflicts_pass(self):
        conflict = pf.assess("takeover", takeover_facts(
            snapshot={"status": "pass", "reason": None, "has_198_18": True,
                      "mihomo_running": True}))
        self.assertEqual(one(conflict, "tun_dns")["status"], "fail")
        self.assertEqual(one(conflict, "mihomo_process")["status"], "fail")
        self.assertIn("不会改 DNS", one(conflict, "tun_dns")["remediation"])
        self.assertIn("不会结束它", one(conflict, "mihomo_process")["remediation"])
        clear = pf.assess("takeover", takeover_facts())
        self.assertEqual(clear["result"], "pass")
        self.assertFalse(clear["blocking"])
        self.assertTrue(clear["effects"]["command_may_change_network"])
        self.assertFalse(clear["effects"]["preflight_mutates"])

    def test_tailscale_offline_fails_and_a_failed_probe_stays_unknown(self):
        offline = pf.assess("takeover", takeover_facts(
            tailscale_status={"status": "fail", "availability": "offline",
                              "reason": "not_running"}))
        self.assertEqual(one(offline, "tailscale_status")["status"], "fail")
        self.assertIn("不会执行 tailscale set", one(offline, "tailscale_status")["remediation"])
        unknown = pf.assess("takeover", takeover_facts(
            tailscale_status={"status": "unknown", "availability": "unavailable",
                              "reason": "timeout"}))
        self.assertEqual(one(unknown, "tailscale_status")["status"], "unknown")
        self.assertNotEqual(unknown["result"], "fail")
        missing = pf.assess("daemon", daemon_facts(tailscale_cli=dict(CLI_MISSING)))
        self.assertEqual(one(missing, "tailscale_cli")["status"], "fail")
        self.assertIn("不会自动安装", one(missing, "tailscale_cli")["remediation"])
        self.assertIn("不会改用其他客户端", one(missing, "tailscale_cli")["remediation"])

    def test_a_non_result_on_a_required_check_becomes_unknown(self):
        report = pf.assess("daemon", daemon_facts(
            mihomo={"status": "skip", "path": None, "reason": None}))
        self.assertEqual(one(report, "mihomo_executable")["status"], "unknown")
        self.assertEqual(report["result"], "unknown")

    def test_other_platforms_are_not_applicable_and_do_not_block(self):
        report = pf.assess("daemon", {"platform": "other"})
        self.assertEqual(report["result"], "not_applicable")
        self.assertFalse(report["blocking"])
        self.assertEqual(pf.exit_code(report), 0)
        self.assertFalse(report["effects"]["preflight_mutates"])


class SnapshotConflictTests(unittest.TestCase):
    def test_strict_accept_refuses_anything_that_is_not_an_explicit_clear(self):
        clear = {"has_198_18": False, "mihomo_running": False}
        self.assertIsNone(pf.snapshot_conflict(clear, snapshot_name="snap.json", strict=True))
        unknown = pf.snapshot_conflict(
            {"has_198_18": None, "mihomo_running": False},
            snapshot_name="snap.json", strict=True)
        self.assertEqual(unknown["result"], "preflight_unknown")
        missing = pf.snapshot_conflict(clear, snapshot_name=None, strict=True)
        self.assertEqual(missing["result"], "preflight_unknown")
        failed = pf.snapshot_conflict(
            {"has_198_18": True, "mihomo_running": False},
            snapshot_name="snap.json", strict=True)
        self.assertEqual(failed["result"], "preflight_failed")

    def test_non_strict_only_refuses_a_positive_conflict(self):
        self.assertIsNone(pf.snapshot_conflict(
            {"has_198_18": None, "mihomo_running": False},
            snapshot_name=None, strict=False))
        self.assertIsNone(pf.snapshot_conflict(
            {"has_198_18": False, "mihomo_running": False},
            snapshot_name="kept", strict=False))
        failed = pf.snapshot_conflict(
            {"has_198_18": False, "mihomo_running": True},
            snapshot_name="kept", strict=False)
        self.assertEqual(failed["result"], "preflight_failed")
        self.assertEqual(failed["preflight"], {"has_198_18": False, "mihomo_running": True})


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_executable_probe_does_not_spawn(self):
        missing = self.base / "missing-mihomo"
        plain = self.base / "plain-mihomo"
        plain.write_bytes(b"not a program")
        plain.chmod(0o644)
        program = self.base / "mihomo"
        program.write_bytes(b"#!/bin/sh\nexit 0\n")
        program.chmod(0o755)
        dangling = self.base / "dangling"
        dangling.symlink_to(self.base / "nowhere")
        with patch.object(macos_readonly.subprocess, "Popen",
                          side_effect=AssertionError("spawned")):
            self.assertEqual(pf.probe_executable(missing), "fail")
            self.assertEqual(pf.probe_executable(plain), "fail")
            self.assertEqual(pf.probe_executable(program), "pass")
            self.assertEqual(pf.probe_executable(dangling), "fail")
            self.assertEqual(pf._resolve_mihomo(str(missing))["reason"], "missing")
            self.assertEqual(pf._resolve_mihomo(str(plain))["reason"], "not_executable")
            self.assertEqual(pf._resolve_mihomo(str(program))["status"], "pass")
            self.assertEqual(pf._resolve_mihomo(str(dangling))["reason"], "not_executable")
            self.assertEqual(pf._resolve_mihomo("relative/mihomo")["reason"], "not_absolute")

    def test_version_probe_is_bounded_stdout_only_and_drops_the_banner(self):
        seen = {}

        def fake(argv, timeout, limit):
            seen["argv"] = list(argv)
            seen["timeout"] = timeout
            seen["limit"] = limit
            return 0, b"Mihomo Meta 1.19.33 " + TOKEN.encode() + b"\n", None

        with patch.object(macos_readonly, "bounded_run", side_effect=fake):
            result = pf.probe_version("/usr/local/bin/mihomo")
        self.assertEqual(seen["argv"], ["/usr/local/bin/mihomo", "-v"])
        self.assertLessEqual(seen["timeout"], 3)
        self.assertLessEqual(seen["limit"], 4096)
        self.assertEqual(result["parsed"], (1, 19, 33))
        self.assertNotIn(TOKEN, json.dumps(result))

        def timeout(argv, timeout, limit):
            return None, b"", "timeout"

        with patch.object(macos_readonly, "bounded_run", side_effect=timeout):
            result = pf.probe_version("/usr/local/bin/mihomo")
        self.assertEqual(result, {"status": "unknown", "parsed": None, "reason": "timeout"})

        def broken(argv, timeout, limit):
            raise OSError("probe failed")

        with patch.object(macos_readonly, "bounded_run", side_effect=broken):
            result = pf.probe_version("/usr/local/bin/mihomo")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "probe_error")

        def unparsed(argv, timeout, limit):
            return 0, b"no version " + TOKEN.encode(), None

        with patch.object(macos_readonly, "bounded_run", side_effect=unparsed):
            result = pf.probe_version("/usr/local/bin/mihomo")
        self.assertEqual(result["reason"], "unparsed")
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_tailscale_status_keeps_failed_probes_unknown_and_drops_names(self):
        secret = json.dumps({
            "BackendState": "Running",
            "Self": {"Online": True, "HostName": TOKEN},
            "Peer": {"node": {"HostName": "PEER-" + TOKEN, "Online": True}},
        })
        cases = (
            ((0, secret, None), "pass"),
            ((0, '{"BackendState":"Stopped","Self":{"Online":false}}', None), "fail"),
            ((0, '{"BackendState":"Running"}', None), "unknown"),
            ((1, secret, None), "unknown"),
            ((None, "", "timeout"), "unknown"),
        )
        for reply, status in cases:
            with self.subTest(status=status), \
                    patch.object(macos_readonly, "execute", return_value=reply):
                result = pf.probe_tailscale_status("/usr/bin/tailscale")
            self.assertEqual(result["status"], status)
            blob = json.dumps(result)
            self.assertNotIn(TOKEN, blob)
            self.assertNotIn("HostName", blob)
            self.assertNotIn("Peer", blob)

    def test_listen_probe_connects_and_never_binds_or_checks_ssh(self):
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        self.addCleanup(busy.close)
        self.assertEqual(pf.probe_listen(port), "busy")
        busy.close()
        self.assertEqual(pf.probe_listen(port), "free")
        with patch.object(pf.socket, "socket", side_effect=AssertionError("connected")):
            self.assertEqual(pf.probe_listen(22), "unknown")
            self.assertEqual(pf.probe_listen(True), "unknown")

    def test_state_directory_mode_is_a_real_permission_failure(self):
        private = self.base / "private"
        private.mkdir(mode=0o700)
        os.chmod(private, 0o700)
        shared = self.base / "shared"
        shared.mkdir(mode=0o700)
        os.chmod(shared, 0o777)
        self.assertEqual(pf.inspect_state_dir(str(private))["status"], "pass")
        shared_result = pf.inspect_state_dir(str(shared))
        self.assertEqual(shared_result["status"], "fail")
        self.assertEqual(shared_result["reason"], "unsafe_path_parent")
        self.assertEqual(pf.inspect_state_dir(None)["status"], "unknown")

    def test_geodata_missing_is_fail_and_unreadable_is_unknown(self):
        geo = self.base / "geo"
        geo.mkdir(mode=0o700)
        self.assertEqual(
            pf.probe_geodata(geo, True, True),
            {"status": "fail", "reason": "geodata_missing", "missing": ["geosite.dat", "geoip"]})
        (geo / "geosite.dat").write_bytes(b"x")
        (geo / "geoip.dat").write_bytes(b"y")
        self.assertEqual(pf.probe_geodata(geo, True, True)["status"], "fail")
        self.assertEqual(pf.probe_geodata(geo, True, True)["missing"], ["geoip"])
        (geo / "Country.mmdb").write_bytes(b"m")
        self.assertEqual(pf.probe_geodata(geo, True, True)["status"], "pass")
        (geo / "geosite.dat").unlink()
        (geo / "GeoSite.dat").write_bytes(b"x")
        self.assertEqual(pf.probe_geodata(geo, True, False)["status"], "pass")
        (geo / "GeoSite.dat").unlink()
        (geo / "geosite.dat").write_bytes(b"x")
        (geo / "geosite.dat").chmod(0)
        if os.geteuid() != 0:
            unreadable = pf.probe_geodata(geo, True, True)
            self.assertEqual(unreadable["status"], "unknown")
            self.assertEqual(unreadable["reason"], "geodata_unreadable")
        else:
            real = os.access

            def denied(path, mode, **kwargs):
                if str(path).endswith("geosite.dat"):
                    return False
                return real(path, mode, **kwargs)

            with patch.object(pf.os, "access", side_effect=denied):
                unreadable = pf.probe_geodata(geo, True, True)
            self.assertEqual(unreadable["reason"], "geodata_unreadable")
        self.assertFalse(any(path.is_symlink() for path in geo.iterdir()))

    def test_placeholder_document_does_not_keep_the_address(self):
        result = pf.inspect_document(None, {
            "server": "203.0.113.20", "port": 1080, "proxy_name": TOKEN})
        self.assertEqual(result["reason"], "placeholder_inputs")
        self.assertNotIn("203.0.113.20", json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(result))
        valid = pf.inspect_document(None, {"server": TAILNET, "port": 1081, "proxy_name": TOKEN})
        self.assertEqual(valid["status"], "pass")
        self.assertEqual(valid["dns_mode"], "native")
        self.assertTrue(valid["needs_site"])
        self.assertTrue(valid["needs_ip"])
        self.assertEqual(valid["listen_port"], 1053)
        self.assertNotIn(TOKEN, json.dumps(valid))
        self.assertNotIn(TAILNET, json.dumps(valid))

    def test_activity_probe_distinguishes_absent_garbled_and_timeout(self):
        missing = self.base / "missing.sock"
        self.assertEqual(pf.probe_activity(missing)["state"], "inactive")
        plain = self.base / "not-a-socket"
        plain.write_text("x", encoding="utf-8")
        self.assertEqual(pf.probe_activity(plain)["reason"], "socket_not_a_socket")

        sequence = {"n": 0}

        def serve(payload):
            sequence["n"] += 1
            path = self.base / f"reply-{sequence['n']}.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(os.fspath(path))
            server.listen(1)

            def run():
                try:
                    conn, _addr = server.accept()
                except OSError:
                    return
                with contextlib.closing(conn):
                    conn.recv(64)
                    if payload is not None:
                        conn.sendall(payload)

            thread = threading.Thread(target=run)
            thread.start()
            self.addCleanup(thread.join)
            self.addCleanup(server.close)
            return path

        active = pf.probe_activity(serve(b'{"takeover_active": true, "on_boot": false}\n'))
        self.assertEqual(active["state"], "active")
        garbled = pf.probe_activity(serve(b"not-json"))
        self.assertEqual(garbled["state"], "unknown")
        self.assertEqual(garbled["reason"], "invalid_reply")

        hung = self.base / "hung.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(os.fspath(hung))
        server.listen(1)
        self.addCleanup(server.close)
        hung_result = pf.probe_activity(hung)
        self.assertEqual(hung_result["state"], "unknown")
        self.assertEqual(hung_result["reason"], "timeout")


class CommandTests(unittest.TestCase):
    def test_usage_does_not_probe(self):
        with patch.object(pf, "run", side_effect=AssertionError("probed")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pf.main(["--tier", "sideways"]), 2)
            self.assertEqual(pf.main(["readonly"]), 2)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(pf.main(["--help"]), 0)
        self.assertIn("readonly", output.getvalue())
        self.assertIn("daemon", output.getvalue())
        self.assertIn("takeover", output.getvalue())
        self.assertIn("unknown", output.getvalue())
        self.assertIn("--json", output.getvalue())
        self.assertIn("--summary", output.getvalue())

    def test_main_prints_json_and_the_matching_exit_code(self):
        for result, code in (("pass", 0), ("fail", 1), ("unknown", 3), ("not_applicable", 0)):
            report = {"schema_version": 1, "kind": "macos_preflight", "tier": "readonly",
                      "result": result, "blocking": result in ("fail", "unknown"),
                      "checks": [], "remediation": ["请在本机安装官方 mihomo。不会自动下载。"],
                      "effects": {"preflight_mutates": False}}
            output = io.StringIO()
            error = io.StringIO()
            with patch.object(pf, "run", return_value=report), \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(error):
                self.assertEqual(pf.main(["--tier", "readonly"]), code)
            body = json.loads(output.getvalue())
            self.assertEqual(body["result"], result)
            self.assertIn("不会自动下载", body["remediation"][0])
            self.assertEqual(error.getvalue(), "")

    def test_conflicting_format_flags_do_not_probe(self):
        with patch.object(pf, "run", side_effect=AssertionError("probed")), \
                contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(pf.main(["--json", "--summary"]), 2)
        self.assertIn("--json", error.getvalue())

    def test_tty_defaults_to_summary_and_explicit_json_stays_clean(self):
        report = {"schema_version": 1, "kind": "macos_preflight", "tier": "readonly",
                  "result": "fail", "blocking": True,
                  "checks": [
                      {"id": "collector_directory", "status": "pass", "required": True,
                       "summary": "当前用户可以使用采集目录。"},
                      {"id": "dashboard_port", "status": "fail", "required": True,
                       "summary": "面板端口 8765 已有程序在监听。",
                       "remediation": "换一个端口，或停掉占用它的程序后再开面板。预检不会结束那个进程。"},
                  ],
                  "remediation": ["换一个端口，或停掉占用它的程序后再开面板。预检不会结束那个进程。"],
                  "effects": {"preflight_mutates": False}}
        seen = {}

        def fake_run(tier, on_check=None):
            seen["on_check"] = on_check
            if on_check is not None:
                on_check(report["checks"][0])
                on_check(report["checks"][1])
            return report

        class Stream(io.StringIO):
            def __init__(self, tty):
                super().__init__()
                self._tty = tty

            def isatty(self):
                return self._tty

        cases = (
            ("tty-default", [], True, False, True),
            ("pipe-default", [], False, False, False),
            ("tty-json", ["--json"], True, True, False),
            ("pipe-summary", ["--summary"], False, False, True),
            ("tty-summary", ["--summary"], True, True, True),
        )
        for name, args, out_tty, err_tty, human in cases:
            with self.subTest(name=name):
                seen.clear()
                stdout, stderr = Stream(out_tty), Stream(err_tty)
                with patch.object(pf, "run", side_effect=fake_run), \
                        patch.object(sys, "stdout", stdout), \
                        patch.object(sys, "stderr", stderr):
                    self.assertEqual(pf.main(["--tier", "readonly", *args]), 1)
                if human:
                    self.assertIsNotNone(seen["on_check"])
                    self.assertIn("预检（readonly）：失败", stdout.getvalue())
                    self.assertIn("阻塞：", stdout.getvalue())
                    self.assertEqual(stdout.getvalue().count("不会结束那个进程"), 1)
                    self.assertNotIn("schema_version", stdout.getvalue())
                    self.assertNotIn("\x1b", stdout.getvalue() + stderr.getvalue())
                    self.assertIn("采集目录", stderr.getvalue())
                    if err_tty:
                        self.assertIn("\r", stderr.getvalue())
                    else:
                        self.assertNotIn("\r", stderr.getvalue())
                else:
                    self.assertIsNone(seen["on_check"])
                    self.assertEqual(stderr.getvalue(), "")
                    body = json.loads(stdout.getvalue())
                    self.assertEqual(body, report)
                    self.assertTrue(stdout.getvalue().startswith("{"))

    def test_summary_exit_codes_match_pass_fail_and_unknown(self):
        labels = {"pass": "通过", "fail": "失败", "unknown": "未知",
                  "not_applicable": "不适用"}
        for result, code in (("pass", 0), ("fail", 1), ("unknown", 3), ("not_applicable", 0)):
            report = {"schema_version": 1, "kind": "macos_preflight", "tier": "daemon",
                      "result": result, "blocking": result in ("fail", "unknown"),
                      "checks": [], "remediation": [],
                      "effects": {"preflight_mutates": False}}
            output = io.StringIO()
            with patch.object(pf, "run", return_value=report), \
                    contextlib.redirect_stdout(output), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pf.main(["--summary"]), code)
            text = output.getvalue()
            self.assertIn(labels[result], text)
            self.assertNotIn("schema_version", text)
            self.assertNotIn("\x1b", text)
            if result == "not_applicable":
                self.assertIn("没有执行检查", text)

    def test_duplicate_remediation_is_listed_once(self):
        report = pf.assess("takeover", takeover_facts(snapshot={
            "status": "unknown", "reason": "timeout",
            "has_198_18": None, "mihomo_running": None}))
        text = pf.render_summary(report)
        self.assertEqual(text.count("不会当成没有冲突"), 1)
        self.assertIn("预检（takeover）：未知", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("{", text)

    def test_library_entry_points_do_not_print_human_text(self):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(pf, "host_is_darwin", return_value=False), \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(error):
            self.assertEqual(pf.for_foreground({})["result"], "not_applicable")
            self.assertEqual(pf.for_daemon_lifecycle()["result"], "not_applicable")
            self.assertEqual(pf.for_installed_takeover()["result"], "not_applicable")
            self.assertEqual(pf.run("readonly")["result"], "not_applicable")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(error.getvalue(), "")

    def test_non_darwin_summary_explains_the_early_exit(self):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(pf, "host_is_darwin", return_value=False), \
                patch.object(pf, "collect", side_effect=AssertionError("probed")), \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(error):
            self.assertEqual(pf.main(["--tier", "takeover", "--summary"]), 0)
        self.assertIn("不适用", output.getvalue())
        self.assertIn("没有执行检查", output.getvalue())
        self.assertEqual(error.getvalue(), "")
        self.assertNotIn("\x1b", output.getvalue())

    def test_non_darwin_run_does_not_probe_and_does_not_block(self):
        with patch.object(pf, "host_is_darwin", return_value=False), \
                patch.object(pf, "probe_executable", side_effect=AssertionError("probed")), \
                patch.object(pf, "probe_snapshot", side_effect=AssertionError("snapshot")):
            report = pf.run("takeover")
        self.assertEqual(report["result"], "not_applicable")
        self.assertFalse(report["blocking"])
        self.assertEqual(pf.host_is_darwin(), sys.platform == "darwin")


class _Tree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.checkout = self.base / "repo"
        self.config_dir = self.base / "config"
        self.state_dir = self.base / "state"
        self.checkout.mkdir()
        self.config_dir.mkdir(mode=0o700)
        self.state_dir.mkdir(mode=0o700)
        os.chmod(self.config_dir, 0o700)
        os.chmod(self.state_dir, 0o700)
        env = patch.dict(os.environ, {
            "HOME": self.tmp.name,
            "XDG_CONFIG_HOME": str(self.base / "xdg-config"),
            "XDG_STATE_HOME": str(self.base / "xdg-state"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }, clear=False)
        env.start()
        self.addCleanup(env.stop)
        subprocess.run(["git", "init", "-q", str(self.checkout)], check=True,
                       capture_output=True)
        (self.checkout / "marker").write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.checkout), "add", "marker"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(self.checkout), "-c", "user.email=t@example.com",
                        "-c", "user.name=test", "commit", "-q", "-m", "init"],
                       check=True, capture_output=True)
        manager.setting(self.checkout, "home", str(self.checkout))
        manager.setting(self.checkout, "scope", "user")
        manager.setting(self.checkout, "configDir", str(self.config_dir))
        manager.setting(self.checkout, "stateDir", str(self.state_dir))

    def write_config(self, *, on_boot=False, mihomo_path, port=8765):
        nmd_daemon.write_daemon_config(self.config_dir / "daemon.json", {
            "schema_version": 1,
            "dashboard": {"port": port},
            "takeover": {
                "inputs": {"proxy_name": TOKEN, "server": TAILNET, "port": 1081},
                "profile": None, "on_boot": on_boot, "check_interval_seconds": 20,
                "critical_failures": 3, "mihomo_path": mihomo_path,
                "state_dir": str(self.state_dir),
            },
        })

    def program(self, name):
        path = self.base / name
        path.write_bytes(b"#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
        return str(path)

    def context(self):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(pf, "host_is_darwin", return_value=True))
        stack.enter_context(patch.object(manager, "ROOT", self.checkout))
        stack.enter_context(patch.object(nmd_platform, "name", return_value="macos"))
        return stack


class CollectTests(_Tree):
    def test_readonly_does_not_probe_takeover_tools_or_create_directories(self):
        absent = self.base / "not-created"
        manager.setting(self.checkout, "stateDir", str(absent))
        with self.context(), \
                patch.object(pf, "probe_executable", side_effect=AssertionError("mihomo")), \
                patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                patch.object(pf, "probe_tailscale_cli", side_effect=AssertionError("tailscale")), \
                patch.object(pf, "probe_tailscale_status", side_effect=AssertionError("status")), \
                patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                patch.object(pf, "probe_snapshot", side_effect=AssertionError("snapshot")), \
                patch.object(pf, "probe_activity", side_effect=AssertionError("activity")), \
                patch.object(pf, "probe_listen", side_effect=AssertionError("listen")):
            report = pf.run("readonly")
        self.assertEqual(report["result"], "pass")
        self.assertFalse(absent.exists())
        self.assertIn("不检查接管组件", one(report, "dashboard_port")["summary"])

    def test_readonly_busy_dashboard_port_still_skips_mihomo(self):
        self.write_config(mihomo_path=str(self.base / "missing-mihomo"), port=8765)
        with self.context(), \
                patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                patch.object(pf, "probe_listen", return_value="busy"):
            report = pf.run("readonly")
        self.assertEqual(report["result"], "fail")
        self.assertEqual(one(report, "dashboard_port")["reason"], "busy")
        self.assertNotIn("mihomo_executable", [item["id"] for item in report["checks"]])
        self.assertNotIn(TOKEN, json.dumps(report))
        self.assertNotIn(TAILNET, json.dumps(report))

    def _agent_plist(self, script, config_path, arguments=None):
        import plistlib
        directory = Path.home() / "Library" / "LaunchAgents"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "io.github.zzzhty.nmd-daemon.plist"
        path.write_bytes(plistlib.dumps({
            "Label": "io.github.zzzhty.nmd-daemon",
            "Note": "HTTP/1.1 200 nmd",
            "ProgramArguments": arguments or [
                "/usr/bin/python3", str(script), "run-user", "--config", str(config_path)],
            "RunAtLoad": True,
        }))
        path.chmod(0o644)
        return path

    def _job_text(self, script, config_path, *, state="running", pid="25353"):
        args = "\n".join([
            "\t\t/usr/bin/python3", f"\t\t{script}", "\t\trun-user",
            "\t\t--config", f"\t\t{config_path}"])
        return (
            "gui/501/io.github.zzzhty.nmd-daemon = {\n"
            "\tstate = " + state + "\n"
            "\tpath = /tmp/nmd HTTP/1.1 200\n"
            "\targuments = {\n" + args + "\n\t}\n"
            "\tpid = " + pid + "\n"
            "}\n")

    def test_running_collector_matches_only_with_the_job_and_the_socket(self):
        self.write_config(mihomo_path=str(self.base / "missing-mihomo"), port=8765)
        script = self.base / "scripts" / "nmd_daemon.py"
        script.parent.mkdir()
        script.write_text("print('nmd')\n", encoding="utf-8")
        config_path = self.config_dir / "daemon.json"
        self._agent_plist(script, config_path)
        calls = []

        def runner(argv):
            calls.append(argv)
            if argv[:2] == ["/bin/launchctl", "print"]:
                self.assertEqual(argv[2], f"gui/{os.geteuid()}/io.github.zzzhty.nmd-daemon")
                return {"code": 0, "error": None, "stderr": "",
                        "stdout": self._job_text(script, config_path)}
            self.assertEqual(argv[0], "/usr/sbin/lsof")
            self.assertIn("-p", argv)
            self.assertEqual(argv[argv.index("-p") + 1], "25353")
            self.assertIn("-iTCP:127.0.0.1:8765", argv)
            return {"code": 0, "error": None, "stderr": "", "stdout": "n127.0.0.1:8765\n"}

        def refuse_connect(self, *_args, **_kwargs):
            raise AssertionError("connect")

        with self.context(), patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(pf, "_bounded_text", side_effect=runner), \
                patch.object(socket.socket, "connect", refuse_connect):
            report = pf.run("readonly")
        check = one(report, "dashboard_port")
        self.assertEqual(report["result"], "pass")
        self.assertEqual(check["reason"], "collector_running")
        self.assertIn("采集器已运行", check["summary"])
        self.assertNotIn("停掉", json.dumps(report, ensure_ascii=False))
        self.assertEqual([item[0] for item in calls], ["/bin/launchctl", "/usr/sbin/lsof"])

    def test_other_listener_forged_argv_and_unknown_job_do_not_pass(self):
        self.write_config(mihomo_path=str(self.base / "missing-mihomo"), port=8765)
        script = self.base / "scripts" / "nmd_daemon.py"
        script.parent.mkdir()
        script.write_text("# nmd\n", encoding="utf-8")
        config_path = self.config_dir / "daemon.json"
        self._agent_plist(script, config_path)

        def other_socket(argv):
            if argv[0] == "/bin/launchctl":
                return {"code": 0, "error": None, "stderr": "",
                        "stdout": self._job_text(script, config_path)}
            return {"code": 1, "error": None, "stderr": "", "stdout": ""}

        with self.context(), patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(pf, "_bounded_text", side_effect=other_socket):
            other = pf.run("readonly")
        self.assertEqual(one(other, "dashboard_port")["status"], "fail")
        self.assertEqual(one(other, "dashboard_port")["reason"], "busy")
        self.assertIn("停掉占用它的程序", one(other, "dashboard_port")["remediation"])
        self.assertNotIn("采集器已运行", one(other, "dashboard_port")["summary"])

        self._agent_plist(script, config_path, arguments=[
            "/usr/bin/python3", "/tmp/nmd", "run-user", "--config", str(config_path)])

        def forbidden(argv):
            raise AssertionError(argv)

        with self.context(), patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(pf, "_bounded_text", side_effect=forbidden):
            forged = pf.run("readonly")
        self.assertEqual(one(forged, "dashboard_port")["reason"], "wrong_instance")
        self.assertNotIn("采集器已运行", one(forged, "dashboard_port")["summary"])

        other_config = self.base / "other-daemon.json"
        other_config.write_text("{}\n", encoding="utf-8")
        self._agent_plist(script, other_config)
        with self.context(), patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(pf, "_bounded_text", side_effect=forbidden):
            wrong = pf.run("readonly")
        self.assertEqual(one(wrong, "dashboard_port")["reason"], "wrong_config")

        self._agent_plist(script, config_path)
        with self.context(), patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(pf, "_bounded_text",
                             return_value={"code": None, "stdout": "", "stderr": "",
                                           "error": "tool_missing"}):
            unclear = pf.run("readonly")
        self.assertEqual(unclear["result"], "unknown")
        self.assertEqual(pf.exit_code(unclear), 3)
        self.assertEqual(one(unclear, "dashboard_port")["reason"], "job_unreadable")
        self.assertNotIn("采集器已运行", json.dumps(unclear, ensure_ascii=False))

        plist = self._agent_plist(script, config_path)
        plist.chmod(0o666)
        with self.context(), patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(pf, "_bounded_text", side_effect=forbidden):
            alien = pf.run("readonly")
        self.assertEqual(one(alien, "dashboard_port")["reason"], "plist_untrusted")
        self.assertEqual(alien["result"], "unknown")

        self._agent_plist(script, config_path)
        plist = Path.home() / "Library" / "LaunchAgents" / "io.github.zzzhty.nmd-daemon.plist"
        plist.chmod(0o644)

        def waiting(argv):
            if argv[0] == "/bin/launchctl":
                return {"code": 0, "error": None, "stderr": "",
                        "stdout": self._job_text(script, config_path, state="waiting")}
            raise AssertionError(argv)

        with self.context(), patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(pf, "_bounded_text", side_effect=waiting):
            sick = pf.run("readonly")
        self.assertEqual(one(sick, "dashboard_port")["reason"], "job_unhealthy")
        self.assertEqual(sick["result"], "unknown")
        self.assertNotIn("采集器已运行", json.dumps(sick, ensure_ascii=False))

    def test_daemon_start_does_not_ask_who_owns_the_dashboard(self):
        self.write_config(mihomo_path=str(self.base / "missing-mihomo"), port=8765)
        with self.context(), \
                patch.object(pf, "inspect_dashboard_owner", side_effect=AssertionError("owner")), \
                patch.object(pf, "probe_listen", return_value="busy"):
            report = pf.run("daemon")
        self.assertNotIn("dashboard_port", [item["id"] for item in report["checks"]])
        self.assertNotIn("采集器已运行", json.dumps(report, ensure_ascii=False))

    def test_progress_is_flushed_before_the_next_probe_starts(self):
        self.write_config(mihomo_path=str(self.base / "missing-mihomo"), port=8765)
        err = _Capture()
        out = io.StringIO()
        entered = {}

        def blocking_listen(port):
            text = err.getvalue()
            self.assertGreater(err.flushes, 0, text)
            self.assertIn("采集目录", text)
            self.assertNotIn("面板端口", text)
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\r", text)
            entered["ok"] = True
            return "busy"

        with self.context(), patch.object(pf, "probe_listen", side_effect=blocking_listen), \
                patch.object(sys, "stdout", out), patch.object(sys, "stderr", err):
            code = pf.main(["--summary"])
        self.assertTrue(entered.get("ok"))
        self.assertEqual(code, 1)
        summary = out.getvalue()
        self.assertIn("预检（readonly）：失败", summary)
        self.assertIn("面板端口", summary)
        self.assertEqual(summary.count("不会结束那个进程"), 1)
        self.assertNotIn("schema_version", summary)
        self.assertNotIn("\x1b", err.getvalue())
        self.assertIn("[失败] 面板端口", err.getvalue())

    def test_explicit_json_matches_the_report_and_has_no_progress(self):
        err = _Capture()
        out = io.StringIO()
        with self.context(), patch.object(sys, "stdout", out), patch.object(sys, "stderr", err):
            expected = pf.run("readonly")
            code = pf.main(["--json"])
        self.assertEqual(code, pf.exit_code(expected))
        self.assertEqual(out.getvalue(),
                         json.dumps(expected, ensure_ascii=False, indent=2) + "\n")
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(err.flushes, 0)

    def test_missing_daemon_config_summary_names_the_gap(self):
        err = _Capture()
        out = io.StringIO()
        with self.context(), \
                patch.object(pf, "probe_activity", return_value=dict(INACTIVE)), \
                patch.object(pf, "probe_snapshot", side_effect=AssertionError("snapshot")), \
                patch.object(pf, "probe_listen", side_effect=AssertionError("listen")), \
                patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                patch.object(pf, "probe_tailscale_status", side_effect=AssertionError("status")), \
                patch.object(sys, "stdout", out), patch.object(sys, "stderr", err):
            code = pf.main(["--tier", "daemon", "--summary"])
        self.assertEqual(code, 1)
        text = out.getvalue()
        self.assertIn("预检（daemon）：失败", text)
        self.assertIn("没有 daemon.json", text)
        self.assertIn("nmd macos daemon init", text)
        self.assertNotIn("schema_version", text)
        self.assertNotIn("\x1b", err.getvalue())
        self.assertNotIn("\r", err.getvalue())
        self.assertIn("[失败] 守护配置", err.getvalue())


class _Capture(io.TextIOBase):
    def __init__(self):
        self.parts = []
        self.flushes = 0

    def write(self, data):
        self.parts.append(data)
        return len(data)

    def flush(self):
        self.flushes += 1

    def isatty(self):
        return False

    def getvalue(self):
        return "".join(self.parts)


class LifecycleTests(_Tree):
    def test_restart_and_start_do_not_stop_when_mihomo_is_missing_or_not_executable(self):
        cases = ("missing", "plain")
        for kind in cases:
            with self.subTest(kind=kind):
                if kind == "missing":
                    mihomo = str(self.base / "missing-mihomo")
                else:
                    mihomo = str(self.base / "plain-mihomo")
                    Path(mihomo).write_bytes(b"not executable")
                    Path(mihomo).chmod(0o644)
                self.write_config(mihomo_path=mihomo)
                before = sorted(path.name for path in self.state_dir.iterdir())
                output = io.StringIO()
                for action in ("restart", "start"):
                    with self.context(), \
                            patch.object(pf, "probe_activity", return_value=dict(INACTIVE)), \
                            patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                            patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                            patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                            patch.object(pf, "probe_snapshot", side_effect=AssertionError("snapshot")), \
                            patch.object(pf, "probe_tailscale_status",
                                         side_effect=AssertionError("status")), \
                            patch.object(pf, "probe_listen", side_effect=AssertionError("listen")), \
                            patch.object(nmd_daemon, "_daemon_stop",
                                         side_effect=AssertionError("stop")), \
                            patch.object(nmd_daemon, "_daemon_start",
                                         side_effect=AssertionError("start")), \
                            patch.object(nmd_daemon, "_run_helper",
                                         side_effect=AssertionError("sudo")), \
                            contextlib.redirect_stdout(output):
                        code = nmd_daemon.cli_daemon([action])
                    report = json.loads(output.getvalue())
                    self.assertEqual(code, 1)
                    self.assertEqual(report["result"], "fail")
                    self.assertEqual(report["refused_action"], action)
                    self.assertFalse(report["effects"]["preflight_mutates"])
                    item = one(report, "mihomo_executable")
                    self.assertEqual(item["status"], "fail")
                    self.assertEqual(item["reason"],
                                     "missing" if kind == "missing" else "not_executable")
                    if kind == "missing":
                        self.assertIn("不会自动下载", item["remediation"])
                    else:
                        self.assertIn("不会改权限", item["remediation"])
                    self.assertNotIn(TOKEN, output.getvalue())
                    self.assertNotIn(TAILNET, output.getvalue())
                    output.seek(0)
                    output.truncate()
                self.assertEqual(before, sorted(path.name for path in self.state_dir.iterdir()))

    def test_on_boot_runs_every_takeover_probe_before_any_stop(self):
        self.write_config(on_boot=True, mihomo_path=self.program("mihomo"))
        order = []

        def version(_path):
            order.append("version")
            return {"status": "unknown", "parsed": None, "reason": "timeout"}

        def geodata_probe(*_args):
            order.append("geodata")
            return {"status": "fail", "reason": "geodata_missing", "missing": ["geosite.dat"]}

        def snapshot():
            order.append("snapshot")
            return dict(CLEAR)

        def listen(_port, host="127.0.0.1", timeout=1.0):
            order.append("listen")
            return "free"

        def status(_path):
            order.append("tailscale_status")
            return {"status": "unknown", "availability": "unavailable", "reason": "timeout"}

        output = io.StringIO()
        with self.context(), \
                patch.object(pf, "probe_activity", return_value=dict(INACTIVE)), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(macos_takeover, "resolve_geodata_dir",
                             return_value=str(self.base / "geo")), \
                patch.object(pf, "probe_version", side_effect=version), \
                patch.object(pf, "probe_geodata", side_effect=geodata_probe), \
                patch.object(pf, "probe_snapshot", side_effect=snapshot), \
                patch.object(pf, "probe_listen", side_effect=listen), \
                patch.object(pf, "probe_tailscale_status", side_effect=status), \
                patch.object(geodata, "fetch_verified", side_effect=geodata.GeodataError("timeout")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=AssertionError("stop")), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(output):
            code = nmd_daemon.cli_daemon(["restart"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(order, ["version", "tailscale_status", "geodata", "snapshot", "listen"])
        self.assertEqual(one(report, "mihomo_version")["status"], "unknown")
        self.assertEqual(one(report, "geodata")["status"], "fail")
        self.assertEqual(report["result"], "fail")
        self.assertIn("nmd macos geodata ensure", one(report, "geodata")["remediation"])

    def test_inactive_daemon_does_not_consult_takeover_probes_before_restart(self):
        self.write_config(on_boot=False, mihomo_path=self.program("mihomo"))
        calls = []

        def stop():
            calls.append("stop")
            return {"result": "stop"}

        def start():
            calls.append("start")
            return {"result": "start"}

        with self.context(), \
                patch.object(pf, "probe_activity", return_value=dict(INACTIVE)), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                patch.object(pf, "probe_snapshot", side_effect=AssertionError("snapshot")), \
                patch.object(pf, "probe_listen", side_effect=AssertionError("listen")), \
                patch.object(pf, "probe_tailscale_status", side_effect=AssertionError("status")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=stop), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=start), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = nmd_daemon.cli_daemon(["restart"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["stop", "start"])

    def test_unknown_activity_and_probe_errors_do_not_stop(self):
        self.write_config(on_boot=False, mihomo_path=self.program("mihomo"))
        output = io.StringIO()
        with self.context(), \
                patch.object(pf, "probe_activity",
                             return_value={"state": "unknown", "reason": "timeout",
                                           "on_boot": None}), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_version", return_value=dict(VERSION_OK)), \
                patch.object(pf, "probe_geodata", return_value=dict(GEO_OK)), \
                patch.object(pf, "probe_snapshot", return_value=dict(CLEAR)), \
                patch.object(pf, "probe_listen", return_value="free"), \
                patch.object(pf, "probe_tailscale_status", return_value=dict(TS_OK)), \
                patch.object(macos_takeover, "resolve_geodata_dir",
                             return_value=str(self.state_dir)), \
                patch.object(geodata, "fetch_verified", side_effect=geodata.GeodataError("timeout")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=AssertionError("stop")), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(output):
            code = nmd_daemon.cli_daemon(["restart"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(report["result"], "unknown")
        self.assertIn("不会 stop", output.getvalue())

        def explode():
            raise OSError("socket blew up")

        output.seek(0)
        output.truncate()
        with self.context(), \
                patch.object(pf, "probe_activity", side_effect=explode), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_version", return_value=dict(VERSION_OK)), \
                patch.object(pf, "probe_geodata", return_value=dict(GEO_OK)), \
                patch.object(pf, "probe_snapshot", return_value=dict(CLEAR)), \
                patch.object(pf, "probe_listen", return_value="free"), \
                patch.object(pf, "probe_tailscale_status", return_value=dict(TS_OK)), \
                patch.object(macos_takeover, "resolve_geodata_dir",
                             return_value=str(self.state_dir)), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=AssertionError("stop")), \
                contextlib.redirect_stdout(output):
            code = nmd_daemon.cli_daemon(["restart"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(one(report, "daemon_activity")["reason"], "probe_error")

    def test_restart_is_not_blocked_by_the_active_daemons_own_resources(self):
        self.write_config(on_boot=True, mihomo_path=self.program("mihomo"))
        calls = []

        def stop():
            calls.append("stop")
            return {"result": "stop"}

        def start():
            calls.append("start")
            return {"result": "start"}

        held = {"status": "pass", "reason": None, "has_198_18": True, "mihomo_running": True}
        (self.state_dir / "geosite.dat").write_bytes(_valid_geosite())
        (self.state_dir / "geoip.metadb").write_bytes(_valid_mmdb())
        with self.context(), \
                patch.object(pf, "probe_activity",
                             return_value={"state": "active", "reason": None, "on_boot": True}), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_tailscale_status", return_value=dict(TS_OK)), \
                patch.object(pf, "probe_version", return_value=dict(VERSION_OK)), \
                patch.object(pf, "probe_geodata", return_value=dict(GEO_OK)), \
                patch.object(pf, "probe_snapshot", return_value=held), \
                patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(macos_takeover, "resolve_geodata_dir",
                             return_value=str(self.state_dir)), \
                patch.object(geodata, "fetch_verified", side_effect=AssertionError("network")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=stop), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=start), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = nmd_daemon.cli_daemon(["restart"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["stop", "start"])

        calls.clear()
        output = io.StringIO()
        with self.context(), \
                patch.object(pf, "probe_activity", return_value=dict(INACTIVE)), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_tailscale_status", return_value=dict(TS_OK)), \
                patch.object(pf, "probe_version", return_value=dict(VERSION_OK)), \
                patch.object(pf, "probe_geodata", return_value=dict(GEO_OK)), \
                patch.object(pf, "probe_snapshot", return_value=held), \
                patch.object(pf, "probe_listen", return_value="busy"), \
                patch.object(macos_takeover, "resolve_geodata_dir",
                             return_value=str(self.state_dir)), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=AssertionError("stop")), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(output):
            code = nmd_daemon.cli_daemon(["restart"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(report["result"], "fail")
        self.assertEqual(one(report, "mihomo_process")["reason"], "conflict")
        self.assertEqual(calls, [])

    def test_active_takeover_restart_does_stop_and_the_report_names_the_change(self):
        self.write_config(on_boot=False, mihomo_path=self.program("mihomo"))
        calls = []

        def stop():
            calls.append("stop")
            return {"result": "stop"}

        def start():
            calls.append("start")
            return {"result": "start"}

        with self.context(), \
                patch.object(pf, "probe_activity",
                             return_value={"state": "active", "reason": None, "on_boot": False}), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                patch.object(pf, "probe_snapshot", side_effect=AssertionError("snapshot")), \
                patch.object(pf, "probe_listen", side_effect=AssertionError("listen")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=stop), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=start), \
                contextlib.redirect_stdout(io.StringIO()):
            code = nmd_daemon.cli_daemon(["restart"])
            report = pf.for_daemon_lifecycle(self.checkout)
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["stop", "start"])
        self.assertEqual(report["result"], "pass")
        self.assertIn("会变", one(report, "network_effect")["summary"])

    def test_unsafe_state_directory_blocks_before_stop(self):
        self.write_config(on_boot=False, mihomo_path=self.program("mihomo"))
        os.chmod(self.state_dir, 0o777)
        output = io.StringIO()
        with self.context(), \
                patch.object(pf, "probe_activity", return_value=dict(INACTIVE)), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=AssertionError("stop")), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(output):
            code = nmd_daemon.cli_daemon(["restart"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(one(report, "state_directory")["reason"], "unsafe_path_parent")
        self.assertIn("不会改权限", output.getvalue())

    def test_stop_is_not_gated(self):
        calls = []

        def stop():
            calls.append("stop")
            return {"result": "stop"}

        with self.context(), \
                patch.object(pf, "for_daemon_lifecycle", side_effect=AssertionError("gated")), \
                patch.object(pf, "for_installed_takeover", side_effect=AssertionError("gated")), \
                patch.object(nmd_daemon, "daemon_receipt", return_value=None), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=stop), \
                contextlib.redirect_stdout(io.StringIO()):
            code = nmd_daemon.cli_daemon(["stop"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["stop"])

    def test_non_darwin_restart_keeps_stop_then_start(self):
        calls = []

        def stop():
            calls.append("stop")
            return {"result": "stop"}

        def start():
            calls.append("start")
            return {"result": "start"}

        with patch.object(pf, "host_is_darwin", return_value=False), \
                patch.object(pf, "for_daemon_lifecycle", side_effect=AssertionError("preflight")), \
                patch.object(nmd_daemon, "daemon_receipt", return_value=None), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=stop), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=start), \
                contextlib.redirect_stdout(io.StringIO()):
            code = nmd_daemon.cli_daemon(["restart"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["stop", "start"])

    def test_apply_preflight_failure_keeps_pending_and_does_not_activate(self):
        self.write_config(on_boot=False, mihomo_path=str(self.base / "missing-mihomo"))
        output = io.StringIO()
        with self.context(), \
                patch.object(nmd_daemon, "daemon_receipt", return_value={"version": 1}), \
                patch.object(pf, "probe_activity", return_value=dict(INACTIVE)), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                patch.object(pf, "probe_snapshot", side_effect=AssertionError("snapshot")), \
                patch.object(manager, "ensure_assets", side_effect=AssertionError("assets")), \
                patch.object(manager, "network_command", side_effect=AssertionError("network")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=AssertionError("stop")), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=AssertionError("start")), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(manager.ManagerError, "待应用状态保留"):
                manager.main(["apply"])
        self.assertEqual(manager.setting(self.checkout, "pendingApply"), "true")
        self.assertEqual(manager.setting(self.checkout, "appliedRevision"), "")
        report = json.loads(output.getvalue())
        self.assertEqual(report["result"], "fail")
        self.assertEqual(report["refused_action"], "restart")
        self.assertFalse(report["effects"]["preflight_mutates"])
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertNotIn(TAILNET, output.getvalue())

    def test_takeover_start_preflight_runs_before_sudo(self):
        self.write_config(on_boot=False, mihomo_path=str(self.base / "missing-mihomo"))
        order = []

        def reexec(*_args):
            order.append("reexec")
            raise AssertionError("reexec")

        output = io.StringIO()
        with self.context(), \
                patch.object(macos_takeover, "reexec_root", side_effect=reexec), \
                patch.object(macos_takeover.os, "execv", side_effect=AssertionError("execv")), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                patch.object(pf, "probe_geodata", return_value={
                    "status": "fail", "reason": "geodata_missing", "missing": ["geosite.dat"]}), \
                patch.object(pf, "probe_snapshot", return_value=dict(CLEAR)), \
                patch.object(pf, "probe_listen", return_value="free"), \
                patch.object(pf, "probe_tailscale_status", return_value=dict(TS_OK)), \
                patch.object(macos_takeover, "resolve_geodata_dir",
                             return_value=str(self.state_dir)), \
                patch.object(geodata, "fetch_verified", side_effect=geodata.GeodataError("timeout")), \
                patch.object(nmd_daemon, "DaemonIPCClient",
                             side_effect=AssertionError("ipc")), \
                contextlib.redirect_stdout(output):
            code = nmd_daemon.cli_daemon(["takeover-start"])
        self.assertEqual(code, 1)
        self.assertEqual(order, [])
        report = json.loads(output.getvalue())
        self.assertEqual(report["refused_action"], "takeover-start")
        self.assertEqual(report["tier"], "takeover")
        self.assertIn("geodata", [item["id"] for item in report["checks"]])
        self.assertNotIn(TOKEN, output.getvalue())


class ForegroundTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("root skips the pre-sudo gate")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        env = patch.dict(os.environ, {"HOME": self.tmp.name}, clear=False)
        env.start()
        self.addCleanup(env.stop)

    def _inputs(self):
        path = self.base / "inputs.json"
        path.write_text(json.dumps({"server": TAILNET, "port": 1081, "proxy_name": TOKEN}),
                        encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_foreground_failure_does_not_reexec(self):
        state = self.base / "state"
        geo = self.base / "geo"
        state.mkdir(mode=0o700)
        geo.mkdir(mode=0o700)
        output = io.StringIO()
        for command in ("takeover", "accept"):
            with self.subTest(command=command), \
                    patch.object(pf, "host_is_darwin", return_value=True), \
                    patch.object(macos_takeover, "reexec_root",
                                 side_effect=AssertionError("reexec")), \
                    patch.object(macos_takeover.os, "execv", side_effect=AssertionError("execv")), \
                    patch.object(macos_takeover.os, "execvp", side_effect=AssertionError("execvp")), \
                    patch.object(pf, "probe_snapshot", return_value=dict(CLEAR)), \
                    patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_MISSING)), \
                    patch.object(pf, "probe_tailscale_status",
                                 side_effect=AssertionError("status")), \
                    patch.object(pf, "probe_listen", return_value="free"), \
                    patch.object(pf, "probe_version", side_effect=AssertionError("version")), \
                    patch.object(macos_readonly.subprocess, "Popen",
                                 side_effect=AssertionError("spawn")), \
                    patch.object(geodata, "fetch_verified",
                                 side_effect=geodata.GeodataError("timeout")), \
                    contextlib.redirect_stdout(output):
                code = macos_takeover.main([
                    command, "--inputs", str(self._inputs()),
                    "--mihomo", str(self.base / "missing-mihomo"),
                    "--state-dir", str(state), "--geodata-dir", str(geo)])
            report = json.loads(output.getvalue())
            self.assertEqual(code, 1, output.getvalue())
            self.assertEqual(report["refused_action"], command)
            self.assertEqual(report["result"], "fail")
            self.assertFalse(report["effects"]["preflight_mutates"])
            self.assertTrue(report["effects"]["command_may_change_network"])
            self.assertNotIn(TOKEN, output.getvalue())
            self.assertNotIn(TAILNET, output.getvalue())
            names = {path.name for path in geo.iterdir()}
            self.assertFalse(names & {"geosite.dat", "GeoSite.dat", "geoip.metadb",
                                      "Country.mmdb", "geoip.dat", "geoip.db"})
            self.assertFalse(any(name.startswith(".geosite") or name.startswith(".geoip")
                                 for name in names))
            output.seek(0)
            output.truncate()

    def test_foreground_pass_still_reaches_the_existing_reexec(self):
        state = self.base / "state"
        geo = self.base / "geo"
        state.mkdir(mode=0o700)
        geo.mkdir(mode=0o700)
        (geo / "geosite.dat").write_bytes(_valid_geosite())
        (geo / "geoip.metadb").write_bytes(_valid_mmdb())
        program = self.base / "mihomo"
        program.write_bytes(b"#!/bin/sh\nexit 0\n")
        program.chmod(0o755)
        order = []

        def reexec(_script, argv):
            order.append(list(argv))
            raise SystemExit(0)

        with patch.object(pf, "host_is_darwin", return_value=True), \
                patch.object(macos_takeover, "reexec_root", side_effect=reexec), \
                patch.object(macos_takeover.os, "execv", side_effect=AssertionError("execv")), \
                patch.object(pf, "probe_snapshot", return_value=dict(CLEAR)), \
                patch.object(pf, "probe_tailscale_cli", return_value=dict(CLI_OK)), \
                patch.object(pf, "probe_tailscale_status", return_value=dict(TS_OK)), \
                patch.object(pf, "probe_listen", return_value="free"), \
                patch.object(pf, "probe_version", return_value=dict(VERSION_OK)), \
                patch.object(macos_readonly.subprocess, "Popen",
                             side_effect=AssertionError("spawn")), \
                patch.object(geodata, "fetch_verified", side_effect=AssertionError("network")):
            with self.assertRaises(SystemExit):
                macos_takeover.main([
                    "takeover", "--inputs", str(self._inputs()),
                    "--mihomo", str(program), "--state-dir", str(state),
                    "--geodata-dir", str(geo)])
        self.assertEqual(order[0][0], "takeover")
        self.assertEqual(stat.S_IMODE(program.stat().st_mode), 0o755)

    def test_invalid_foreground_arguments_do_not_preflight(self):
        with patch.object(pf, "for_foreground", side_effect=AssertionError("preflight")), \
                patch.object(macos_takeover.os, "execv", side_effect=AssertionError("execv")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(macos_takeover.main(["takeover", "--bogus"]), 2)


if __name__ == "__main__":
    unittest.main()
