"""Phase B controller tests: fully offline, no real mutation ever runs.

Every takeover and rollback drives an injected runner/mutator/spawner over
fixture command output and a fake clock, so the macOS CI runner never clears
an exit node, never starts mihomo, and never writes network state.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import macos_coexist
import macos_prepare
import macos_takeover as mod
import macos_readonly

PROFILE = json.loads((ROOT / "examples/macos-mihomo-coexist.experiment.json").read_text(encoding="utf-8"))
INPUTS = {"proxy_name": "VPS", "server": "fd7a:115c:a1e0::abcd", "port": 1081}
TS = "/usr/local/bin/tailscale"
MIHOMO = "/usr/local/bin/mihomo"
EXIT_IP = "100.64.0.2"
PINNED_IP = "100.64.0.8"
DNS_CLEAN = "resolver #1\n  nameserver[0]     : 100.100.100.100\n"
DNS_DIRTY = "resolver #1\n  nameserver[0]     : 198.18.0.2\n"


class Table:
    """Fixture host: read-only answers, mutable effects, one fake process."""

    def __init__(self, *, dns_dirty_window=None, tcp_ok=True, status_healthy=True,
                 ps_mihomo=False, exit_node_selected=True,
                 services=(("Wi-Fi", []),), fail_mutations=(), process_alive=True,
                 corp_dns=True, allow_lan=False):
        self.dns_dirty_window = dns_dirty_window  # (from, to) in fake seconds
        self.tcp_ok = tcp_ok
        self.status_healthy = status_healthy
        self.ps_mihomo = ps_mihomo
        self.exit_node_cleared = False
        self.snapshot_exit_node = exit_node_selected
        self.snapshot_corp_dns = corp_dns
        self.snapshot_services = {name: list(servers) for name, servers in services}
        self.service_dns = {name: list(servers) for name, servers in services}
        self.corp_dns = corp_dns
        self.allow_lan = allow_lan
        self.mutations = []
        self.fail_mutations = fail_mutations
        self.process_alive = process_alive
        self.clock = 0.0
        self.proxy_text = "<dictionary> {\n}\n"
        self.route_text = ("Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n"
                           "default 192.0.2.1 UGScg en0\n")

    # -- read-only side ------------------------------------------------------
    def runner(self, argv, timeout):
        argv = tuple(argv)
        if argv == ("/usr/sbin/netstat", "-rn", "-f", "inet"):
            return 0, self.route_text, None
        if argv == ("/usr/sbin/netstat", "-rn", "-f", "inet6"):
            return 0, "Routing tables\n\nInternet6:\n", None
        if argv == ("/usr/sbin/scutil", "--dns"):
            window = self.dns_dirty_window
            dirty = window is not None and window[0] <= self.clock < window[1]
            return 0, DNS_DIRTY if dirty else DNS_CLEAN, None
        if argv == ("/usr/sbin/scutil", "--proxy"):
            return 0, self.proxy_text, None
        if argv == ("/bin/ps", "-axo", "pid=,comm="):
            body = "  1 /sbin/launchd\n"
            if self.ps_mihomo:
                body += "  456 /usr/local/bin/mihomo\n"
            return 0, body, None
        # The fake child is not a real session. Identity probes must not
        # raise, and they must not look like a confirmed mihomo.
        if (len(argv) == 5 and argv[0:2] == ("/bin/ps", "-p")
                and argv[3:] == ("-o", "lstart=,args=")):
            return 1, "", None
        if argv == ("/usr/sbin/networksetup", "-listallnetworkservices"):
            return 0, ("An asterisk (*) denotes that a network service is disabled.\n"
                       + "\n".join(self.service_dns) + "\n"), None
        if len(argv) == 3 and argv[0:2] == ("/usr/sbin/networksetup", "-getdnsservers"):
            servers = self.service_dns.get(argv[2], [])
            if not servers:
                return 0, f"There aren't any DNS Servers set on {argv[2]}.\n", None
            return 0, "\n".join(servers) + "\n", None
        if argv == (TS, "status", "--json"):
            peers = {
                "nodekey:abc": {
                    "ID": "nodekey:abc", "DNSName": "pinned-exit.example.ts.net.",
                    "HostName": "pinned-exit", "TailscaleIPs": [EXIT_IP],
                    "ExitNodeOption": True, "Online": True,
                },
                "nodekey:pinned": {
                    "ID": "nodekey:pinned", "DNSName": "other-exit.example.ts.net.",
                    "HostName": "other-exit", "TailscaleIPs": [PINNED_IP],
                    "ExitNodeOption": True, "Online": True,
                },
            }
            if self.status_healthy:
                body = {"BackendState": "Running", "Self": {"Online": True},
                        "MagicDNSSuffix": "example.ts.net.", "Peer": peers}
            else:
                body = {"BackendState": "Stopped", "Self": {"Online": False},
                        "MagicDNSSuffix": "example.ts.net.", "Peer": peers}
            return 0, json.dumps(body), None
        if argv == (TS, "debug", "prefs"):
            prefs = {"ExitNodeID": None if self.exit_node_cleared else "nodekey:abc",
                     "ExitNodeIP": None, "CorpDNS": self.corp_dns, "RouteAll": False,
                     "ExitNodeAllowLANAccess": self.allow_lan, "WantRunning": True}
            return 0, json.dumps(prefs), None
        raise AssertionError(f"unexpected read {argv}")

    # -- mutating side -------------------------------------------------------
    def mutator(self, argv):
        argv = list(argv)
        for pattern in self.fail_mutations:
            if all(len(argv) > index and argv[index] == item for index, item in pattern):
                raise mod.TakeoverError("mutation_failed")
        self.mutations.append(argv)
        if argv[0] == TS and argv[1] == "set":
            for item in argv[2:]:
                if item.startswith("--exit-node="):
                    self.exit_node_cleared = item == "--exit-node="
                elif item == "--accept-dns=true":
                    self.corp_dns = True
                elif item == "--accept-dns=false":
                    self.corp_dns = False
                elif item in ("--exit-node-allow-lan-access",
                              "--exit-node-allow-lan-access=true"):
                    self.allow_lan = True
                elif item == "--exit-node-allow-lan-access=false":
                    self.allow_lan = False
        if argv[0:2] == ["/usr/sbin/networksetup", "-setdnsservers"]:
            rest = argv[2:]
            self.service_dns[rest[0]] = [] if rest[1] == "Empty" else rest[1:]

    def tcp(self, host, port, timeout):
        return {"status": "ok" if self.tcp_ok else "timeout"}

    def spawner(self, argv, log_path):
        # Starting the child costs one fake second; DNS turns dirty only from
        # then on, so the pre-start snapshot stays clean like on a real host.
        self.clock += 1
        return FakeProcess(self)

    def sleep(self, seconds, on_sleep=None):
        self.clock += seconds
        if on_sleep is not None:
            on_sleep(self.clock)


class FakeProcess:
    pid = 9999999  # implausible: killpg fails with ProcessLookupError, suppressed

    def __init__(self, table):
        self.table = table

    def poll(self):
        return None if self.table.process_alive else 1

    def wait(self, timeout=None):
        return 0


def run_takeover(table, **overrides):
    options = dict(
        inputs=INPUTS, profile=PROFILE, minutes=1, mihomo_path=MIHOMO,
        state_dir=None, runner=table.runner, mutator=table.mutator,
        spawner=table.spawner, tcp=table.tcp,
        exists=lambda path: path == TS, sleep=table.sleep, now=lambda: table.clock)
    options.update(overrides)
    with tempfile.TemporaryDirectory() as tmp:
        options["state_dir"] = tmp
        record = mod.takeover(**options)
        yield record, Path(tmp)


class AllowlistTests(unittest.TestCase):
    def test_the_closed_mutation_set(self):
        allowed = (
            [TS, "set", "--exit-node="],
            [TS, "set", "--exit-node=" + EXIT_IP],
            [TS, "set", "--exit-node=pinned-exit"],
            [TS, "set", "--exit-node=", "--accept-dns=true"],
            [TS, "set", "--exit-node=x", "--exit-node-allow-lan-access"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "Empty"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53", "192.0.2.54"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "fe80::1%en0"],
            [MIHOMO, "-d", "/tmp/work", "-f", "/tmp/work/config.yaml"],
            [MIHOMO, "-d", "/tmp/work", "-t", "-f", "/tmp/work/config.yaml"],
            [TS, "set", "--exit-node-allow-lan-access=true"],
            [TS, "set", "--exit-node-allow-lan-access=false"],
            [TS, "set", "--accept-dns=false"],
        )
        for argv in allowed:
            with self.subTest(argv=argv):
                self.assertTrue(mod.mutating_allowlisted(argv))

    def test_everything_else_is_rejected_before_a_spawn(self):
        rejected = (
            ["/usr/sbin/networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "7897"],
            ["/usr/sbin/networksetup", "-setwebproxystate", "Wi-Fi", "off"],
            ["/usr/sbin/networksetup", "-setproxybypassdomains", "Wi-Fi", "x"],
            ["/usr/sbin/networksetup", "-setnetworkserviceenabled", "Wi-Fi", "off"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "Empty", "extra"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi;rm", "Empty"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "vps.example.com"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "fe80::1%en0;rm"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "fe80::1%"],
            [TS, "set", "--advertise-routes=10.0.0.0/8"],
            [TS, "set", "--logout"],
            [TS, "set"],
            ["/bin/sh", "-c", "true"],
            ["/usr/bin/sudo", TS, "set", "--exit-node="],
            ["/tmp/other/mihomo", "-f", "/tmp/config.yaml"],
            [MIHOMO, "-t", "-f", "/tmp/config.yaml"],
            [MIHOMO, "-f", "/tmp/config.yaml"],
            [MIHOMO, "-d", "/tmp/work", "-f", "/tmp/config.yaml"],
            [MIHOMO, "-d", "/tmp/work", "-f", "/tmp/work/../config.yaml"],
            [MIHOMO, "-d", "/tmp/../work", "-f", "/tmp/work/config.yaml"],
            [MIHOMO, "-d", "/tmp"],
            [MIHOMO, "-t", "-f", "/tmp/config.yaml", "--ext-ui"],
            [MIHOMO, "-d", "relative", "-f", "/tmp/config.yaml"],
            [TS, "set", "--exit-node-allow-lan-access=maybe"],
            [TS, "set", "--exit-node=bad node"],
            [TS, "set", "--exit-node=nodekey:abc"],
            [TS, "set", "--exit-node=auto:any"],
            [TS, "set", "--exit-node=100.64.0.2/32"],
        )
        for argv in rejected:
            with self.subTest(argv=argv):
                self.assertFalse(mod.mutating_allowlisted(argv))
        with patch.object(macos_readonly.subprocess, "Popen", side_effect=AssertionError("spawn")):
            with self.assertRaisesRegex(mod.TakeoverError, "not_allowlisted"):
                mod.execute_mutating(["/bin/sh", "-c", "true"])

    def test_explicit_mihomo_path_widens_only_that_binary(self):
        allowed = ["/opt/custom/mihomo", "-d", "/tmp/work", "-t", "-f", "/tmp/work/c.yaml"]
        self.assertTrue(mod.mutating_allowlisted(allowed, mihomo_path="/opt/custom/mihomo"))
        self.assertFalse(mod.mutating_allowlisted(allowed, mihomo_path="/opt/other/mihomo"))
        outside = ["/opt/custom/mihomo", "-d", "/tmp/work", "-f", "/tmp/other/c.yaml"]
        self.assertFalse(mod.mutating_allowlisted(outside, mihomo_path="/opt/custom/mihomo"))


class TakeoverFlowTests(unittest.TestCase):
    def record(self, table, **overrides):
        for record, _ in run_takeover(table, **overrides):
            return record

    def test_deadline_reaches_then_rolls_back(self):
        table = Table(dns_dirty_window=(1, 61))
        record = self.record(table)
        self.assertEqual(record["result"], "deadline_reached")
        self.assertEqual(record["mutations"], [[TS, "set", "--exit-node="]])
        # The -t call is gated but is not a network mutation. Its argv is the
        # only shape production validation is allowed to exec.
        self.assertTrue(mod.mutating_allowlisted(table.mutations[0], mihomo_path=MIHOMO))
        self.assertEqual(table.mutations[0][1:4], ["-d", table.mutations[0][2], "-t"])
        self.assertEqual(Path(table.mutations[0][-1]).parent, Path(table.mutations[0][2]))
        self.assertIn("native_dns_ready", record["steps"])
        self.assertEqual(record["rollback"]["result"], "rollback_restored")
        self.assertIn("exit_node_restored", record["rollback"]["steps"])

    def test_stop_rolls_back_before_the_deadline(self):
        table = Table(dns_dirty_window=(1, 21))
        handlers = {}

        def fake_signal(sig, handler):
            handlers[sig] = handler
            return None

        def sleeping(seconds):
            table.clock += seconds
            if signal.SIGINT in handlers:
                handlers.pop(signal.SIGINT)()

        with patch.object(mod.signal, "signal", side_effect=fake_signal):
            record = self.record(table, sleep=sleeping)
        self.assertEqual(record["result"], "stopped")
        self.assertEqual(record["rollback"]["result"], "rollback_restored")

    def test_three_consecutive_critical_failures_roll_back(self):
        table = Table(dns_dirty_window=(1, 42), tcp_ok=False)
        record = self.record(table)
        self.assertEqual(record["result"], "critical_failures")
        self.assertEqual(record["steps"].count("critical:vps_socks_tcp"), 3)
        self.assertIn("critical_cycles:3", record["steps"])
        self.assertEqual(record["rollback"]["result"], "rollback_restored")

    def test_a_passing_cycle_resets_the_failure_counter(self):
        # tcp fails two cycles, then every cycle passes: the streak resets and
        # the run still ends at the deadline instead of a critical rollback.
        table = Table(dns_dirty_window=(1, 61))
        outcomes = iter([False, False, True, True, True, True, True, True])

        def flaky(host, port, timeout):
            return {"status": "ok" if next(outcomes) else "timeout"}

        record = self.record(table, tcp=flaky)
        self.assertEqual(record["result"], "deadline_reached")
        self.assertEqual(record["steps"].count("critical:vps_socks_tcp"), 2)
        self.assertIn("critical_cycles:1", record["steps"])
        self.assertIn("critical_cycles:2", record["steps"])
        self.assertNotIn("critical_cycles:3", record["steps"])

    def test_ready_timeout_rolls_back(self):
        table = Table(dns_dirty_window=None)
        record = self.record(table)
        self.assertEqual(record["result"], "ready_timeout")
        self.assertNotIn("native_dns_ready", record["steps"])
        self.assertEqual(record["rollback"]["result"], "rollback_restored")

    def test_mihomo_exiting_early_rolls_back(self):
        table = Table(dns_dirty_window=None, process_alive=False)
        record = self.record(table)
        self.assertEqual(record["result"], "mihomo_exited_early")
        self.assertEqual(record["rollback"]["result"], "rollback_restored")

    def test_preflight_blocks_when_mihomo_already_runs(self):
        table = Table(ps_mihomo=True)
        record = self.record(table)
        self.assertEqual(record["result"], "preflight_failed")
        self.assertEqual(record["mutations"], [])
        self.assertNotIn("mihomo_started", record["steps"])

    def test_failed_mihomo_t_stops_before_any_mutation(self):
        table = Table(fail_mutations=(((3, "-t"),),))
        record = self.record(table)
        self.assertTrue(str(record["result"]).startswith("config_invalid"))
        self.assertEqual(record["mutations"], [])
        self.assertNotIn("snapshot", record)

    def test_failed_exit_node_clear_still_rolls_back(self):
        table = Table(fail_mutations=(((2, "--exit-node="),),))
        record = self.record(table)
        self.assertTrue(str(record["result"]).startswith("takeover_error"))
        self.assertEqual(record["rollback"]["result"], "rollback_restored")
        # Snapshot kept the exit node; the no-op restore must not re-set it.
        self.assertIn("exit_node_already_set", record["rollback"]["steps"])

    def test_run_record_and_heartbeat_are_persisted(self):
        table = Table(dns_dirty_window=(1, 61))
        for record, state in run_takeover(table):
            records = list(state.glob("takeover-*.json"))
            self.assertEqual(len(records), 1)
            stored = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(stored["result"], "deadline_reached")
            self.assertTrue((state / "watchdog-heartbeat").is_file())
            self.assertTrue((state / "takeover" / "config.yaml").is_file())


class RollbackTests(unittest.TestCase):
    def write_snapshot(self, state, *, prefs=None, services=(("Wi-Fi", ["192.0.2.53"]),),
                       exit_node_cli=None):
        tail = {"prefs": prefs or {"status": "observed", "ExitNodeID": "nodekey:abc",
                                   "ExitNodeIP": None, "CorpDNS": True,
                                   "RouteAll": False,
                                   "ExitNodeAllowLANAccess": False,
                                   "WantRunning": True}}
        if exit_node_cli is not None:
            tail["exit_node_cli"] = exit_node_cli
        snapshot = {"schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
                    "tailscale": tail,
                    "dns": {"services": [{"service": name, "dnsservers": list(servers),
                                          "status": "observed"} for name, servers in services]}}
        path = state / "pre-start-20261117T000000Z.json"
        path.write_text(json.dumps(snapshot), encoding="utf-8")
        return path

    def test_without_a_snapshot_rollback_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(mod.TakeoverError, "no_snapshot"):
                mod.rollback(tmp, tailscale_path=TS, runner=Table().runner,
                             mutator=Table().mutator, sleep=lambda s: None,
                             now=lambda: 0.0)

    def test_dirty_native_dns_blocks_the_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state)
            table = Table(dns_dirty_window=(0, 10 ** 9))
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_blocked_dirty_dns")
            self.assertEqual(table.mutations, [])

    def test_full_restore_and_its_idempotent_second_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state)
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            table.service_dns["Wi-Fi"] = []
            table.corp_dns_current = False
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            self.assertIn(["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53"],
                          table.mutations)
            after_first = len(table.mutations)
            again = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                 sleep=table.sleep, now=lambda: table.clock,
                                 tailscale_path=TS)
            self.assertEqual(again["result"], "rollback_restored")
            self.assertEqual(len(table.mutations), after_first)  # 同秒重复回退幂等
            self.assertIn("exit_node_already_set", again["steps"])
            self.assertIn("Wi-Fi:unchanged", again["steps"])

    def test_unavailable_snapshot_prefs_restore_nothing_destructive(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, prefs={"status": "unavailable", "reason": "invalid_json"})
            table = Table()
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn("prefs_unavailable_in_snapshot", result["steps"])
            # The live exit node stays exactly as it is: no empty-value guess.
            self.assertEqual([m for m in table.mutations if m[0] == TS], [])
            self.assertIn("Wi-Fi:restored", result["steps"])

    def test_allow_lan_and_accept_dns_restore_and_second_pass_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state)
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            table.corp_dns = False
            table.allow_lan = True
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn([TS, "set", "--accept-dns=true"], table.mutations)
            self.assertIn([TS, "set", "--exit-node-allow-lan-access=false"], table.mutations)
            after = len(table.mutations)
            again = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                 sleep=table.sleep, now=lambda: table.clock,
                                 tailscale_path=TS)
            self.assertEqual(again["result"], "rollback_restored")
            self.assertEqual(len(table.mutations), after)
            self.assertIn("accept_dns_unchanged", again["steps"])
            self.assertIn("allow_lan_unchanged", again["steps"])

    def test_pin_beats_a_newer_post_cutover_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pinned = self.write_snapshot(state)
            newer = {"schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
                     "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:evil",
                                             "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                             "ExitNodeAllowLANAccess": False, "WantRunning": True}},
                     "dns": {"services": []}}
            (state / "pre-start-20261118T000000Z.json").write_text(
                json.dumps(newer), encoding="utf-8")
            mod.write_pin(state, pinned.name)
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["snapshot"], pinned.name)
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            self.assertFalse(any("evil" in json.dumps(item) for item in table.mutations))

    def test_symlink_snapshot_and_symlink_pin_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pinned = self.write_snapshot(state)
            evil = state / "evil.json"
            evil.write_text(json.dumps({
                "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
                "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:evil",
                                        "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                        "ExitNodeAllowLANAccess": False, "WantRunning": True}},
                "dns": {"services": []}}), encoding="utf-8")
            (state / "pre-start-20261118T000000Z.json").symlink_to(evil)
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["snapshot"], pinned.name)
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            link = state / mod.PIN_FILE
            link.symlink_to(evil)
            with self.assertRaisesRegex(mod.TakeoverError, "pin_untrusted"):
                mod.rollback(state, runner=table.runner, mutator=table.mutator,
                             sleep=table.sleep, now=lambda: table.clock,
                             tailscale_path=TS)

    def test_unsafe_exit_node_is_not_passed_to_tailscale(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, prefs={
                "status": "observed", "ExitNodeID": "bad node", "ExitNodeIP": None,
                "CorpDNS": True, "RouteAll": False, "ExitNodeAllowLANAccess": False,
                "WantRunning": True})
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_incomplete")
            self.assertIn("exit_node_unrestorable", result["steps"])
            self.assertEqual([item for item in table.mutations if item[0] == TS], [])

    def test_stable_node_id_is_not_passed_to_tailscale(self):
        stable = "n292kg92CNTRL"
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, prefs={
                "status": "observed", "ExitNodeID": stable, "ExitNodeIP": None,
                "CorpDNS": True, "RouteAll": False, "ExitNodeAllowLANAccess": False,
                "WantRunning": True})
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True

            def runner(argv, timeout):
                if tuple(argv) == (TS, "status", "--json"):
                    body = {
                        "BackendState": "Running", "Self": {"Online": True},
                        "MagicDNSSuffix": "example.ts.net.",
                        "Peer": {"k": {
                            "ID": stable, "DNSName": "pinned-exit.example.ts.net.",
                            "TailscaleIPs": [EXIT_IP], "ExitNodeOption": True, "Online": True,
                        }},
                    }
                    return 0, json.dumps(body), None
                return table.runner(argv, timeout)

            result = mod.rollback(state, runner=runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            self.assertFalse(any(stable in json.dumps(item) for item in table.mutations))
            self.assertNotIn("auto:any", json.dumps(table.mutations))

    def test_unresolved_stable_id_skips_exit_and_still_restores_dns(self):
        stable = "n292kg92CNTRL"
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, prefs={
                "status": "observed", "ExitNodeID": stable, "ExitNodeIP": "",
                "CorpDNS": False, "RouteAll": False, "ExitNodeAllowLANAccess": True,
                "WantRunning": True})
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            table.service_dns["Wi-Fi"] = []
            table.corp_dns = True
            table.allow_lan = False

            def runner(argv, timeout):
                if tuple(argv) == (TS, "status", "--json"):
                    return 0, json.dumps({"BackendState": "Running", "Self": {"Online": True},
                                          "Peer": {}}), None
                return table.runner(argv, timeout)

            result = mod.rollback(state, runner=runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_incomplete")
            self.assertIn("exit_node_unrestorable", result["steps"])
            self.assertIn([TS, "set", "--accept-dns=false"], table.mutations)
            self.assertIn([TS, "set", "--exit-node-allow-lan-access=true"], table.mutations)
            self.assertIn(["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53"],
                          table.mutations)
            self.assertFalse(any(item[2:3] == ["--exit-node=" + stable] for item in table.mutations))

    def test_stored_cli_target_is_used_when_status_has_no_peer(self):
        stable = "n292kg92CNTRL"
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, prefs={
                "status": "observed", "ExitNodeID": stable, "ExitNodeIP": None,
                "CorpDNS": True, "RouteAll": False, "ExitNodeAllowLANAccess": False,
                "WantRunning": True}, exit_node_cli="100.64.0.9")
            table = Table(services=(("Wi-Fi", []),))
            table.exit_node_cleared = True

            def runner(argv, timeout):
                if tuple(argv) == (TS, "status", "--json"):
                    return 1, "", "command_failed"
                return table.runner(argv, timeout)

            result = mod.rollback(state, runner=runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn([TS, "set", "--exit-node=100.64.0.9"], table.mutations)
            self.assertFalse(any(stable in json.dumps(item) for item in table.mutations))

    def test_failed_exit_set_keeps_the_reason_and_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state)
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            table.service_dns["Wi-Fi"] = []
            table.corp_dns = False
            table.allow_lan = True
            detail = 'invalid value "n292kg92CNTRL" for --exit-node; must be IP or peer hostname'

            def mutator(argv):
                if argv[:2] == [TS, "set"] and any(
                        item.startswith("--exit-node=") and item != "--exit-node=" for item in argv[2:]):
                    raise mod.TakeoverError("mutation_failed", detail)
                table.mutator(argv)

            result = mod.rollback(state, runner=table.runner, mutator=mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_incomplete")
            self.assertIn("exit_node:failed", result["steps"])
            self.assertIn("accept_dns_restored", result["steps"])
            self.assertIn("allow_lan_restored", result["steps"])
            self.assertIn("Wi-Fi:restored", result["steps"])
            self.assertEqual(result["failures"][0]["error"], "mutation_failed")
            self.assertIn("must be IP or peer hostname", result["failures"][0]["detail"])
            self.assertIn([TS, "set", "--accept-dns=true"], table.mutations)
            self.assertNotIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)

    def test_mutation_stderr_is_kept_and_credentials_are_redacted(self):
        class Proc:
            returncode = 1
            pid = 4242

            def communicate(self, timeout=None):
                return b"", b'failed tskey-auth-abc123xyz must be IP or peer hostname\n'

        with patch.object(mod.subprocess, "Popen", return_value=Proc()):
            with self.assertRaises(mod.TakeoverError) as caught:
                mod.execute_mutating([TS, "set", "--exit-node=" + EXIT_IP])
        self.assertEqual(str(caught.exception), "mutation_failed")
        self.assertIn("must be IP or peer hostname", caught.exception.detail)
        self.assertNotIn("tskey-auth-abc123xyz", caught.exception.detail)
        self.assertIn("[redacted]", caught.exception.detail)

    def test_one_dns_service_failure_does_not_skip_the_next(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, services=(("Wi-Fi", ["192.0.2.53"]),
                                                 ("Ethernet", ["192.0.2.54"])))
            table = Table(services=(("Wi-Fi", []), ("Ethernet", [])),
                          fail_mutations=(( (0, "/usr/sbin/networksetup"), (2, "Wi-Fi") ),))
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_incomplete")
            self.assertIn("Wi-Fi:failed", result["steps"])
            self.assertIn("Ethernet:restored", result["steps"])

    def test_one_unreadable_scutil_does_not_abort_the_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state)
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            calls = {"dns": 0}

            def runner(argv, timeout):
                if tuple(argv) == ("/usr/sbin/scutil", "--dns"):
                    calls["dns"] += 1
                    if calls["dns"] == 1:
                        return 1, "", "scutil_failed"
                return table.runner(argv, timeout)

            result = mod.rollback(state, runner=runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertGreaterEqual(calls["dns"], 2)
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)

    def test_unreadable_live_prefs_leave_the_exit_node_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state)
            table = Table()

            def runner(argv, timeout):
                if len(argv) >= 2 and argv[-2:] == ["debug", "prefs"]:
                    return 1, "", "prefs_failed"
                return table.runner(argv, timeout)

            result = mod.rollback(state, runner=runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_incomplete")
            self.assertIn("prefs_unreadable", result["steps"])
            self.assertEqual([item for item in table.mutations if item[0] == TS], [])
            self.assertIn("Wi-Fi:restored", result["steps"])

    def _identity(self, lstart, work, args=None):
        command = args if args is not None else f"{MIHOMO} -d {work} -f {work}/config.yaml"
        return f"{lstart} {command}\n"

    def _ps_runner(self, text, table=None):
        table = table or Table()

        def runner(argv, timeout):
            argv = tuple(argv)
            if (len(argv) == 5 and argv[0:2] == ("/bin/ps", "-p")
                    and argv[3:] == ("-o", "lstart=,args=")):
                return 0, text, None
            return table.runner(argv, timeout)

        return runner

    def test_rollback_signals_only_the_confirmed_mihomo_leader(self):
        lstart = "Tue Nov 17 18:09:00 2026"
        work = "/tmp/nmd-owned-work"
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, services=(("Wi-Fi", []),))
            line = self._identity(lstart, work)
            mod.write_owner(state, 4242, MIHOMO, work, runner=self._ps_runner(line))
            owner = json.loads((state / mod.OWNER_FILE).read_text(encoding="utf-8"))
            self.assertEqual(owner["lstart"], lstart)
            self.assertIn(f"-d {work}", owner["args"])
            killed = []

            with patch.object(mod.os, "getpgid", return_value=4242), \
                    patch.object(mod.os, "killpg", side_effect=lambda pgid, sig: killed.append((pgid, sig))):
                result = mod.rollback(state, runner=self._ps_runner(line), mutator=Table().mutator,
                                      sleep=lambda _seconds: None, now=lambda: 0.0,
                                      tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn("owner_signalled", result["steps"])
            self.assertEqual({item[0] for item in killed}, {4242})

            killed.clear()
            gone = self._ps_runner("")
            # ps with an empty body is "not running"; a different comm used to
            # be enough to skip the signal, and it still must not signal.
            with patch.object(mod.os, "getpgid", side_effect=AssertionError("pgid")), \
                    patch.object(mod.os, "killpg", side_effect=AssertionError("signal")):
                result = mod.rollback(state, runner=gone, mutator=Table().mutator,
                                      sleep=lambda _seconds: None, now=lambda: 0.0,
                                      tailscale_path=TS)
            self.assertIn("owner_not_running", result["steps"])

            with patch.object(mod.os, "getpgid", return_value=1), \
                    patch.object(mod.os, "killpg", side_effect=AssertionError("signal")):
                result = mod.rollback(state, runner=self._ps_runner(line), mutator=Table().mutator,
                                      sleep=lambda _seconds: None, now=lambda: 0.0,
                                      tailscale_path=TS)
            self.assertIn("owner_not_session_leader", result["steps"])

    def test_reused_pid_with_the_same_comm_is_not_signalled(self):
        lstart = "Tue Nov 17 18:09:00 2026"
        work = "/tmp/nmd-owned-work"
        reused = self._identity(
            "Wed Nov 18 01:02:03 2026", "/tmp/other-mihomo",
            f"{MIHOMO} -d /tmp/other-mihomo -f /tmp/other-mihomo/config.yaml")
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, services=(("Wi-Fi", []),))
            mod.write_owner(state, 4242, MIHOMO, work,
                            runner=self._ps_runner(self._identity(lstart, work)))
            table = Table(dns_dirty_window=(0, 10 ** 9))
            with patch.object(mod.os, "getpgid", side_effect=AssertionError("pgid")), \
                    patch.object(mod.os, "killpg", side_effect=AssertionError("signal")):
                result = mod.rollback(state, runner=self._ps_runner(reused, table),
                                      mutator=table.mutator, sleep=table.sleep,
                                      now=lambda: table.clock, tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_blocked_dirty_dns")
            self.assertIn("owner_identity_mismatch", result["steps"])
            self.assertEqual(table.mutations, [])

    def test_owner_recorded_without_a_start_time_is_not_signalled(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, services=(("Wi-Fi", []),))
            (state / mod.OWNER_FILE).write_text(json.dumps(
                {"schema_version": 1, "pid": 4242, "mihomo": MIHOMO}), encoding="utf-8")
            with patch.object(mod.os, "killpg", side_effect=AssertionError("signal")):
                result = mod.rollback(state, runner=Table().runner, mutator=Table().mutator,
                                      sleep=lambda _seconds: None, now=lambda: 0.0,
                                      tailscale_path=TS)
            self.assertIn("owner_unconfirmed", result["steps"])
            self.assertEqual(result["result"], "rollback_restored")

    def test_dead_controller_restores_the_pinned_snapshot_and_keeps_user_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            outside = Path(tempfile.mkdtemp())
            self.addCleanup(lambda: __import__("shutil").rmtree(outside, ignore_errors=True))
            kept = state / "user-kept.txt"
            kept.write_text("keep-me", encoding="utf-8")
            outside_file = outside / "user-mihomo.yaml"
            outside_file.write_text("do-not-touch", encoding="utf-8")
            pinned = self.write_snapshot(state, services=(("Wi-Fi", ["192.0.2.53"]),))
            original = pinned.read_bytes()
            mod.write_pin(state, pinned.name)
            table = Table(services=(("Wi-Fi", []),))
            table.exit_node_cleared = True
            result = mod.rollback(state, runner=table.runner, mutator=table.mutator,
                                  sleep=table.sleep, now=lambda: table.clock,
                                  tailscale_path=TS)
            self.assertEqual(result["result"], "rollback_restored")
            self.assertEqual(result["snapshot"], pinned.name)
            self.assertEqual(pinned.read_bytes(), original)
            self.assertEqual(kept.read_text(encoding="utf-8"), "keep-me")
            self.assertEqual((state / mod.PIN_FILE).read_text(encoding="utf-8").find(pinned.name) > 0, True)
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "do-not-touch")
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)


class WorkdirTests(unittest.TestCase):
    def test_validation_refuses_a_symlink_config_without_spawning(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            secret = Path(tmp) / "secret.yaml"
            secret.write_text("secret", encoding="utf-8")
            link = work / "config.yaml"
            link.symlink_to(secret)
            with patch.object(mod.subprocess, "run", side_effect=AssertionError("spawn")):
                ok, detail = mod.run_mihomo_validate(MIHOMO, link, work)
            self.assertFalse(ok)
            self.assertEqual(detail, "config_not_confined")
            self.assertEqual(secret.read_text(encoding="utf-8"), "secret")

    def test_geodata_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            secret = base / "secret"
            secret.write_bytes(b"secret")
            source = base / "src"
            source.mkdir()
            (source / "geoip.metadb").symlink_to(secret)
            (source / "geosite.dat").write_bytes(b"geosite")
            target = base / "work"
            target.mkdir()
            planted = target / "Country.mmdb"
            planted.symlink_to(secret)
            staged, missing = mod.stage_geodata(target, source)
            self.assertNotIn("geoip.metadb", staged)
            self.assertIn("geoip.metadb", missing)
            self.assertIn("geosite.dat", staged)
            self.assertEqual((target / "geosite.dat").read_bytes(), b"geosite")
            self.assertFalse(planted.exists())
            self.assertFalse(planted.is_symlink())
            self.assertEqual(secret.read_bytes(), b"secret")

    def test_omitted_tcp_uses_the_readonly_connector(self):
        seen = {}

        def connector(host, port, timeout):
            seen["target"] = (host, port)
            return {"status": "ok"}

        table = Table(dns_dirty_window=(1, 61))
        with patch.object(macos_readonly, "tcp_connect", connector):
            record = TakeoverFlowTests().record(table, tcp=None)
        self.assertEqual(record["result"], "deadline_reached")
        self.assertEqual(seen["target"], (INPUTS["server"], INPUTS["port"]))

    def test_state_dir_symlink_is_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.mkdir()
            link = Path(tmp) / "link"
            link.symlink_to(real)
            with self.assertRaisesRegex(mod.TakeoverError, "state_dir_symlink"):
                mod.takeover(inputs=INPUTS, profile=PROFILE, minutes=1, mihomo_path=MIHOMO,
                             state_dir=link, runner=Table().runner, mutator=Table().mutator,
                             spawner=Table().spawner, tcp=Table().tcp,
                             exists=lambda path: path == TS, sleep=lambda _s: None,
                             now=lambda: 0.0)
            self.assertEqual(list(real.iterdir()), [])

    def test_symlink_ancestor_and_shared_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            state = link / "state"
            state.mkdir(mode=0o700)
            with self.assertRaisesRegex(mod.TakeoverError, "unsafe_path_symlink"):
                mod.takeover(inputs=INPUTS, profile=PROFILE, minutes=1, mihomo_path=MIHOMO,
                             state_dir=state, runner=Table().runner, mutator=Table().mutator,
                             spawner=Table().spawner, tcp=Table().tcp,
                             exists=lambda path: path == TS, sleep=lambda _s: None,
                             now=lambda: 0.0)
            self.assertEqual([path.name for path in real.iterdir()], ["state"])
            self.assertEqual(list((real / "state").iterdir()), [])
            mod.assert_private_ancestors(base / "not-created-yet")
            base.chmod(0o777)
            nested = base / "nested"
            nested.mkdir(mode=0o700)
            with self.assertRaisesRegex(mod.TakeoverError, "unsafe_path_parent"):
                mod.rollback(nested, runner=Table().runner, mutator=Table().mutator,
                             sleep=lambda _s: None, now=lambda: 0.0, tailscale_path=TS)
            with self.assertRaisesRegex(mod.TakeoverError, "unsafe_path_parent"):
                mod.assert_private_ancestors(base / "not-created-yet")

    def test_ps_identity_accepts_ctime_and_rejects_a_prefix_work_dir(self):
        parsed = mod._parse_ps_identity(
            "Tue Nov  4 18:09:00 2026 /usr/local/bin/mihomo -d /tmp/work -f /tmp/work/config.yaml\n")
        self.assertEqual(parsed[0], "Tue Nov  4 18:09:00 2026")
        self.assertFalse(mod._command_matches(MIHOMO, "/tmp/work",
                                              [MIHOMO, "-d", "/tmp/work-evil", "-f", "/tmp/work-evil/c.yaml"]))
        self.assertTrue(mod._command_matches(MIHOMO, "/tmp/work", parsed[1]))
        self.assertIsNone(mod._parse_ps_identity("mihomo\n"))
        self.assertIsNone(mod._parse_ps_identity(""))

    def test_root_does_not_stage_var_root_geodata(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root_home = base / "var-root"
            user_home = base / "user"
            root_geo = root_home / ".config" / "mihomo"
            user_geo = user_home / ".config" / "mihomo"
            for directory in (root_home, root_home / ".config", root_geo,
                              user_home, user_home / ".config", user_geo):
                directory.mkdir(mode=0o700)
            (root_geo / "geosite.dat").write_bytes(b"root-secret")
            (user_geo / "geosite.dat").write_bytes(b"user-secret")
            account = type("Account", (), {"pw_uid": os.getuid(), "pw_dir": str(user_home),
                                           "pw_name": "alice"})()
            target = base / "work"
            target.mkdir(mode=0o700)
            with patch.object(mod.os, "geteuid", return_value=0), \
                    patch.dict(mod.os.environ, {"SUDO_USER": "alice", "HOME": str(root_home)}), \
                    patch("pwd.getpwnam", return_value=account):
                source = mod.default_geodata_dir()
                staged, _missing = mod.stage_geodata(target, source)
            self.assertEqual(source, user_geo)
            self.assertEqual((target / "geosite.dat").read_bytes(), b"user-secret")
            self.assertIn("geosite.dat", staged)
            with patch.object(mod.os, "geteuid", return_value=0), \
                    patch.dict(mod.os.environ, {"SUDO_USER": "", "HOME": str(root_home)}, clear=False):
                self.assertIsNone(mod.default_geodata_dir())
            staged, missing = mod.stage_geodata(target, None)
            self.assertEqual(staged, [])
            self.assertIn("geosite.dat", missing)
            self.assertIsNone(mod.geodata_dir_for_uid(0))
            self.assertIsNone(mod.geodata_dir_for_uid(True))

    def test_explicit_geodata_symlink_fails_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real"
            real.mkdir(mode=0o700)
            link = base / "linked"
            link.symlink_to(real, target_is_directory=True)
            state = base / "state"
            state.mkdir(mode=0o700)
            with self.assertRaisesRegex(mod.TakeoverError, "unsafe_path_symlink"):
                mod.takeover(inputs=INPUTS, profile=PROFILE, minutes=1, mihomo_path=MIHOMO,
                             state_dir=state, geodata_dir=link, runner=Table().runner,
                             mutator=Table().mutator, spawner=Table().spawner, tcp=Table().tcp,
                             exists=lambda path: path == TS, sleep=lambda _s: None,
                             now=lambda: 0.0)
            self.assertEqual(list(state.iterdir()), [])
            with self.assertRaisesRegex(mod.TakeoverError, "invalid_geodata_dir"):
                mod.resolve_geodata_dir("relative/geodata")


class ContractPins(unittest.TestCase):
    def test_deadline_and_watchdog_constants(self):
        self.assertEqual((mod.DEFAULT_MINUTES, mod.MIN_MINUTES, mod.MAX_MINUTES), (10, 1, 480))
        self.assertEqual(mod.CRITICAL_THRESHOLD, 3)
        self.assertEqual(mod.CHECK_INTERVAL_SECONDS, 20)

    def test_source_never_writes_proxy_or_bypass(self):
        source = (ROOT / "scripts/macos_takeover.py").read_text(encoding="utf-8")
        for banned in (r"-set[a-z]*proxy", r"-setproxystat", r"-setproxybypassdomains",
                       r"-setnetworkserviceenabled", r"--advertise", r"--login",
                       r"--logout", r"--reset", r"paramiko"):
            self.assertNotRegex(source, banned, banned)
        self.assertIn("absolute deadline", mod.HELP)
        self.assertFalse(hasattr(mod, "autostart"))

    def test_minutes_bounds(self):
        for value in (0, -1, 481, "10", True, None):
            with self.subTest(value=value):
                with self.assertRaises(mod.TakeoverError):
                    mod.validate_minutes(value)
        self.assertEqual(mod.validate_minutes(480), 480)


class CLITests(unittest.TestCase):
    def record(self, table, **overrides):
        for record, _ in run_takeover(table, **overrides):
            return record

    def write_snapshot(self, state, **kwargs):
        return RollbackTests.write_snapshot(self, state, **kwargs)

    def _identity(self, lstart, work, args=None):
        return RollbackTests._identity(self, lstart, work, args)

    def _ps_runner(self, text, table=None):
        return RollbackTests._ps_runner(self, text, table)

    def test_parse_requires_inputs_and_valid_minutes(self):
        example = str(ROOT / "examples/macos-mihomo-takeover.inputs.example.json")
        with self.assertRaisesRegex(mod.TakeoverError, "inputs_required"):
            mod._parse_takeover_args([])
        with self.assertRaisesRegex(mod.TakeoverError, "invalid_minutes"):
            mod._parse_takeover_args(["--inputs", example, "--minutes", "abc"])
        with self.assertRaisesRegex(mod.TakeoverError, "invalid_arguments"):
            mod._parse_takeover_args(["--inputs", example, "--bogus", "1"])
        values, rest = mod._parse_takeover_args(
            ["--inputs", example, "--minutes", "10"])
        self.assertEqual(rest, [])
        self.assertEqual(values["minutes"], 10)
        self.assertIsNone(values["geodata_dir"])
        self.assertEqual(values["inputs"], macos_prepare.PLACEHOLDER_INPUTS)
        values, rest = mod._parse_takeover_args(
            ["--inputs", example, "--geodata-dir", "/tmp/nmd-geodata"])
        self.assertEqual(values["geodata_dir"], "/tmp/nmd-geodata")
        self.assertEqual(rest, [])

    def test_process_identity_ps_is_allowlisted_only_for_a_numeric_pid(self):
        with patch.object(macos_readonly, "bounded_run", return_value=(0, b"ok\n", None)) as run:
            code, text, error = macos_prepare.execute(
                ["/bin/ps", "-p", "4242", "-o", "lstart=,args="], 2)
        self.assertEqual((code, text, error), (0, "ok\n", None))
        self.assertEqual(run.call_args.args[0], ["/bin/ps", "-p", "4242", "-o", "lstart=,args="])
        with patch.object(macos_readonly.subprocess, "Popen", side_effect=AssertionError("spawn")):
            for argv in (
                ["/bin/ps", "-p", "4242;rm", "-o", "lstart=,args="],
                ["/bin/ps", "-p", "01", "-o", "lstart=,args="],
                ["/bin/ps", "-axo", "pid=,args="],
                ["/bin/ps", "-p", "1", "-o", "lstart=,args="],
            ):
                with self.subTest(argv=argv):
                    with self.assertRaisesRegex(ValueError, "command_not_allowlisted"):
                        macos_prepare.execute(argv, 2)

    def test_help_and_invalid_options_do_not_escalate(self):
        for argv in (
            ["takeover", "--help"],
            ["rollback", "-h"],
            ["accept", "--help"],
            ["takeover", "--inputs", "x", "--help"],
            ["accept", "--inputs", "x", "--state-dir", "y", "-h"],
        ):
            with patch.object(mod.os, "execv", side_effect=AssertionError("execv")), \
                    patch.object(mod.os, "execvp", side_effect=AssertionError("execvp")), \
                    patch.object(mod, "takeover", side_effect=AssertionError("takeover")):
                self.assertEqual(mod.main(argv), 0, argv)
        for argv in (
            ["takeover", "--bogus"],
            ["accept", "--inputs", "x"],
            ["rollback", "--nope"],
            ["takeover", "--inputs", "x", "--minutes"],
            ["accept", "--inputs", "x", "--state-dir", "y", "--minutes", "10"],
        ):
            with patch.object(mod.os, "execv", side_effect=AssertionError("execv")), \
                    patch.object(mod.os, "execvp", side_effect=AssertionError("execvp")), \
                    patch.object(mod, "takeover", side_effect=AssertionError("takeover")):
                self.assertEqual(mod.main(argv), 2, argv)

    def test_non_root_reexec_uses_absolute_sudo(self):
        # Keep the real euid. A fake uid does not own this checkout, so the
        # trust check would refuse a path that the actual user can run.
        if os.geteuid() == 0:
            self.skipTest("already root")
        with patch.object(mod.os, "execvp", side_effect=AssertionError("execvp")), \
                patch.object(mod.os, "execv", side_effect=SystemExit(0)) as invoked:
            try:
                code = mod.main(["rollback"])
            except SystemExit:
                self.assertEqual(invoked.call_args.args[0], "/usr/bin/sudo")
                self.assertEqual(invoked.call_args.args[1][0], "/usr/bin/sudo")
                self.assertNotIn("sudo", invoked.call_args.args[1][1:])
                return
        self.assertFalse(invoked.called)
        self.assertEqual(code, 2)

    def test_daemon_help_and_invalid_do_not_escalate(self):
        import nmd_daemon
        for argv, expected in ((["takeover-start", "--help"], 0),
                               (["takeover-start", "--bogus"], 2),
                               (["supervise", "--bogus"], 2)):
            with patch.object(nmd_daemon.os, "execv", side_effect=AssertionError("execv")), \
                    patch.object(nmd_daemon.os, "execvp", side_effect=AssertionError("execvp")), \
                    patch.object(mod.os, "execv", side_effect=AssertionError("execv")), \
                    patch.object(mod.os, "execvp", side_effect=AssertionError("execvp")):
                code = (nmd_daemon.cli_daemon(argv) if argv[0] != "supervise"
                        else nmd_daemon.main(argv))
            self.assertEqual(code, expected, argv)

    def _ready_arm(self, state, pin, deadline):
        return {"ready": True, "pid": 1, "pgid": 2, "pin": pin}

    def test_accept_refuses_unknown_preflight_before_any_mutation(self):
        def runner(argv, timeout):
            if tuple(argv) == ("/usr/sbin/scutil", "--dns"):
                return 1, "", "scutil_failed"
            return Table().runner(argv, timeout)

        def arm(*_args):
            raise AssertionError("watchdog armed before a known preflight")

        table = Table()
        record = self.record(table, runner=runner, external_rollback=True, arm_watchdog=arm)
        self.assertEqual(record["result"], "preflight_unknown")
        self.assertEqual(record["mutations"], [])
        self.assertFalse(any(item[0] == TS or "networksetup" in item[0] for item in table.mutations))

    def test_watchdog_not_ready_changes_nothing(self):
        def arm(*_args):
            return {"ready": None, "reason": "ready_unknown"}

        table = Table()
        record = self.record(table, external_rollback=True, arm_watchdog=arm)
        self.assertEqual(record["result"], "watchdog_not_ready")
        self.assertEqual(record["mutations"], [])
        self.assertFalse(any(item[0] == TS for item in table.mutations))
        self.assertFalse(record["guarantees_restore_if_watchdog_dies"])

    def test_engaged_pin_blocks_the_controller_before_cutover(self):
        def arm(state, pin, _deadline):
            mod._mark_engaged(state, pin)
            return {"ready": True, "pid": 1, "pgid": 2, "pin": pin}

        table = Table()
        record = self.record(table, external_rollback=True, arm_watchdog=arm)
        self.assertIn("rollback_already_engaged", record["result"])
        self.assertNotIn([TS, "set", "--exit-node="], table.mutations)
        self.assertEqual(record["rollback"]["result"], "rollback_restored")

    def test_external_stop_still_restores(self):
        table = Table(dns_dirty_window=(1, 21))
        handlers = {}

        def fake_signal(sig, handler):
            handlers[sig] = handler
            return None

        def sleeping(seconds):
            table.clock += seconds
            if signal.SIGINT in handlers:
                handlers.pop(signal.SIGINT)()

        with patch.object(mod.signal, "signal", side_effect=fake_signal):
            record = self.record(table, sleep=sleeping, external_rollback=True,
                                 arm_watchdog=self._ready_arm)
        self.assertEqual(record["result"], "stopped")
        self.assertEqual(record["rollback"]["result"], "rollback_restored")
        self.assertIn("watchdog_ready", record["steps"])
        self.assertFalse(record["guarantees_restore_if_watchdog_dies"])

    def test_external_partial_dns_failure_continues(self):
        table = Table(services=(("Wi-Fi", ["192.0.2.53"]), ("Ethernet", ["192.0.2.54"])),
                      fail_mutations=(((0, "/usr/sbin/networksetup"), (2, "Wi-Fi")),))

        def arm(state, pin, deadline):
            table.service_dns["Wi-Fi"] = []
            table.service_dns["Ethernet"] = []
            return self._ready_arm(state, pin, deadline)

        record = self.record(table, external_rollback=True, arm_watchdog=arm)
        self.assertEqual(record["rollback"]["result"], "rollback_incomplete")
        self.assertIn("Wi-Fi:failed", record["rollback"]["steps"])
        self.assertIn("Ethernet:restored", record["rollback"]["steps"])

    def test_accept_config_disables_geo_auto_update(self):
        generated = run_takeover(
            Table(), external_rollback=True, geo_auto_update=False,
            arm_watchdog=lambda *_args: {"ready": False})
        record, state = next(generated)
        text = (state / "takeover" / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("geo-auto-update: false", text)
        self.assertEqual(record["result"], "watchdog_not_ready")
        normal = macos_prepare.render_config(PROFILE, INPUTS)
        self.assertIn("geo-auto-update: true", normal)

    def test_production_state_and_daemon_socket_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            with patch.object(mod, "_production_state_paths", return_value={path.as_posix()}):
                with self.assertRaisesRegex(mod.TakeoverError, "production_state_forbidden"):
                    mod.assert_acceptance_state(path)
        table = Table()
        with patch.object(mod, "_daemon_conflict", return_value=True):
            with self.assertRaisesRegex(mod.TakeoverError, "daemon_conflict"):
                self.record(table, external_rollback=True)
        self.assertEqual(table.mutations, [])

    def test_a_live_watchdog_blocks_another_accept_in_the_same_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            document = {"ready": True, "pid": os.getpid(), "pgid": 9, "euid": 0,
                        "pin": "pre-start-20260101T000000Z.json",
                        "deadline_unix": int(time.time()) + 120}
            (state / mod.READY_FILE).write_text(json.dumps(document), encoding="utf-8")
            table = Table()
            options = dict(
                inputs=INPUTS, profile=PROFILE, minutes=1, mihomo_path=MIHOMO,
                state_dir=tmp, runner=table.runner, mutator=table.mutator,
                spawner=table.spawner, tcp=table.tcp, exists=lambda path: path == TS,
                sleep=table.sleep, now=lambda: table.clock, external_rollback=True,
                arm_watchdog=lambda *_args: (_ for _ in ()).throw(AssertionError("armed")))
            with self.assertRaisesRegex(mod.TakeoverError, "watchdog_conflict"):
                mod.takeover(**options)
            self.assertEqual(table.mutations, [])
            with patch.object(mod, "_pid_alive", return_value=False):
                record = mod.takeover(**dict(options, arm_watchdog=lambda *_args: {"ready": False}))
            self.assertEqual(record["result"], "watchdog_not_ready")
            self.assertFalse(any(item[0] == TS for item in table.mutations))

    def test_launch_is_inside_the_rollback_lock(self):
        table = Table(dns_dirty_window=(1, 21))
        seen = {}

        def spawner(_argv, log_path):
            import fcntl
            lock = Path(log_path).parent.parent / "rollback.lock"
            handle = open(lock, "a+b")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                seen["held"] = True
            else:
                seen["held"] = False
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()
            return FakeProcess(table)

        self.record(table, external_rollback=True, arm_watchdog=self._ready_arm,
                    spawner=spawner)
        self.assertTrue(seen["held"])

    def test_deadline_marker_is_a_normal_completion(self):
        table = Table(dns_dirty_window=(1, 21))
        clock = {"wall": None}

        def wall():
            return 1_700_000_000 if clock["wall"] is None else clock["wall"]

        def arm(state, pin, deadline):
            clock["deadline"] = deadline
            clock["state"] = state
            clock["pin"] = pin
            return {"ready": True, "pid": 1, "pgid": 2, "pin": pin}

        def sleeping(seconds):
            table.clock += seconds
            clock["wall"] = clock["deadline"]
            mod._mark_engaged(clock["state"], clock["pin"])

        with patch.object(mod.time, "time", side_effect=wall):
            record = self.record(table, sleep=sleeping, external_rollback=True,
                                 arm_watchdog=arm)
        self.assertEqual(record["result"], "deadline_reached")
        self.assertEqual(record["rollback"]["result"], "rollback_restored")

    def test_watchdog_spawn_keeps_the_validated_user(self):
        import pwd
        account = pwd.getpwuid(os.getuid())
        if account.pw_uid == 0 or not mod._ACCOUNT_NAME.fullmatch(account.pw_name):
            self.skipTest("no ordinary account name")
        captured = {}

        def popen(argv, **kwargs):
            captured["env"] = kwargs["env"]
            captured["argv"] = argv

            class Child:
                pid = 1

                def poll(self):
                    return 0

            return Child()

        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {"SUDO_USER": account.pw_name}, clear=False), \
                patch.object(mod, "_trusted_interpreter", return_value=Path("/usr/bin/python3")), \
                patch.object(mod, "_trusted_script", return_value=Path("/usr/bin/nmd-script")), \
                patch.object(mod.subprocess, "Popen", side_effect=popen):
            mod._spawn_watch(Path(tmp), "pre-start-20260101T000000Z.json", 50)
        self.assertEqual(captured["argv"][:2], ["/usr/bin/python3", "/usr/bin/nmd-script"])
        self.assertEqual(captured["env"]["SUDO_USER"], account.pw_name)
        self.assertEqual(captured["env"]["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertNotIn("HOME", captured["env"])

    def test_past_deadline_watchdog_still_blocks_until_it_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            document = {"ready": True, "pid": os.getpid(), "pgid": 9, "euid": 0,
                        "pin": "pre-start-20260101T000000Z.json",
                        "deadline_unix": int(time.time()) - 5}
            (state / mod.READY_FILE).write_text(json.dumps(document), encoding="utf-8")
            self.assertTrue(mod._watchdog_still_running(state))
            with patch.object(mod, "_pid_alive", return_value=False):
                self.assertFalse(mod._watchdog_still_running(state))

    def test_confirm_ready_rejects_unknown_and_shared_group(self):
        document = {"ready": True, "pid": 7, "pgid": 8, "euid": 0,
                    "pin": "pre-start-20260101T000000Z.json", "deadline_unix": 50}
        probe = lambda pid: {"alive": True, "pgid": 8, "uid": 0}
        ok = mod.confirm_ready(document, expected_pin=document["pin"], expected_deadline=50,
                               child_pid=7, parent_pgid=3, probe=probe)
        self.assertTrue(ok["ready"])
        shared = mod.confirm_ready(document, expected_pin=document["pin"], expected_deadline=50,
                                   child_pid=7, parent_pgid=8, probe=probe)
        self.assertEqual(shared["reason"], "not_independent")
        unknown = mod.confirm_ready(document, expected_pin=document["pin"], expected_deadline=50,
                                    child_pid=7, parent_pgid=3,
                                    probe=lambda pid: {"alive": None, "pgid": 8, "uid": 0})
        self.assertEqual(unknown["reason"], "ready_unknown")
        mismatch = dict(document, pin="pre-start-20260101T000001Z.json")
        self.assertEqual(mod.confirm_ready(
            document, expected_pin=mismatch["pin"], expected_deadline=50,
            child_pid=7, parent_pgid=3, probe=probe)["reason"], "ready_unknown")

    def test_handshake_timeout_and_planted_ready_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pin = "pre-start-20260101T000000Z.json"

            class Child:
                pid = 4321

                def poll(self):
                    return None

                def wait(self, timeout=None):
                    return 0

            calls = {"n": 0}

            def now():
                calls["n"] += 1
                return 0 if calls["n"] < 3 else 100

            result = mod.arm_external_watchdog(
                state, pin, 99, spawn=lambda *_args: Child(), probe=lambda pid: {"alive": True},
                sleep=lambda _seconds: None, now=now)
            self.assertEqual(result["reason"], "watchdog_handshake_timeout")
            ready = state / mod.READY_FILE
            ready.symlink_to("planted")
            result = mod.arm_external_watchdog(
                state, pin, 99, spawn=lambda *_args: (_ for _ in ()).throw(AssertionError("spawn")),
                now=lambda: 0)
            self.assertEqual(result["reason"], "ready_unknown")

    def test_watch_uses_the_original_pin_after_parent_death_and_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state)
            name = next(state.glob("pre-start-*.json")).name
            mod.write_pin(state, name)
            table = Table()
            table.exit_node_cleared = True
            clock = {"now": 0}

            def rollback_fn(state_dir, snapshot_name=None):
                return mod.rollback(state_dir, snapshot_name=snapshot_name, runner=table.runner,
                                    mutator=table.mutator, sleep=lambda _seconds: None,
                                    now=lambda: 0.0, tailscale_path=TS)

            result = mod.run_rollback_watch(
                state, pin=name, deadline_unix=10 ** 12, parent_pid=1,
                now=lambda: clock["now"], sleep=lambda _seconds: None,
                alive=lambda _pid: False, rollback_fn=rollback_fn)
            self.assertEqual(result["trigger"], "parent_dead")
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            before = len(table.mutations)
            again = rollback_fn(state, snapshot_name=name)
            self.assertEqual(again["result"], "rollback_restored")
            self.assertEqual(len(table.mutations), before)

            clock["now"] = 0

            def later(_seconds):
                clock["now"] = 100

            calls = []

            def counting(state_dir, snapshot_name=None):
                calls.append(snapshot_name)
                return {"result": "rollback_restored"}

            result = mod.run_rollback_watch(
                state, pin=name, deadline_unix=50, parent_pid=1,
                now=lambda: clock["now"], sleep=later, alive=lambda _pid: True,
                rollback_fn=counting)
            self.assertEqual(calls, [name])
            self.assertEqual(result["trigger"], "deadline")

    def test_watch_does_not_signal_a_mismatched_mihomo(self):
        lstart = "Tue Nov 17 18:09:00 2026"
        work = "/tmp/nmd-owned-work"
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            self.write_snapshot(state, services=(("Wi-Fi", []),))
            name = next(state.glob("pre-start-*.json")).name
            mod.write_pin(state, name)
            mod.write_owner(state, 4242, MIHOMO, work, runner=self._ps_runner(self._identity(lstart, work)))
            other = self._identity("Wed Nov 18 18:09:00 2026", work)

            def rollback_fn(state_dir, snapshot_name=None):
                return mod.rollback(state_dir, snapshot_name=snapshot_name,
                                    runner=self._ps_runner(other), mutator=Table().mutator,
                                    sleep=lambda _seconds: None, now=lambda: 0.0,
                                    tailscale_path=TS)

            with patch.object(mod.os, "getpgid", side_effect=AssertionError("pgid")), \
                    patch.object(mod.os, "killpg", side_effect=AssertionError("signal")):
                result = mod.run_rollback_watch(
                    state, pin=name, deadline_unix=10 ** 12, parent_pid=1,
                    now=lambda: 0, sleep=lambda _seconds: None, alive=lambda _pid: False,
                    rollback_fn=rollback_fn)
            self.assertIn("owner_identity_mismatch", result["steps"])

    def test_engaged_marker_for_another_snapshot_does_not_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            current = "pre-start-20260101T000000Z.json"
            other = "pre-start-20260101T000001Z.json"
            mod._mark_engaged(state, other)
            self.assertFalse(mod._mutation_blocked(state, current))
            mod._mark_engaged(state, current)
            self.assertTrue(mod._mutation_blocked(state, current))
            (state / mod.ENGAGED_FILE).unlink()
            (state / mod.ENGAGED_FILE).symlink_to(current)
            self.assertTrue(mod._mutation_blocked(state, current))

    def test_unknown_subcommand_and_help_exit_codes(self):
        script = str(ROOT / "scripts/macos_takeover.py")
        for argv, expected in ((["bogus"], 2), (["help"], 0)):
            result = subprocess.run([sys.executable, script, *argv],
                                    check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, argv)
        result = subprocess.run([sys.executable, script], check=False,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

    def test_manager_dispatches_macos_only_on_darwin(self):
        import manager
        with patch.object(manager.nmd_platform, "name", return_value="macos"), \
                patch("macos_takeover.main", return_value=0) as cli:
            with self.assertRaises(SystemExit) as ctx:
                manager.main(["macos", "rollback", "--state-dir", "/tmp/x"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(cli.call_args.args, (["rollback", "--state-dir", "/tmp/x"],))
        with patch.object(manager.nmd_platform, "name", return_value="linux"):
            with self.assertRaises(SystemExit):
                manager.main(["macos", "rollback"])


class PowerAndSentinelTests(unittest.TestCase):
    """Watchdog death and sleep/wake. Clocks and observations are injected.

    Nothing here sleeps a Mac or touches a live network. ``sleep_wake_verified``
    stays false for that reason.
    """

    def write_snapshot(self, state, **kwargs):
        return RollbackTests.write_snapshot(self, state, **kwargs)

    def _rollback(self, table):
        def rollback_fn(state_dir, snapshot_name=None):
            return mod.rollback(
                state_dir, snapshot_name=snapshot_name, runner=table.runner,
                mutator=table.mutator, sleep=lambda _seconds: None, now=lambda: 0.0,
                tailscale_path=TS)
        return rollback_fn

    def _arm(self, state, pin, _deadline):
        return {"ready": True, "pid": 1, "pgid": 2, "pin": pin, "sentinel_ready": True}

    def test_power_gap_is_wake_only_when_wall_time_runs_ahead(self):
        self.assertIsNone(mod.classify_power_gap(0, 20, 0, 20))
        self.assertEqual(mod.classify_power_gap(0, 30, 0, 1), "wake")
        self.assertEqual(mod.classify_power_gap(100, 90, 0, 1), "clock_step")
        self.assertIsNone(mod.classify_power_gap(0, 1.5, 0, 0))
        self.assertIsNone(mod.classify_power_gap("nope", 1, 0, 0))

    def test_wake_decision_restores_broken_managed_state_and_keeps_a_good_one(self):
        healthy = {"has_198_18": True, "exit_cleared": True,
                   "default_route_present": True, "proxy_enabled": {}}
        self.assertEqual(mod.wake_decision(
            woke=False, deadline_due=False, mihomo_alive=True, observed=healthy,
            expected_proxy={})["action"], "continue")
        self.assertEqual(mod.wake_decision(
            woke=True, deadline_due=True, mihomo_alive=True, observed=healthy,
            expected_proxy={})["reasons"], ["deadline_reached"])
        broken = dict(healthy, has_198_18=False, exit_cleared=False,
                      default_route_present=False, proxy_enabled={"HTTP": True})
        reasons = mod.wake_decision(
            woke=True, deadline_due=False, mihomo_alive=False, observed=broken,
            expected_proxy={})["reasons"]
        for reason in ("mihomo_not_alive", "native_dns_missing", "exit_node_not_cleared",
                       "default_route_missing", "proxy_drift"):
            self.assertIn(reason, reasons)
        starting = mod.wake_decision(
            woke=True, deadline_due=False, mihomo_alive=True,
            observed=dict(healthy, has_198_18=False), expected_proxy={},
            require_native_dns=False)
        self.assertEqual(starting["action"], "continue")
        unknown = mod.wake_decision(
            woke=True, deadline_due=False, mihomo_alive=True,
            observed={"has_198_18": None, "exit_cleared": None,
                      "default_route_present": None, "proxy_enabled": None},
            expected_proxy={})
        self.assertEqual(unknown["action"], "rollback")
        self.assertIn("dns_unknown", unknown["reasons"])
        self.assertIn("proxy_unknown", unknown["reasons"])

    def test_sentinel_restores_the_pinned_exit_when_the_watchdog_dies(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pinned = self.write_snapshot(state)
            mod.write_pin(state, pinned.name)
            (state / "pre-start-20261118T000000Z.json").write_text(json.dumps({
                "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
                "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:evil",
                                         "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                         "ExitNodeAllowLANAccess": False, "WantRunning": True}},
                "dns": {"services": []}}), encoding="utf-8")
            table = Table(services=(("Wi-Fi", ["192.0.2.53"]),))
            table.exit_node_cleared = True
            table.service_dns["Wi-Fi"] = []
            result = mod.run_restore_sentinel(
                state, pin=pinned.name, deadline_unix=10 ** 12, watchdog_pid=4242,
                parent_pid=7, now=lambda: 0, sleep=lambda _seconds: None,
                alive=lambda _pid: False, rollback_fn=self._rollback(table))
            self.assertEqual(result["trigger"], "watchdog_dead")
            self.assertEqual(result["result"], "rollback_restored")
            self.assertFalse(result["guarantees_restore_if_watchdog_dies"])
            self.assertFalse(mod.GUARANTEES_RESTORE_IF_WATCHDOG_DIES)
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            rendered = json.dumps(table.mutations)
            self.assertNotIn("nodekey:", rendered)
            self.assertNotIn("auto:any", rendered)
            self.assertEqual((state / mod.SENTINEL_RESULT_FILE).is_file(), True)

    def test_sentinel_does_not_mutate_after_the_watchdog_already_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pinned = self.write_snapshot(state)
            mod.write_pin(state, pinned.name)
            (state / mod.WATCH_RESULT_FILE).write_text(json.dumps({
                "result": "rollback_restored", "pin": pinned.name,
                "deadline_unix": 50, "pid": 4242,
            }), encoding="utf-8")

            def boom(*_args, **_kwargs):
                raise AssertionError("rollback")

            result = mod.run_restore_sentinel(
                state, pin=pinned.name, deadline_unix=50, watchdog_pid=4242,
                parent_pid=7, now=lambda: 0, sleep=lambda _seconds: None,
                alive=lambda _pid: False, rollback_fn=boom)
            self.assertEqual(result["trigger"], "watchdog_restored")
            self.assertEqual(result["result"], "rollback_restored")
            self.assertFalse(result["guarantees_restore_if_watchdog_dies"])

    def test_a_previous_runs_restored_result_does_not_finish_this_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pinned = self.write_snapshot(state, services=(("Wi-Fi", []),))
            mod.write_pin(state, pinned.name)
            (state / mod.WATCH_RESULT_FILE).write_text(
                json.dumps({"result": "rollback_restored", "pin": "pre-start-old.json",
                            "deadline_unix": 1, "pid": 9}), encoding="utf-8")
            table = Table(services=(("Wi-Fi", []),))
            table.exit_node_cleared = True
            result = mod.run_restore_sentinel(
                state, pin=pinned.name, deadline_unix=50, watchdog_pid=4242,
                parent_pid=7, now=lambda: 0, sleep=lambda _seconds: None,
                alive=lambda _pid: False, rollback_fn=self._rollback(table))
            self.assertEqual(result["trigger"], "watchdog_dead")
            self.assertEqual(result["result"], "rollback_restored")
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            self.assertNotIn("nodekey:", json.dumps(table.mutations))

    def test_arm_drops_a_previous_result_and_refuses_a_result_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pin = "pre-start-20260101T000000Z.json"
            (state / mod.WATCH_RESULT_FILE).write_text(
                json.dumps({"result": "rollback_restored"}), encoding="utf-8")
            (state / mod.SENTINEL_RESULT_FILE).write_text(
                json.dumps({"result": "rollback_restored"}), encoding="utf-8")
            seen = {}

            class Child:
                def __init__(self, pid):
                    self.pid = pid

                def poll(self):
                    return None

                def wait(self, timeout=None):
                    return 0

            def write_ready(path, pid):
                path.write_text(json.dumps({
                    "ready": True, "pid": pid, "pgid": pid, "euid": 0,
                    "pin": pin, "deadline_unix": 80,
                }), encoding="utf-8")

            def spawn_watch(state_dir, _pin, _deadline):
                seen["watch"] = not (Path(state_dir) / mod.WATCH_RESULT_FILE).exists()
                seen["sentinel"] = not (Path(state_dir) / mod.SENTINEL_RESULT_FILE).exists()
                write_ready(Path(state_dir) / mod.READY_FILE, 70)
                return Child(70)

            def spawn_sentinel(state_dir, *_args):
                write_ready(Path(state_dir) / mod.SENTINEL_READY_FILE, 71)
                return Child(71)

            probe = lambda pid: {"alive": True, "pgid": pid, "uid": 0}
            with patch.object(mod.os, "kill", lambda *_args, **_kwargs: None):
                armed = mod.arm_external_watchdog(
                    state, pin, 80, spawn=spawn_watch, spawn_sentinel=spawn_sentinel,
                    probe=probe, sleep=lambda _seconds: None, now=lambda: 0)
            self.assertTrue(armed["sentinel_ready"])
            self.assertEqual(seen, {"watch": True, "sentinel": True})

            (state / mod.WATCH_RESULT_FILE).symlink_to(state / "not-a-result")

            def refused(*_args, **_kwargs):
                raise AssertionError("spawned")

            blocked = mod.arm_external_watchdog(
                state, pin, 80, spawn=refused, spawn_sentinel=refused,
                probe=probe, sleep=lambda _seconds: None, now=lambda: 0)
            self.assertEqual(blocked, {"ready": False, "reason": "ready_unknown"})
            self.assertTrue((state / mod.WATCH_RESULT_FILE).is_symlink())

    def test_sentinel_takes_over_when_the_watchdog_stays_silent_past_grace(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pinned = self.write_snapshot(state, services=(("Wi-Fi", []),))
            mod.write_pin(state, pinned.name)
            table = Table(services=(("Wi-Fi", []),))
            table.exit_node_cleared = True
            clock = {"now": 0}

            def sleeping(_seconds):
                clock["now"] = 10 + mod.SENTINEL_GRACE_SECONDS

            result = mod.run_restore_sentinel(
                state, pin=pinned.name, deadline_unix=10, watchdog_pid=4242,
                parent_pid=7, now=lambda: clock["now"], sleep=sleeping,
                alive=lambda _pid: True, rollback_fn=self._rollback(table))
            self.assertEqual(result["trigger"], "watchdog_stuck")
            self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
            self.assertNotIn("nodekey:", json.dumps(table.mutations))

    def test_controller_rolls_back_when_its_watchdog_dies_after_cutover(self):
        table = Table()
        dead = {"value": False}

        def arm(state, pin, _deadline):
            return {"ready": True, "pid": 4242, "pgid": 9, "pin": pin,
                    "sentinel_ready": True}

        def mutator(argv):
            table.mutator(argv)
            if list(argv[:3]) == [TS, "set", "--exit-node="]:
                dead["value"] = True

        def alive(_pid):
            return not dead["value"]

        with patch.object(mod, "_pid_alive", side_effect=alive):
            record = TakeoverFlowTests().record(
                table, external_rollback=True, arm_watchdog=arm, mutator=mutator)
        self.assertEqual(record["result"], "watchdog_died")
        self.assertEqual(record["rollback"]["result"], "rollback_restored")
        self.assertTrue(record["restore_sentinel_armed"])
        self.assertFalse(record["guarantees_restore_if_watchdog_dies"])
        self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
        rendered = json.dumps(table.mutations)
        self.assertNotIn("nodekey:", rendered)
        self.assertNotIn("auto:any", rendered)

    def test_sentinel_not_ready_is_zero_change(self):
        def arm(*_args):
            return {"ready": False, "reason": "sentinel_not_ready"}

        table = Table()
        record = TakeoverFlowTests().record(
            table, external_rollback=True, arm_watchdog=arm)
        self.assertEqual(record["result"], "watchdog_not_ready")
        self.assertEqual(record["restore_sentinel_armed"], False)
        self.assertFalse(record["guarantees_restore_if_watchdog_dies"])
        self.assertFalse(any(item[0] == TS for item in table.mutations))

    def test_a_live_sentinel_blocks_another_accept(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / mod.SENTINEL_READY_FILE).write_text(json.dumps({
                "ready": True, "pid": os.getpid(), "pgid": 9, "euid": 0,
                "pin": "pre-start-20260101T000000Z.json",
                "deadline_unix": int(time.time()) + 120,
            }), encoding="utf-8")
            table = Table()
            with self.assertRaisesRegex(mod.TakeoverError, "sentinel_conflict"):
                mod.takeover(
                    inputs=INPUTS, profile=PROFILE, minutes=1, mihomo_path=MIHOMO,
                    state_dir=state, runner=table.runner, mutator=table.mutator,
                    spawner=table.spawner, tcp=table.tcp, exists=lambda path: path == TS,
                    sleep=table.sleep, now=lambda: table.clock, external_rollback=True,
                    arm_watchdog=lambda *_args: (_ for _ in ()).throw(AssertionError("armed")))
            self.assertEqual(table.mutations, [])

    def test_arm_accepts_only_after_both_processes_are_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            pin = "pre-start-20260101T000000Z.json"
            stopped = []

            class Child:
                def __init__(self, pid, polls=None):
                    self.pid = pid
                    self._polls = polls

                def poll(self):
                    if self._polls:
                        return self._polls.pop(0)
                    return None

                def wait(self, timeout=None):
                    stopped.append(self.pid)
                    return 0

            def write_ready(path, pid):
                path.write_text(json.dumps({
                    "ready": True, "pid": pid, "pgid": pid, "euid": 0,
                    "pin": pin, "deadline_unix": 80,
                }), encoding="utf-8")

            def spawn_watch(state_dir, _pin, _deadline):
                write_ready(Path(state_dir) / mod.READY_FILE, 70)
                return Child(70)

            seen = {}

            def spawn_sentinel(state_dir, _pin, _deadline, watchdog_pid):
                seen["watchdog"] = watchdog_pid
                write_ready(Path(state_dir) / mod.SENTINEL_READY_FILE, 71)
                return Child(71)

            probe = lambda pid: {"alive": True, "pgid": pid, "uid": 0}
            with patch.object(mod.os, "kill", lambda *_args, **_kwargs: None):
                armed = mod.arm_external_watchdog(
                    state, pin, 80, spawn=spawn_watch, spawn_sentinel=spawn_sentinel,
                    probe=probe, sleep=lambda _seconds: None, now=lambda: 0)
            self.assertTrue(armed["ready"])
            self.assertTrue(armed["sentinel_ready"])
            self.assertEqual(seen["watchdog"], 70)
            self.assertEqual(armed["sentinel_pid"], 71)
            self.assertFalse(armed["guarantees_restore_if_watchdog_dies"])
            self.assertEqual(stopped, [])

            calls = {"n": 0}

            def later():
                calls["n"] += 1
                return 0 if calls["n"] < 6 else 1000

            def silent(*_args):
                return Child(81)

            with patch.object(mod.os, "kill", lambda *_args, **_kwargs: None):
                failed = mod.arm_external_watchdog(
                    state, pin, 80, spawn=spawn_watch, spawn_sentinel=silent,
                    probe=probe, sleep=lambda _seconds: None, now=later)
            self.assertFalse(failed["ready"])
            self.assertEqual(failed["reason"], "sentinel_not_ready")
            self.assertIn(70, stopped)
            self.assertIn(81, stopped)

    def test_wake_with_broken_dns_restores_the_exit_by_ip(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        clocks = {"wall": 2_000.0}

        def wall():
            return clocks["wall"]

        def sleeping(_seconds):
            table.clock += 0.1
            clocks["wall"] += 30
            table.dns_dirty_window = None

        record = TakeoverFlowTests().record(
            table, minutes=10, wall=wall, sleep=sleeping, external_rollback=True,
            arm_watchdog=self._arm)
        self.assertEqual(record["result"], "wake_restore")
        self.assertIn("wake:restore", record["steps"])
        self.assertIn("native_dns_missing", record["wake"]["reasons"])
        self.assertEqual(record["rollback"]["result"], "rollback_restored")
        self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
        rendered = json.dumps(table.mutations)
        self.assertNotIn("nodekey:", rendered)
        self.assertNotIn("auto:any", rendered)
        self.assertNotIn("proxy", rendered)
        self.assertFalse(record["guarantees_restore_if_watchdog_dies"])

    def test_proxy_drift_on_wake_restores_managed_state_without_writing_proxy(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        clocks = {"wall": 3_000.0}

        def wall():
            return clocks["wall"]

        def sleeping(_seconds):
            table.clock += 0.1
            clocks["wall"] += 20
            table.proxy_text = (
                "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 127.0.0.1\n"
                "  HTTPPort : 8080\n}\n")
            table.dns_dirty_window = None

        record = TakeoverFlowTests().record(
            table, minutes=10, wall=wall, sleep=sleeping, external_rollback=True,
            arm_watchdog=self._arm)
        self.assertEqual(record["result"], "wake_restore")
        self.assertIn("proxy_drift", record["wake"]["reasons"])
        self.assertNotIn("proxy", json.dumps(table.mutations))
        self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)

    def test_a_healthy_wake_keeps_the_absolute_wall_deadline(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        clocks = {"wall": 10_000.0}
        jumps = {"n": 0}

        def wall():
            return clocks["wall"]

        def sleeping(_seconds):
            table.clock += 1
            jumps["n"] += 1
            if jumps["n"] == 1:
                clocks["wall"] += 15
            else:
                clocks["wall"] += 600
                table.dns_dirty_window = None

        record = TakeoverFlowTests().record(
            table, minutes=10, wall=wall, sleep=sleeping, external_rollback=True,
            arm_watchdog=self._arm)
        self.assertEqual(record["result"], "deadline_reached")
        self.assertIn("wake:continue", record["steps"])
        self.assertEqual(record["rollback"]["result"], "rollback_restored")
        self.assertLess(table.clock, 30)


if __name__ == "__main__":
    unittest.main()
