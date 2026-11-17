"""Phase B controller tests: fully offline, no real mutation ever runs.

Every takeover and rollback drives an injected runner/mutator/spawner over
fixture command output and a fake clock, so the macOS CI runner never clears
an exit node, never starts mihomo, and never writes network state.
"""
import contextlib
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
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
DNS_CLEAN = "resolver #1\n  nameserver[0]     : 100.100.100.100\n"
DNS_DIRTY = "resolver #1\n  nameserver[0]     : 198.18.0.2\n"


class Table:
    """Fixture host: read-only answers, mutable effects, one fake process."""

    def __init__(self, *, dns_dirty_window=None, tcp_ok=True, status_healthy=True,
                 ps_mihomo=False, exit_node_selected=True, corp_dns=True,
                 services=(("Wi-Fi", []),), fail_mutations=(), process_alive=True):
        self.dns_dirty_window = dns_dirty_window  # (from, to) in fake seconds
        self.tcp_ok = tcp_ok
        self.status_healthy = status_healthy
        self.ps_mihomo = ps_mihomo
        self.exit_node_cleared = False
        self.snapshot_exit_node = exit_node_selected
        self.snapshot_corp_dns = corp_dns
        self.snapshot_services = {name: list(servers) for name, servers in services}
        self.service_dns = {name: list(servers) for name, servers in services}
        self.mutations = []
        self.fail_mutations = fail_mutations
        self.process_alive = process_alive
        self.clock = 0.0

    # -- read-only side ------------------------------------------------------
    def runner(self, argv, timeout):
        argv = tuple(argv)
        if argv == ("/usr/sbin/netstat", "-rn", "-f", "inet"):
            return 0, ("Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n"
                       "default 192.0.2.1 UGScg en0\n"), None
        if argv == ("/usr/sbin/netstat", "-rn", "-f", "inet6"):
            return 0, "Routing tables\n\nInternet6:\n", None
        if argv == ("/usr/sbin/scutil", "--dns"):
            window = self.dns_dirty_window
            dirty = window is not None and window[0] <= self.clock < window[1]
            return 0, DNS_DIRTY if dirty else DNS_CLEAN, None
        if argv == ("/usr/sbin/scutil", "--proxy"):
            return 0, "<dictionary> {\n}\n", None
        if argv == ("/bin/ps", "-axo", "pid=,comm="):
            body = "  1 /sbin/launchd\n"
            if self.ps_mihomo:
                body += "  456 /usr/local/bin/mihomo\n"
            return 0, body, None
        if argv == ("/usr/sbin/networksetup", "-listallnetworkservices"):
            return 0, ("An asterisk (*) denotes that a network service is disabled.\n"
                       + "\n".join(self.service_dns) + "\n"), None
        if len(argv) == 3 and argv[0:2] == ("/usr/sbin/networksetup", "-getdnsservers"):
            servers = self.service_dns.get(argv[2], [])
            if not servers:
                return 0, f"There aren't any DNS Servers set on {argv[2]}.\n", None
            return 0, "\n".join(servers) + "\n", None
        if argv == (TS, "status", "--json"):
            if self.status_healthy:
                body = {"BackendState": "Running", "Self": {"Online": True}, "Peer": {}}
            else:
                body = {"BackendState": "Stopped", "Self": {"Online": False}, "Peer": {}}
            return 0, json.dumps(body), None
        if argv == (TS, "debug", "prefs"):
            prefs = {"ExitNodeID": None if self.exit_node_cleared else "nodekey:abc",
                     "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                     "ExitNodeAllowLANAccess": False, "WantRunning": True}
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
            [TS, "set", "--exit-node=nodekey:abc"],
            [TS, "set", "--exit-node=", "--accept-dns=true"],
            [TS, "set", "--exit-node=x", "--exit-node-allow-lan-access"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "Empty"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53"],
            ["/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53", "192.0.2.54"],
            [MIHOMO, "-t", "-f", "/tmp/config.yaml"],
            [MIHOMO, "-f", "/tmp/config.yaml"],
            [MIHOMO, "-d", "/tmp/work", "-f", "/tmp/config.yaml"],
            [MIHOMO, "-d", "/tmp/work", "-t", "-f", "/tmp/config.yaml"],
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
            [TS, "set", "--advertise-routes=10.0.0.0/8"],
            [TS, "set", "--logout"],
            [TS, "set"],
            ["/bin/sh", "-c", "true"],
            ["/usr/bin/sudo", TS, "set", "--exit-node="],
            ["/tmp/other/mihomo", "-f", "/tmp/config.yaml"],
            [MIHOMO, "-d", "/tmp"],
            [MIHOMO, "-t", "-f", "/tmp/config.yaml", "--ext-ui"],
            [MIHOMO, "-d", "relative", "-f", "/tmp/config.yaml"],
        )
        for argv in rejected:
            with self.subTest(argv=argv):
                self.assertFalse(mod.mutating_allowlisted(argv))
        with patch.object(macos_readonly.subprocess, "Popen", side_effect=AssertionError("spawn")):
            with self.assertRaisesRegex(mod.TakeoverError, "not_allowlisted"):
                mod.execute_mutating(["/bin/sh", "-c", "true"])

    def test_explicit_mihomo_path_widens_only_that_binary(self):
        self.assertTrue(mod.mutating_allowlisted(
            ["/opt/custom/mihomo", "-t", "-f", "/tmp/c.yaml"], mihomo_path="/opt/custom/mihomo"))
        self.assertFalse(mod.mutating_allowlisted(
            ["/opt/custom/mihomo", "-t", "-f", "/tmp/c.yaml"], mihomo_path="/opt/other/mihomo"))


class TakeoverFlowTests(unittest.TestCase):
    def record(self, table, **overrides):
        for record, _ in run_takeover(table, **overrides):
            return record

    def test_deadline_reaches_then_rolls_back(self):
        table = Table(dns_dirty_window=(1, 61))
        record = self.record(table)
        self.assertEqual(record["result"], "deadline_reached")
        self.assertEqual(record["mutations"], [[TS, "set", "--exit-node="]])
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
        table = Table(fail_mutations=(((1, "-t"),),))
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
    def write_snapshot(self, state, *, prefs=None, services=(("Wi-Fi", ["192.0.2.53"]),)):
        snapshot = {"schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
                    "tailscale": {"prefs": prefs or {"status": "observed", "ExitNodeID": "nodekey:abc",
                                                     "ExitNodeIP": None, "CorpDNS": True,
                                                     "RouteAll": False,
                                                     "ExitNodeAllowLANAccess": False,
                                                     "WantRunning": True}},
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
            self.assertIn([TS, "set", "--exit-node=nodekey:abc"], table.mutations)
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
        self.assertEqual(values["inputs"], macos_prepare.PLACEHOLDER_INPUTS)

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


if __name__ == "__main__":
    unittest.main()
