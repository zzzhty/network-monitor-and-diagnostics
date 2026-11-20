"""Phase C daemon tests: fully offline, nothing real is spawned or mutated.

The supervisor drives the same injected fixture host as the takeover tests
(Table/FakeProcess), and the IPC server runs on a real AF_UNIX socket in a
temporary directory, so the macOS CI runner never clears an exit node, never
starts mihomo, and never writes launchd state.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import macos_coexist
import nmd_daemon as d
from test_macos_takeover import EXIT_IP, FakeProcess, MIHOMO, PINNED_IP, Table, TS

CONFIG = {"schema_version": 1, "dashboard": {"port": 8765},
          "takeover": {"inputs": {"proxy_name": "VPS", "server": "fd7a:115c:a1e0::abcd",
                                  "port": 1081},
                       "profile": None, "on_boot": False, "check_interval_seconds": 20,
                       "critical_failures": 3, "mihomo_path": MIHOMO, "state_dir": None}}


def make_supervisor(state, table, config=None, *, on_boot=False, boottime=lambda: 111,
                    validator=None, geodata_dir=None, wall=None):
    config = json.loads(json.dumps(config or CONFIG))
    config["takeover"]["on_boot"] = on_boot
    return d.RootSupervisor(
        config, state, runner=table.runner, mutator=table.mutator,
        spawner=table.spawner, tcp=table.tcp, exists=lambda path: path == TS,
        sleep=table.sleep, now=lambda: table.clock,
        wall=wall if wall is not None else (lambda: table.clock),
        boottime=boottime,
        socket_path=Path(state) / "nmd.sock",
        validator=validator or (lambda mihomo, config_path, work_dir: (True, "")),
        geodata_dir=geodata_dir)


class ConfigTests(unittest.TestCase):
    def test_valid_config_round_trips(self):
        value = d.validate_daemon_config(CONFIG)
        self.assertEqual(value["takeover"]["inputs"], CONFIG["takeover"]["inputs"])

    def test_exact_keys_at_every_level(self):
        for broken in (
                {"schema_version": 1, "dashboard": {"port": 1}},
                dict(CONFIG, extra=1),
                dict(CONFIG, dashboard={"port": 8765, "host": "x"}),
                dict(CONFIG, takeover=dict(CONFIG["takeover"], extra=1)),
                dict(CONFIG, takeover={k: v for k, v in CONFIG["takeover"].items()
                                       if k != "on_boot"}),
        ):
            with self.subTest(broken=broken):
                with self.assertRaises(d.DaemonError):
                    d.validate_daemon_config(broken)

    def test_bounds_and_types(self):
        for mutation in (
                lambda c: c["dashboard"].update(port=0),
                lambda c: c["dashboard"].update(port=65536),
                lambda c: c["dashboard"].update(port=True),
                lambda c: c["takeover"].update(on_boot="true"),
                lambda c: c["takeover"].update(check_interval_seconds=4),
                lambda c: c["takeover"].update(check_interval_seconds=301),
                lambda c: c["takeover"].update(critical_failures=0),
                lambda c: c["takeover"].update(critical_failures=11),
                lambda c: c["takeover"].update(mihomo_path="relative/path"),
                lambda c: c["takeover"].update(state_dir="relative"),
                lambda c: c["takeover"].update(inputs={"server": "8.8.8.8", "port": 1081}),
        ):
            with self.subTest(mutation=mutation):
                config = json.loads(json.dumps(CONFIG))
                mutation(config)
                with self.assertRaises(d.DaemonError):
                    d.validate_daemon_config(config)

    def test_profile_delegates_to_the_experiment_validator(self):
        config = json.loads(json.dumps(CONFIG))
        config["takeover"]["profile"] = json.loads(
            (ROOT / "examples/macos-mihomo-coexist.experiment.json").read_text(encoding="utf-8"))
        self.assertEqual(d.validate_daemon_config(config)["takeover"]["profile"]["egress"]["group"],
                         macos_coexist.DEFAULT_EXIT_GROUP)
        broken = json.loads(json.dumps(config))
        broken["takeover"]["profile"]["egress"]["tailscale_exit_node"] = True
        with self.assertRaises(d.DaemonError):
            d.validate_daemon_config(broken)

    def test_write_and_reload_are_private_and_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "daemon.json"
            d.write_daemon_config(path, CONFIG)
            self.assertEqual(d.load_daemon_config(path)["takeover"]["on_boot"], False)
            import stat as stat_module
            self.assertEqual(stat_module.S_IMODE(path.stat().st_mode), 0o600)
            path.write_text("{oops", encoding="utf-8")
            with self.assertRaises(d.DaemonError):
                d.load_daemon_config(path)

    def test_symlink_config_and_shared_parent_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "daemon.json"
            d.write_daemon_config(real, CONFIG)
            link = base / "linked.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(d.DaemonError, "config_not_regular"):
                d.load_daemon_config(link)
            os.chmod(base, 0o755)
            self.assertEqual(d.load_daemon_config(real)["schema_version"], 1)
            os.chmod(base, 0o777)
            with self.assertRaisesRegex(d.DaemonError, "config_group_or_world_writable"):
                d.load_daemon_config(real)
            os.chmod(base, 0o755)
            real_dir = base / "real"
            real_dir.mkdir(mode=0o755)
            moved = real_dir / "daemon.json"
            real.replace(moved)
            link = base / "via"
            link.symlink_to(real_dir, target_is_directory=True)
            with self.assertRaisesRegex(d.DaemonError, "config_not_regular"):
                d.load_daemon_config(link / "daemon.json")
            self.assertEqual(d.load_daemon_config(moved)["schema_version"], 1)
            self.assertIn("schema_version", moved.read_text(encoding="utf-8"))


class IPCTests(unittest.TestCase):
    def serve(self, dispatch, peer):
        server = d.DaemonIPCServer(self.socket_path, dispatch, group=None,
                                   peer_uid_fn=lambda conn: peer)
        server.bind()
        stop = threading.Event()
        thread = threading.Thread(target=server.serve_forever, args=(stop,), daemon=True)
        thread.start()
        self.addCleanup(stop.set)
        self.addCleanup(server.close)
        time.sleep(0.05)
        return server

    def setUp(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.socket_path = Path(holder.name) / "nmd.sock"

    def test_round_trip_carries_peer_identity(self):
        seen = []

        def dispatch(message, uid):
            seen.append((message, uid))
            return {"echo": message, "uid": uid}

        self.serve(dispatch, peer=501)
        reply = d.DaemonIPCClient(self.socket_path).status()
        self.assertEqual(reply, {"echo": {"cmd": "status"}, "uid": 501})
        self.assertEqual(seen, [({"cmd": "status"}, 501)])

    def test_malformed_and_oversized_payloads_get_fixed_errors(self):
        self.serve(lambda message, uid: {"ok": True}, peer=501)
        for payload in (b"not json", b"x" * 5000, b""):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(3)
            client.connect(str(self.socket_path))
            with contextlib.suppress(OSError):
                if payload:
                    client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            data = client.recv(200)
            client.close()
            self.assertIn(b"invalid_payload", data, payload)

    def test_missing_socket_raises_daemon_unavailable(self):
        with self.assertRaises(d.DaemonError):
            d.DaemonIPCClient(self.socket_path / "missing.sock").status()

    def test_peer_uid_reads_the_connected_process(self):
        seen = []

        def dispatch(message, uid):
            seen.append(uid)
            return {"uid": uid}

        server = d.DaemonIPCServer(self.socket_path, dispatch, group=None,
                                   peer_uid_fn=d.peer_uid)
        server.bind()
        stop = threading.Event()
        thread = threading.Thread(target=server.serve_forever, args=(stop,), daemon=True)
        thread.start()
        self.addCleanup(stop.set)
        self.addCleanup(server.close)
        time.sleep(0.05)
        reply = d.DaemonIPCClient(self.socket_path).status()
        self.assertEqual(reply["uid"], os.getuid())
        self.assertEqual(seen, [os.getuid()])

    def test_darwin_xucred_uid_is_not_a_twelve_byte_triple(self):
        import struct
        data = struct.pack("@Ii", 0, 501) + b"\x00" * 64
        self.assertEqual(d._uid_from_cred("darwin", data), 501)
        self.assertEqual(d._uid_from_cred("darwin", struct.pack("@Ii", 0, 0)), 0)
        # The first int is the version. A buffer whose first int is a uid must
        # not be accepted as that uid.
        self.assertEqual(d._uid_from_cred("darwin", struct.pack("@iii", 501, 0, 0)), -1)
        self.assertEqual(d._uid_from_cred("darwin", b"\x00" * 4), -1)
        self.assertEqual(d._uid_from_cred("linux", struct.pack("@iii", 9, 501, 20)), 501)

    def test_regular_file_at_the_socket_path_is_kept(self):
        self.socket_path.write_text("keep", encoding="utf-8")
        server = d.DaemonIPCServer(self.socket_path, lambda message, uid: {}, group=None)
        with self.assertRaises(d.DaemonError):
            server.bind()
        self.assertEqual(self.socket_path.read_text(encoding="utf-8"), "keep")


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.state = Path(holder.name)

    def test_start_rolls_cutover_with_fresh_snapshot_first(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        sup = make_supervisor(self.state, table)
        result = sup.dispatch({"cmd": "takeover.start"}, 0)
        self.assertEqual(result["result"], "takeover_active")
        self.assertEqual(sup.mutations, [[TS, "set", "--exit-node="]])
        # Snapshot ran before the cutover: prefs read precedes the clear.
        self.assertTrue(list(self.state.glob("pre-start-*.json")))
        self.assertEqual(sup.status()["takeover_active"], True)

    def test_placeholder_inputs_never_start_a_takeover(self):
        table = Table()
        config = json.loads(json.dumps(CONFIG))
        config["takeover"]["inputs"] = dict(macos_coexist and {"proxy_name": "VPS",
                                                               "server": macos_coexist.PLACEHOLDER_SOCKS_HOST,
                                                               "port": 1080})
        sup = make_supervisor(self.state, table, config)
        self.assertEqual(sup.dispatch({"cmd": "takeover.start"}, 0),
                         {"error": "placeholder_inputs"})
        self.assertEqual(sup.mutations, [])
        self.assertNotEqual(sup.status()["phase"], d.PHASE_ACTIVE)

    def test_preflight_failure_leaves_everything_untouched(self):
        table = Table(ps_mihomo=True)
        sup = make_supervisor(self.state, table)
        result = sup.dispatch({"cmd": "takeover.start"}, 0)
        self.assertEqual(result["error"], "preflight_failed")
        self.assertTrue(result["mihomo_running"])
        self.assertEqual(sup.mutations, [])
        self.assertNotEqual(sup.status()["phase"], d.PHASE_ACTIVE)

    def test_failed_validation_reports_the_stage_and_detail(self):
        table = Table()
        sup = make_supervisor(self.state, table,
                              validator=lambda m, c, w: (False, "geodata not found"))
        result = sup.dispatch({"cmd": "takeover.start"}, 0)
        self.assertEqual(result["error"], "mihomo_t_failed")
        self.assertEqual(result["detail"], "geodata not found")
        self.assertEqual(result["geodata_staged"], [])
        records = json.loads(sorted(self.state.glob("takeover-*.json"))[-1]
                             .read_text(encoding="utf-8"))
        self.assertEqual(records["result"], "mihomo_t_failed")
        self.assertEqual(records["detail"], "geodata not found")
        self.assertEqual(sup.mutations, [])

    def test_geodata_is_staged_from_the_local_mihomo_dir(self):
        geodata = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(geodata, ignore_errors=True))
        (geodata / "geoip.metadb").write_bytes(b"geoip")
        (geodata / "geosite.dat").write_bytes(b"geosite")
        table = Table(dns_dirty_window=(1, 10 ** 9))
        seen = {}

        def validator(mihomo, config_path, work_dir):
            seen["work_dir"] = str(work_dir)
            return True, ""

        sup = make_supervisor(self.state, table, validator=validator, geodata_dir=geodata)
        result = sup.dispatch({"cmd": "takeover.start"}, 0)
        self.assertEqual(result["result"], "takeover_active")
        staged_dir = Path(seen["work_dir"])
        self.assertEqual((staged_dir / "geoip.metadb").read_bytes(), b"geoip")
        self.assertEqual((staged_dir / "geosite.dat").read_bytes(), b"geosite")
        self.assertIn("geoip.metadb", result.get("geodata_staged", []))

    def test_exit_node_clear_failure_reports_the_stage(self):
        table = Table(fail_mutations=(((2, "--exit-node="),),))
        sup = make_supervisor(self.state, table)
        result = sup.dispatch({"cmd": "takeover.start"}, 0)
        self.assertEqual(result["error"], "exit_node_clear_failed")
        self.assertEqual(sup.mutations, [])
        records = json.loads(sorted(self.state.glob("takeover-*.json"))[-1]
                             .read_text(encoding="utf-8"))
        self.assertEqual(records["result"], "exit_node_clear_failed")

    def test_health_failures_rollback_without_auto_retry(self):
        table = Table(dns_dirty_window=(1, 40), tcp_ok=False)
        sup = make_supervisor(self.state, table)
        self.assertEqual(sup.start_takeover()["result"], "takeover_active")
        self.assertTrue(sup._watchdog_once())  # cycle 1 fails
        self.assertEqual(sup.status()["failures"], 1)
        self.assertTrue(sup._watchdog_once())  # cycle 2
        self.assertEqual(sup.status()["failures"], 2)
        table.dns_dirty_window = (1, 1)  # native DNS already gone, restore can finish
        self.assertFalse(sup._watchdog_once())  # cycle 3 → rollback
        status = sup.status()
        self.assertEqual((status["phase"], status["result"]),
                         (d.PHASE_ROLLED_BACK, "critical_failures"))
        # No auto-retry of the takeover: further cycles stay quiet.
        self.assertTrue(sup._watchdog_once())
        self.assertEqual(sup.status()["phase"], d.PHASE_ROLLED_BACK)
        self.assertFalse(sup.status()["takeover_active"])

    def test_dirty_dns_stays_needs_rollback_until_a_later_retry(self):
        table = Table(dns_dirty_window=(1, 40), tcp_ok=False)
        sup = make_supervisor(self.state, table)
        self.assertEqual(sup.start_takeover()["result"], "takeover_active")
        sup._watchdog_once()
        sup._watchdog_once()
        self.assertFalse(sup._watchdog_once())
        self.assertEqual(sup.status()["phase"], d.PHASE_NEEDS_ROLLBACK)
        self.assertEqual(sup.status()["result"], "critical_failures")
        self.assertEqual(sup.start_takeover(), {"error": "rollback_pending"})
        self.assertFalse(sup._retry_rollback())
        self.assertEqual(sup.status()["phase"], d.PHASE_NEEDS_ROLLBACK)
        self.assertFalse(sup.status()["takeover_active"])
        self.assertTrue(sup._retry_rollback())
        self.assertEqual(sup.status()["phase"], d.PHASE_ROLLED_BACK)
        self.assertFalse(sup.status()["takeover_active"])

    def test_a_passing_cycle_resets_the_failure_streak(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        # F,F,T(reset),F,T: without the reset the 4th failure would roll back.
        outcomes = iter([False, False, True, False, True])
        sup = make_supervisor(self.state, table)

        def flaky(host, port, timeout):
            return {"status": "ok" if next(outcomes) else "timeout"}

        sup.tcp = flaky
        self.assertEqual(sup.start_takeover()["result"], "takeover_active")
        for _ in range(5):
            sup._watchdog_once()
        self.assertEqual(sup.status()["failures"], 0)
        self.assertEqual(sup.status()["phase"], d.PHASE_ACTIVE)

    def test_process_death_is_an_immediate_panic_rollback(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        sup = make_supervisor(self.state, table)
        sup.start_takeover()
        table.process_alive = False
        table.dns_dirty_window = (1, 1)  # process stopped: native DNS cleared
        self.assertFalse(sup._watchdog_once())
        self.assertEqual(sup.status()["result"], "mihomo_exited")
        self.assertEqual(sup.status()["phase"], d.PHASE_ROLLED_BACK)

    def test_manual_stop_is_idempotent_and_records_the_reason(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        sup = make_supervisor(self.state, table)
        sup.dispatch({"cmd": "takeover.start"}, 0)
        table.dns_dirty_window = (1, 1)  # process stopped: native DNS cleared
        first = sup.dispatch({"cmd": "takeover.stop"}, 501)  # non-root may stop
        self.assertEqual(first["result"], "rollback_restored")
        self.assertEqual(first["reason"], "manual_stop")
        again = sup.dispatch({"cmd": "takeover.stop"}, 501)
        self.assertEqual(again["result"], "not_active")
        records = list(self.state.glob("takeover-*.json"))
        self.assertEqual(len(records), 1)
        stored = json.loads(records[0].read_text(encoding="utf-8"))
        self.assertEqual(stored["result"], "manual_stop")
        self.assertEqual(stored["mutations"], [[TS, "set", "--exit-node="]])

    def test_start_requires_uid_zero_over_ipc(self):
        table = Table()
        sup = make_supervisor(self.state, table)
        self.assertEqual(sup.dispatch({"cmd": "takeover.start"}, 501),
                         {"error": "not_authorized"})
        self.assertEqual(sup.dispatch({"cmd": "nonsense"}, 0), {"error": "invalid_command"})
        self.assertEqual(sup.dispatch({"cmd": "status", "path": "/etc/passwd"}, 0),
                         {"error": "invalid_command"})
        self.assertEqual(sup.dispatch({"cmd": 1}, 0), {"error": "invalid_command"})

    def test_takeover_stop_cli_relay_matches_the_panel_action(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        sup = make_supervisor(self.state, table)
        # Start as the root peer would (uid 0); the socket below only carries
        # the stop relay, which any admin-group peer may send — like the panel.
        self.assertEqual(sup.dispatch({"cmd": "takeover.start"}, 0)["result"],
                         "takeover_active")
        server = d.DaemonIPCServer(
            self.state / "cli.sock", sup.dispatch, group=None).bind()
        self.addCleanup(server.close)
        stop = threading.Event()
        thread = threading.Thread(target=server.serve_forever, args=(stop,), daemon=True)
        thread.start()
        self.addCleanup(stop.set)
        time.sleep(0.05)
        table.dns_dirty_window = (1, 1)
        reply = d.DaemonIPCClient(self.state / "cli.sock").stop_takeover()
        self.assertEqual(reply["result"], "rollback_restored")
        self.assertEqual(reply["reason"], "manual_stop")

    def test_boot_policy_takes_over_on_a_true_boot_with_fresh_snapshot(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))
        sup = make_supervisor(self.state, table, on_boot=True)
        sup._recover_leftovers()
        snapshots_before = list(self.state.glob("pre-start-*.json"))
        sup._boot_policy()
        self.assertEqual(sup.status()["phase"], d.PHASE_ACTIVE)
        self.assertGreaterEqual(len(list(self.state.glob("pre-start-*.json"))),
                                len(snapshots_before) + 1)  # fresh snapshot at boot

    def test_same_boot_keepalive_restart_recovers_but_never_resumes(self):
        session = {"schema_version": 1, "label": d.LABEL, "boot_id": 111,
                   "phase": d.PHASE_ACTIVE, "result": None,
                   "started_at": "2026-11-18T00:00:00+00:00"}
        table = Table(dns_dirty_window=(1, 10 ** 9))
        table.exit_node_cleared = True  # the dead supervisor left the cutover on
        self.state.joinpath("pre-start-20261118T000000Z.json").write_text(json.dumps({
            "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
            "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:abc",
                                     "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                     "ExitNodeAllowLANAccess": False, "WantRunning": True}},
            "dns": {"services": []}}), encoding="utf-8")
        (self.state / d.SESSION_FILE).write_text(json.dumps(session), encoding="utf-8")
        sup = make_supervisor(self.state, table, on_boot=True, boottime=lambda: 111)
        table.dns_dirty_window = (1, 1)  # cleanup confirmed
        sup._recover_leftovers()
        sup._boot_policy()
        status = sup.status()
        self.assertEqual((status["phase"], status["result"]),
                         (d.PHASE_ROLLED_BACK, "recovered_leftovers"))
        self.assertEqual(status["takeover_active"], False)  # anti-flap: same boot

    def test_new_boot_after_health_failure_stays_direct(self):
        session = {"schema_version": 1, "label": d.LABEL, "boot_id": 111,
                   "phase": d.PHASE_ROLLED_BACK, "result": "critical_failures",
                   "started_at": None}
        table = Table()
        (self.state / d.SESSION_FILE).write_text(json.dumps(session), encoding="utf-8")
        sup = make_supervisor(self.state, table, on_boot=True, boottime=lambda: 222)
        sup._recover_leftovers()
        sup._boot_policy()
        self.assertEqual(sup.status()["phase"], d.PHASE_ROLLED_BACK)
        self.assertEqual(sup.status()["result"], "critical_failures")

    def test_new_boot_after_crash_recovers_then_resumes(self):
        session = {"schema_version": 1, "label": d.LABEL, "boot_id": 111,
                   "phase": d.PHASE_ACTIVE, "result": None, "started_at": None}
        table = Table(dns_dirty_window=(1, 10 ** 9))
        table.exit_node_cleared = True
        self.state.joinpath("pre-start-20261118T000000Z.json").write_text(json.dumps({
            "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
            "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:abc",
                                     "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                     "ExitNodeAllowLANAccess": False, "WantRunning": True}},
            "dns": {"services": []}}), encoding="utf-8")
        (self.state / d.SESSION_FILE).write_text(json.dumps(session), encoding="utf-8")
        sup = make_supervisor(self.state, table, on_boot=True, boottime=lambda: 222)
        table.dns_dirty_window = (1, 1)
        sup._recover_leftovers()
        table.dns_dirty_window = (1, 10 ** 9)
        sup._boot_policy()
        self.assertEqual(sup.status()["phase"], d.PHASE_ACTIVE)  # resumed on true boot

    def test_starting_crash_restores_the_pinned_snapshot(self):
        pinned = "pre-start-20261117T000000Z.json"
        self.state.joinpath(pinned).write_text(json.dumps({
            "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
            "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:pinned",
                                     "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                     "ExitNodeAllowLANAccess": False, "WantRunning": True}},
            "dns": {"services": []}}), encoding="utf-8")
        self.state.joinpath("pre-start-20261118T000000Z.json").write_text(json.dumps({
            "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
            "tailscale": {"prefs": {"status": "observed", "ExitNodeID": None,
                                     "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                     "ExitNodeAllowLANAccess": False, "WantRunning": True}},
            "dns": {"services": []}}), encoding="utf-8")
        session = {"schema_version": 1, "label": d.LABEL, "boot_id": 111,
                   "phase": d.PHASE_STARTING, "result": None, "snapshot_name": pinned,
                   "started_at": None}
        (self.state / d.SESSION_FILE).write_text(json.dumps(session), encoding="utf-8")
        table = Table(dns_dirty_window=(1, 1))
        table.exit_node_cleared = True
        sup = make_supervisor(self.state, table, on_boot=True, boottime=lambda: 111)
        sup._recover_leftovers()
        sup._boot_policy()
        self.assertIn([TS, "set", "--exit-node=" + PINNED_IP], table.mutations)
        self.assertFalse(any("evil" in json.dumps(item) for item in table.mutations))
        status = sup.status()
        self.assertEqual((status["phase"], status["result"]),
                         (d.PHASE_ROLLED_BACK, "recovered_leftovers"))
        self.assertFalse(status["takeover_active"])

    def test_needs_rollback_blocks_a_boot_takeover(self):
        name = "pre-start-20261117T000000Z.json"
        self.state.joinpath(name).write_text(json.dumps({
            "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
            "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:abc",
                                     "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                     "ExitNodeAllowLANAccess": False, "WantRunning": True}},
            "dns": {"services": []}}), encoding="utf-8")
        session = {"schema_version": 1, "label": d.LABEL, "boot_id": 111,
                   "phase": d.PHASE_NEEDS_ROLLBACK, "result": "critical_failures",
                   "snapshot_name": name, "started_at": None}
        (self.state / d.SESSION_FILE).write_text(json.dumps(session), encoding="utf-8")
        table = Table(dns_dirty_window=(0, 10 ** 9))
        sup = make_supervisor(self.state, table, on_boot=True, boottime=lambda: 222)
        sup._recover_leftovers()
        sup._boot_policy()
        self.assertEqual(sup.status()["phase"], d.PHASE_NEEDS_ROLLBACK)
        self.assertEqual(sup.status()["result"], "critical_failures")
        self.assertFalse(sup.status()["takeover_active"])
        self.assertEqual([item for item in table.mutations if item[0] == TS], [])

    def test_finished_pending_rollback_keeps_the_failure_and_does_not_restart(self):
        name = "pre-start-20261117T000000Z.json"
        self.state.joinpath(name).write_text(json.dumps({
            "schema_version": 1, "kind": "macos_pre_start_snapshot", "phase": "A",
            "tailscale": {"prefs": {"status": "observed", "ExitNodeID": "nodekey:abc",
                                     "ExitNodeIP": None, "CorpDNS": True, "RouteAll": False,
                                     "ExitNodeAllowLANAccess": False, "WantRunning": True}},
            "dns": {"services": []}}), encoding="utf-8")
        session = {"schema_version": 1, "label": d.LABEL, "boot_id": 111,
                   "phase": d.PHASE_NEEDS_ROLLBACK, "result": "critical_failures",
                   "snapshot_name": name, "started_at": None}
        (self.state / d.SESSION_FILE).write_text(json.dumps(session), encoding="utf-8")
        table = Table()
        table.exit_node_cleared = True
        sup = make_supervisor(self.state, table, on_boot=True, boottime=lambda: 222)
        sup._recover_leftovers()
        sup._boot_policy()
        status = sup.status()
        self.assertEqual((status["phase"], status["result"]),
                         (d.PHASE_ROLLED_BACK, "critical_failures"))
        self.assertFalse(status["takeover_active"])
        self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
        self.assertFalse(any(item[2:3] == ["--exit-node="] for item in table.mutations
                             if item[0] == TS))

    def test_state_dir_ancestor_symlink_and_shared_parent_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            state = link / "state"
            state.mkdir(mode=0o700)
            with self.assertRaisesRegex(d.DaemonError, "state_dir_symlink"):
                make_supervisor(state, Table())
            base.chmod(0o777)
            nested = base / "nested"
            nested.mkdir(mode=0o700)
            with self.assertRaisesRegex(d.DaemonError, "unsafe_state_dir"):
                make_supervisor(nested, Table())

    def test_state_dir_symlink_is_rejected(self):
        real = self.state / "real"
        real.mkdir()
        link = self.state / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(d.DaemonError, "state_dir_symlink"):
            make_supervisor(link, Table())

    def test_supervisor_records_vps_tcp_without_dialing_during_start(self):
        table = Table(dns_dirty_window=(1, 10 ** 9))

        def boom(*_args, **_kwargs):
            raise AssertionError("dialed")

        config = json.loads(json.dumps(CONFIG))
        with patch("macos_readonly.tcp_connect", side_effect=boom):
            sup = d.RootSupervisor(
                config, self.state, runner=table.runner, mutator=table.mutator,
                spawner=table.spawner, tcp=None, exists=lambda path: path == TS,
                sleep=table.sleep, now=lambda: table.clock, boottime=lambda: 111,
                socket_path=self.state / "tcp.sock",
                validator=lambda *_args: (True, ""))
        self.assertEqual(sup.start_takeover()["result"], "takeover_active")
        self.assertIn("vps_socks_tcp", [name for name, _critical, _check in sup.checks])


class CollectorStateDirTests(unittest.TestCase):
    def test_user_owned_directory_stays(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self.assertEqual(d.collector_state_dir(path), path)

    def test_missing_directory_stays_so_the_collector_can_create_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nmd-monitor"
            self.assertFalse(path.exists())
            self.assertEqual(d.collector_state_dir(path), path)

    def test_unowned_directory_uses_a_sibling_and_leaves_the_original(self):
        preferred = Path("/tmp/nmd-state-choice/nmd-monitor")
        with patch.object(d, "_collector_can_lock", return_value=False):
            chosen = d.collector_state_dir(preferred)
        self.assertEqual(chosen, preferred.parent / "nmd-monitor-user")
        self.assertNotEqual(chosen, preferred)


class UserDaemonTests(unittest.TestCase):
    def test_collect_runs_until_stopped_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "monitor.json"
            config_path.write_text("{}", encoding="utf-8")
            calls = []

            def collect(config, state_dir, stop_event=None):
                calls.append(config)
                stop_event.wait(60)
                return "done"

            daemon = d.UserDaemon(monitor_config_path=config_path, state_dir=tmp,
                                  collect=collect, load_config=lambda p: {"loaded": True},
                                  interval=0.05)
            daemon.start_collector()
            time.sleep(0.2)
            self.assertEqual(daemon.collector_status, "running")
            self.assertEqual(calls, [{"loaded": True}])
            daemon.stop_collector()
            self.assertEqual(daemon.collector_status, "stopped")

    def test_config_mtime_change_restarts_the_collector(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "monitor.json"
            config_path.write_text("{}", encoding="utf-8")
            calls = []
            started = threading.Event()

            def collect(config, state_dir, stop_event=None):
                calls.append(config)
                started.set()
                stop_event.wait(60)

            daemon = d.UserDaemon(monitor_config_path=config_path, state_dir=tmp,
                                  collect=collect, load_config=lambda p: {"v": len(calls)},
                                  interval=0.05, stop_event=threading.Event())
            runner = threading.Thread(target=daemon.run, daemon=True)
            runner.start()
            self.assertTrue(started.wait(2))
            time.sleep(0.1)
            os.utime(config_path, (time.time() + 5, time.time() + 5))
            deadline = time.time() + 2
            while len(calls) < 2 and time.time() < deadline:
                time.sleep(0.02)
            daemon.stop_event.set()
            runner.join(timeout=2)
            self.assertEqual(len(calls), 2, calls)
            self.assertNotEqual(calls[0], calls[1])  # config was reloaded

    def test_external_collector_is_reported_not_crash_looped(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "monitor.json"
            config_path.write_text("{}", encoding="utf-8")

            def collect(config, state_dir, stop_event=None):
                raise RuntimeError("collector_already_running")

            daemon = d.UserDaemon(monitor_config_path=config_path, state_dir=tmp,
                                  collect=collect, load_config=lambda p: {}, interval=0.05)
            with patch.object(d, "RECOVER_BACKOFF_SECONDS", 0):
                daemon.start_collector()
                deadline = time.time() + 2
                while daemon.collector_status != "externally_running" and time.time() < deadline:
                    time.sleep(0.02)
                self.assertEqual(daemon.collector_status, "externally_running")
                daemon.stop_collector()


class DaemonInstallTests(unittest.TestCase):
    """Fake checkout + fake sudo/launchctl; nothing touches the real system."""

    SCRIPTS = ("manager.py", "install_scope.py", "egress_sources.py", "nmd_platform.py",
               "macos_coexist.py", "macos_readonly.py", "macos_prepare.py",
               "macos_takeover.py", "nmd_daemon.py")

    def setUp(self):
        import shutil
        import subprocess as sp
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name)
        self.checkout = self.base / "repo"
        (self.checkout / "scripts").mkdir(parents=True)
        for name in self.SCRIPTS:
            shutil.copy2(ROOT / "scripts" / name, self.checkout / "scripts" / name)
        sp.run(["git", "init", "--quiet", str(self.checkout)], check=True, capture_output=True)
        (self.checkout / "examples").mkdir()
        shutil.copy2(ROOT / "examples/macos-mihomo-coexist.experiment.json",
                     self.checkout / "examples/macos-mihomo-coexist.experiment.json")
        import manager
        self.config_dir = self.base / "config/nmd"
        self.state_dir = self.base / "state/nmd-monitor"
        self.config_dir.mkdir(parents=True)
        self.user_agents = self.base / "home/Library/LaunchAgents"
        self.root_daemons = self.base / "Library/LaunchDaemons"
        self.root_daemons.mkdir(parents=True)
        for key, value in (("home", self.checkout), ("scope", "user"),
                           ("configDir", self.config_dir), ("stateDir", self.state_dir),
                           ("daemonInstalled", "false")):
            manager.setting(self.checkout, key, value)
        d.write_daemon_config(self.config_dir / "daemon.json", CONFIG)
        # Fake sudo: logs argv, answers install-root with a canned fingerprint.
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.sudo_log = self.base / "sudo.log"
        root_plist = self.root_daemons / f"{d.LABEL}.plist"
        (self.bin / "sudo").write_text(
            "#!/bin/sh\n"
            f"echo \"$@\" >> {self.sudo_log}\n"
            f"case \"$*\" in *install-root*) echo '{{\"root_plist\": \"{root_plist}\","
            " \"fingerprint\": {\"size\": 3, \"sha256\": \"abc\"}}';;"
            " *) echo '{}';; esac\n", encoding="utf-8")
        (self.bin / "sudo").chmod(0o755)
        self.manager = manager
        self.launchctl = []
        real_run = d.subprocess.run

        def fake_launchctl(argv, **kwargs):
            if argv and argv[0] == "/bin/launchctl":
                self.launchctl.append(list(argv))
                class R:
                    returncode = 0
                    stderr = ""
                    stdout = ""
                return R()
            return real_run(argv, **kwargs)

        patches = [
            patch.object(d, "USER_PLIST_DIR", self.user_agents),
            patch.object(d, "ROOT_PLIST_DIR", self.root_daemons),
            patch.object(d, "SOCKET_PATH", self.base / "nmd.sock"),
            patch.object(manager, "ROOT", self.checkout),
            patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}),
            patch.object(d.subprocess, "run", side_effect=fake_launchctl),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def run_cli(self, *args):
        import io as io_module
        output = io_module.StringIO()
        with contextlib.redirect_stdout(output):
            code = d.cli_daemon(list(args))
        return code, output.getvalue()

    def test_install_writes_user_plist_and_saves_the_receipt(self):
        import plistlib
        code, out = self.run_cli("install")
        self.assertEqual(code, 0, out)
        user_plist = self.user_agents / f"{d.LABEL}.plist"
        data = plistlib.loads(user_plist.read_bytes())
        self.assertEqual(data["Label"], d.LABEL)
        self.assertEqual(data["ProgramArguments"][:3],
                         [sys.executable, str(ROOT / "scripts/nmd_daemon.py"), "run-user"])
        self.assertEqual(data["RunAtLoad"], True)
        self.assertEqual(data["KeepAlive"], True)
        self.assertIn("install-root", self.sudo_log.read_text())
        receipt = d.daemon_receipt(self.checkout)
        self.assertEqual(receipt["paths"]["user_plist"], str(user_plist))
        self.assertEqual(receipt["files"]["root_plist"], {"size": 3, "sha256": "abc"})
        self.assertEqual(self.manager.setting(self.checkout, "daemonInstalled"), "true")
        # Re-running install is an idempotent refresh.
        self.assertEqual(self.run_cli("install")[0], 0)

    def test_install_refuses_placeholder_inputs_and_missing_config(self):
        d.write_daemon_config(self.config_dir / "daemon.json", json.loads(json.dumps(
            dict(CONFIG, takeover=dict(CONFIG["takeover"], inputs={
                "proxy_name": "VPS", "server": macos_coexist.PLACEHOLDER_SOCKS_HOST,
                "port": 1080})))))
        code, _ = self.run_cli("install")
        self.assertEqual(code, 1)
        (self.config_dir / "daemon.json").unlink()
        code, _ = self.run_cli("install")
        self.assertEqual(code, 1)
        self.assertFalse((self.user_agents / f"{d.LABEL}.plist").exists())

    def test_uninstall_removes_owned_artifacts_and_clears_the_receipt(self):
        self.assertEqual(self.run_cli("install")[0], 0)
        code, out = self.run_cli("uninstall")
        self.assertEqual(code, 0, out)
        self.assertFalse((self.user_agents / f"{d.LABEL}.plist").exists())
        self.assertIsNone(d.daemon_receipt(self.checkout))
        self.assertEqual(self.manager.setting(self.checkout, "daemonInstalled"), "false")
        self.assertEqual(self.run_cli("uninstall")[0], 0)  # repeat is a no-op
        self.assertTrue(any(
            call[:2] == ["/bin/launchctl", "bootout"] and call[2].startswith("gui/")
            for call in self.launchctl))

    def test_foreign_user_plist_blocks_install(self):
        self.user_agents.mkdir(parents=True)
        (self.user_agents / f"{d.LABEL}.plist").write_text("foreign", encoding="utf-8")
        with self.assertRaises(d.DaemonError):
            self.run_cli("install")
        self.assertEqual((self.user_agents / f"{d.LABEL}.plist").read_text(), "foreign")

    def test_root_helper_writes_and_bootstraps_the_root_plist(self):
        import plistlib
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            class R:
                returncode = 0
                stderr = ""
                stdout = ""
            return R()

        with patch.object(d.os, "geteuid", return_value=0), \
                patch.object(d.subprocess, "run", side_effect=fake_run):
            reply = d.install_root_plist(self.config_dir / "daemon.json", self.state_dir)
        plist_path = self.root_daemons / f"{d.LABEL}.plist"
        self.assertEqual(reply["root_plist"], str(plist_path))
        self.assertEqual(reply["fingerprint"], d._fingerprint(plist_path))
        data = plistlib.loads(plist_path.read_bytes())
        self.assertEqual(data["ProgramArguments"][2:4], ["supervise", "--config"])
        self.assertEqual(data["ProgramArguments"][4],
                         str((self.config_dir / "daemon.json").resolve()))
        self.assertEqual(data["ProgramArguments"][6], str(self.state_dir.resolve()))
        self.assertEqual(calls[0][1], "bootstrap")
        # Modified root plist refuses a reinstall.
        plist_path.write_text("tampered", encoding="utf-8")
        with patch.object(d.os, "geteuid", return_value=0), \
                patch.object(d.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(d.DaemonError):
                d.install_root_plist(self.config_dir / "daemon.json", self.state_dir)

    def test_start_bootstraps_when_kickstart_finds_the_job_unloaded(self):
        plist = self.root_daemons / f"{d.LABEL}.plist"
        plist.write_text("plist", encoding="utf-8")
        calls = []
        kicks = {"n": 0}

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            class R:
                stdout = ""
                stderr = ""
                returncode = 0
            result = R()
            if argv[1] == "kickstart" and kicks["n"] == 0:
                kicks["n"] += 1
                result.returncode = 1
                result.stderr = "Could not find service"
            return result

        with patch.object(d.os, "geteuid", return_value=0), \
                patch.object(d.subprocess, "run", side_effect=fake_run):
            self.assertEqual(d._root_control("start"), {"result": "start"})
        self.assertEqual([call[1] for call in calls], ["kickstart", "bootstrap", "kickstart"])

    def test_start_refuses_a_symlink_plist(self):
        target = self.root_daemons / "other.plist"
        target.write_text("foreign", encoding="utf-8")
        link = self.root_daemons / f"{d.LABEL}.plist"
        link.symlink_to(target)

        def fake_run(argv, **kwargs):
            class R:
                returncode = 1
                stderr = "Could not find service"
                stdout = ""
            return R()

        with patch.object(d.os, "geteuid", return_value=0), \
                patch.object(d.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(d.DaemonError):
                d._root_control("start")
            with self.assertRaises(d.DaemonError):
                d.install_root_plist(self.config_dir / "daemon.json", self.state_dir)
        self.assertEqual(target.read_text(encoding="utf-8"), "foreign")

    def test_root_helpers_refuse_without_euid_zero(self):
        with patch.object(d.os, "geteuid", return_value=501):
            for helper in (lambda: d.install_root_plist("x", "y"), d.uninstall_root_plist,
                           lambda: d._root_control("start")):
                with self.subTest(helper=helper):
                    with self.assertRaises(d.DaemonError):
                        helper()

    def test_manager_routes_macos_daemon_only_on_darwin(self):
        with patch.object(self.manager.nmd_platform, "name", return_value="macos"), \
                patch("nmd_daemon.cli_daemon", return_value=0) as cli:
            with self.assertRaises(SystemExit) as ctx:
                self.manager.main(["macos", "daemon", "status"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(cli.call_args.args, (["status"],))
        with patch.object(self.manager.nmd_platform, "name", return_value="linux"):
            with self.assertRaises(SystemExit):
                self.manager.main(["macos", "daemon", "status"])

    def test_install_start_and_restart_do_not_rewrite_on_boot(self):
        path = self.config_dir / "daemon.json"
        before = path.read_bytes()
        self.assertIn(b'"on_boot": false', before)
        self.assertNotIn(b'"on_boot": "false"', before)
        self.assertEqual(self.run_cli("install")[0], 0)
        self.assertEqual(path.read_bytes(), before)
        with patch("macos_preflight.host_is_darwin", return_value=False):
            self.assertEqual(self.run_cli("start")[0], 0)
            self.assertEqual(self.run_cli("restart")[0], 0)
        self.assertEqual(path.read_bytes(), before)
        self.assertIs(d.load_daemon_config(path)["takeover"]["on_boot"], False)


class DaemonRestartTests(unittest.TestCase):
    """restart is stop then start. No sudo, launchctl, or socket is used."""

    def run_restart(self, helper, client=None):
        order = []

        class Client:
            def __init__(self, path, timeout=None):
                order.append("ipc")
            def stop_takeover(self):
                order.append("stop_takeover")
                raise d.DaemonError("socket_missing")

        output = io.StringIO()
        # The stop-then-start order is what this class checks. The darwin
        # preflight gate is covered by test_macos_preflight and must not
        # stat this runner's mihomo, Tailscale, or daemon socket.
        with patch.object(d, "daemon_receipt", return_value=None), \
                patch("macos_preflight.host_is_darwin", return_value=False), \
                patch.object(d, "_run_helper", side_effect=helper), \
                patch.object(d, "DaemonIPCClient", client or Client), \
                contextlib.redirect_stdout(output):
            code = d.cli_daemon(["restart"])
        return code, output.getvalue(), order

    def test_restart_stops_then_starts_and_prints_one_document(self):
        calls = []

        def helper(argv):
            calls.append(list(argv))
            return {"result": argv[-1].replace("-root", "")}

        code, out, order = self.run_restart(helper)
        self.assertEqual(code, 0, out)
        self.assertEqual(order, ["ipc", "stop_takeover"])
        self.assertEqual([item[-1] for item in calls], ["stop-root", "start-root"])
        self.assertEqual(calls[0][:2], ["sudo", "--"])
        self.assertEqual(calls[1][:2], ["sudo", "--"])
        document = json.loads(out)
        self.assertEqual(document, {
            "result": "restart",
            "stop": {"result": "stop"},
            "start": {"result": "start"},
        })

    def test_restart_does_not_start_when_stop_fails(self):
        calls = []

        def helper(argv):
            calls.append(argv[-1])
            return {"error": "launchctl_stop_failed"}

        code, out, _order = self.run_restart(helper)
        self.assertEqual(code, 1, out)
        self.assertEqual(calls, ["stop-root"])
        document = json.loads(out)
        self.assertEqual(document["result"], "restart")
        self.assertEqual(document["stop"]["error"], "launchctl_stop_failed")
        self.assertNotIn("start", document)

    def test_restart_reports_a_start_failure_after_stop_succeeded(self):
        calls = []

        def helper(argv):
            calls.append(argv[-1])
            if argv[-1] == "start-root":
                return {"error": "launchctl_start_failed"}
            return {"result": "stop"}

        code, out, _order = self.run_restart(helper)
        self.assertEqual(code, 1, out)
        self.assertEqual(calls, ["stop-root", "start-root"])
        document = json.loads(out)
        self.assertEqual(document["stop"], {"result": "stop"})
        self.assertEqual(document["start"], {"error": "launchctl_start_failed"})

    def test_restart_rejects_extra_arguments_before_any_helper(self):
        with patch.object(d, "_run_helper", side_effect=AssertionError("helper")), \
                patch.object(d, "DaemonIPCClient", side_effect=AssertionError("ipc")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(d.cli_daemon(["restart", "now"]), 2)


class WakeResidencyTests(unittest.TestCase):
    """Sleep/wake for the supervisor. No LaunchDaemon is loaded and on_boot stays put."""

    def setUp(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.state = Path(holder.name)

    def test_broken_wake_restores_residency_and_does_not_start_another(self):
        clocks = {"wall": 5_000.0}
        table = Table(dns_dirty_window=(1, 10 ** 9))
        sup = make_supervisor(self.state, table, on_boot=False, wall=lambda: clocks["wall"])
        self.assertEqual(sup.start_takeover()["result"], "takeover_active")
        self.assertFalse(sup.status()["on_boot"])
        table.dns_dirty_window = None
        clocks["wall"] += 40
        decision = sup.observe_power()
        self.assertEqual(decision["action"], "rollback")
        self.assertIn("native_dns_missing", decision["reasons"])
        status = sup.status()
        self.assertEqual((status["phase"], status["result"], status["takeover_active"]),
                         (d.PHASE_ROLLED_BACK, "wake_restore", False))
        self.assertFalse(status["on_boot"])
        clears = [item for item in table.mutations if item[:3] == [TS, "set", "--exit-node="]]
        self.assertEqual(clears, [[TS, "set", "--exit-node="]])
        self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
        rendered = json.dumps(table.mutations)
        self.assertNotIn("nodekey:", rendered)
        self.assertNotIn("auto:any", rendered)

    def test_healthy_wake_leaves_the_takeover_running(self):
        clocks = {"wall": 8_000.0}
        table = Table(dns_dirty_window=(1, 10 ** 9))
        sup = make_supervisor(self.state, table, wall=lambda: clocks["wall"])
        self.assertEqual(sup.start_takeover()["result"], "takeover_active")
        before = len(table.mutations)
        clocks["wall"] += 25
        decision = sup.observe_power()
        self.assertEqual(decision["action"], "continue")
        self.assertEqual(decision["reasons"], [])
        self.assertEqual(decision["proxy"]["expected_enabled"], {})
        self.assertEqual(decision["proxy"]["live_enabled"], {})
        self.assertNotIn("bypass", decision["proxy"])
        self.assertTrue(sup.status()["takeover_active"])
        self.assertEqual(len(table.mutations), before)
        self.assertFalse(sup.status()["on_boot"])

    def test_wake_while_direct_does_not_take_over_even_if_on_boot_is_configured(self):
        clocks = {"wall": 100.0}
        table = Table()
        sup = make_supervisor(self.state, table, on_boot=True, wall=lambda: clocks["wall"])
        self.assertIsNone(sup.observe_power())
        clocks["wall"] += 50
        decision = sup.observe_power()
        self.assertEqual(decision["action"], "none")
        self.assertEqual(sup.status()["phase"], d.PHASE_DIRECT)
        self.assertEqual(table.mutations, [])
        self.assertFalse(sup.status()["takeover_active"])
        self.assertTrue(sup.status()["on_boot"])

    def test_wake_during_start_restores_before_the_takeover_is_active(self):
        clocks = {"wall": 300.0}
        table = Table(dns_dirty_window=None)

        def sleeping(seconds):
            table.clock += seconds
            clocks["wall"] += 30
            table.route_text = ("Routing tables\n\nInternet:\n"
                                "Destination Gateway Flags Netif Expire\n")

        sup = make_supervisor(self.state, table, wall=lambda: clocks["wall"])
        sup.sleep = sleeping
        result = sup.start_takeover()
        self.assertEqual(result["reason"], "wake_restore")
        self.assertNotEqual(sup.status()["phase"], d.PHASE_ACTIVE)
        self.assertFalse(sup.status()["takeover_active"])
        self.assertIn("default_route_missing", sup.last_wake["reasons"])
        self.assertIn([TS, "set", "--exit-node=" + EXIT_IP], table.mutations)
        self.assertNotIn("nodekey:", json.dumps(table.mutations))
        self.assertFalse(sup.config["takeover"]["on_boot"])


class DaemonOnBootTests(unittest.TestCase):
    """on-boot and init touch daemon.json only. No sudo, launchd, or takeover."""

    def setUp(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name)
        self.path = self.base / "config" / "daemon.json"
        self.path.parent.mkdir(mode=0o700)
        d.write_daemon_config(self.path, CONFIG)
        patcher = patch.object(d, "default_daemon_config_path", return_value=self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_inputs(self, payload, name="inputs.json"):
        path = self.base / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def invoke(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        bombs = (
            patch.object(d.subprocess, "run", side_effect=AssertionError("subprocess")),
            patch.object(d, "_run_helper", side_effect=AssertionError("helper")),
            patch.object(d, "_daemon_start", side_effect=AssertionError("start")),
            patch.object(d, "_daemon_stop", side_effect=AssertionError("stop")),
            patch.object(d, "install_root_plist", side_effect=AssertionError("plist")),
            patch.object(d, "DaemonIPCClient", side_effect=AssertionError("ipc")),
            patch("macos_takeover.reexec_root", side_effect=AssertionError("reexec")),
            patch("macos_takeover.execute_mutating", side_effect=AssertionError("mutate")),
            patch("macos_geodata.prepare_for_daemon", side_effect=AssertionError("geodata")),
            patch("macos_preflight.for_daemon_lifecycle", side_effect=AssertionError("preflight")),
            patch("macos_preflight.for_installed_takeover",
                  side_effect=AssertionError("takeover-preflight")),
            patch("manager.apply", side_effect=AssertionError("apply")),
            patch("manager._activate_macos_daemon", side_effect=AssertionError("activate")),
        )
        with contextlib.ExitStack() as stack:
            for item in bombs:
                stack.enter_context(item)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = d.cli_daemon(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_boot_policy_defaults_stay_closed(self):
        policy = macos_coexist.DAEMON_POLICY
        self.assertIs(policy["takeover_on_boot_default"], False)
        self.assertIs(policy["same_boot_keepalive_restart_never_resumes"], True)
        self.assertIs(policy["wake_does_not_start_takeover"], True)
        self.assertIs(policy["auto_retry_after_rollback"], False)
        self.assertIs(policy["retries_incomplete_rollback"], True)

    def test_help_names_init_and_on_boot_without_reading_config(self):
        digest = self.path.read_bytes()
        with patch.object(d.os, "geteuid", return_value=0), \
                patch.object(d.Path, "home", side_effect=AssertionError("home")), \
                patch.object(d, "write_daemon_config", side_effect=AssertionError("write")), \
                patch.object(d, "load_daemon_config", side_effect=AssertionError("load")):
            code, out, err = self.invoke(["on-boot", "--help"])
        self.assertEqual(code, 0, err)
        self.assertIn("on-boot [on|off|status]", out)
        self.assertIn("init --inputs", out)
        self.assertIn("203.0.113.20", out)
        self.assertEqual(err, "")
        self.assertEqual(self.path.read_bytes(), digest)

    def test_root_refuses_before_home_or_write(self):
        with patch.object(d.os, "geteuid", return_value=0), \
                patch.object(d.Path, "home", side_effect=AssertionError("home")), \
                patch.object(d, "default_daemon_config_path", side_effect=AssertionError("path")), \
                patch.object(d, "write_daemon_config", side_effect=AssertionError("write")), \
                patch.object(d, "load_daemon_config", side_effect=AssertionError("load")):
            for argv in (["on-boot"], ["on-boot", "on"], ["on-boot", "off"],
                         ["on-boot", "true"],
                         ["init", "--inputs", str(self.base / "missing.json")]):
                code, out, err = self.invoke(argv)
                self.assertEqual(code, 1, argv)
                self.assertEqual(out, "", argv)
                self.assertEqual(json.loads(err)["error"], "root_refused", argv)
        self.assertFalse((self.base / "var-root").exists())

    def test_on_off_and_status_round_trip_a_json_boolean(self):
        digest = self.path.read_bytes()
        code, out, err = self.invoke(["on-boot"])
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertIs(body["on_boot"], False)
        self.assertIs(body["changed"], False)
        self.assertIs(body["loaded_daemon"], False)
        self.assertIs(body["takeover_started"], False)
        self.assertIn("没有加载 LaunchDaemon", body["note"])
        self.assertIn("新的一次开机", body["note"])
        self.assertEqual(self.path.read_bytes(), digest)

        code, out, err = self.invoke(["on-boot", "status"])
        self.assertEqual(code, 0, err)
        self.assertIs(json.loads(out)["changed"], False)
        self.assertEqual(self.path.read_bytes(), digest)

        with patch.object(d, "write_daemon_config", side_effect=AssertionError("write")):
            code, out, err = self.invoke(["on-boot", "off"])
        self.assertEqual(code, 0, err)
        self.assertIs(json.loads(out)["on_boot"], False)
        self.assertIs(json.loads(out)["changed"], False)

        code, out, err = self.invoke(["on-boot", "on"])
        self.assertEqual(code, 0, err)
        turned = json.loads(out)
        self.assertIs(turned["on_boot"], True)
        self.assertIs(turned["changed"], True)
        self.assertIs(turned["loaded_daemon"], False)
        self.assertIs(turned["takeover_started"], False)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn('"on_boot": true', text)
        self.assertNotIn('"on_boot": "true"', text)
        stored = json.loads(text)
        self.assertIs(stored["takeover"]["on_boot"], True)
        self.assertEqual(stored["takeover"]["inputs"], CONFIG["takeover"]["inputs"])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode) & 0o777, 0o600)
        self.assertEqual(self.path.stat().st_uid, os.geteuid())
        self.assertEqual(self.path.lstat().st_nlink, 1)

        with patch.object(d, "write_daemon_config", side_effect=AssertionError("write")):
            code, out, err = self.invoke(["on-boot", "on"])
        self.assertEqual(code, 0, err)
        self.assertIs(json.loads(out)["changed"], False)
        self.assertEqual(self.path.read_text(encoding="utf-8"), text)

        code, out, err = self.invoke(["on-boot", "off"])
        self.assertEqual(code, 0, err)
        self.assertIs(json.loads(out)["on_boot"], False)
        self.assertIs(json.loads(out)["changed"], True)
        self.assertIn('"on_boot": false', self.path.read_text(encoding="utf-8"))
        self.assertIs(d.load_daemon_config(self.path)["takeover"]["on_boot"], False)

    def test_on_boot_rejects_string_booleans_and_leaves_the_file(self):
        before = self.path.read_bytes()
        for word in ("true", "false", "yes", "1", "on-boot"):
            code, out, err = self.invoke(["on-boot", word])
            self.assertEqual(code, 2, word)
            self.assertEqual(out, "", word)
            self.assertIn("on-boot [on|off|status]", err)
            self.assertEqual(self.path.read_bytes(), before, word)
        code, _, _ = self.invoke(["on-boot", "on", "please"])
        self.assertEqual(code, 2)
        self.assertEqual(self.path.read_bytes(), before)

    def test_on_boot_refuses_missing_invalid_symlink_and_foreign_files(self):
        self.path.unlink()
        code, out, err = self.invoke(["on-boot", "on"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["error"], "daemon_config_missing")
        self.assertFalse(self.path.exists())

        self.path.write_text("{oops", encoding="utf-8")
        os.chmod(self.path, 0o600)
        broken = self.path.read_bytes()
        code, _, err = self.invoke(["on-boot", "status"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_invalid_json")
        self.assertEqual(self.path.read_bytes(), broken)

        raw = json.loads(json.dumps(CONFIG))
        for bad in ("true", "false", 1, 0):
            raw["takeover"]["on_boot"] = bad
            self.path.write_text(json.dumps(raw), encoding="utf-8")
            os.chmod(self.path, 0o600)
            snapshot = self.path.read_bytes()
            code, _, err = self.invoke(["on-boot", "on"])
            self.assertEqual(code, 1, bad)
            self.assertEqual(json.loads(err)["error"], "invalid_on_boot", bad)
            self.assertEqual(self.path.read_bytes(), snapshot, bad)

        d.write_daemon_config(self.path, CONFIG)
        os.chmod(self.path, 0o666)
        writable = self.path.read_bytes()
        code, _, err = self.invoke(["on-boot", "off"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_group_or_world_writable")
        self.assertEqual(self.path.read_bytes(), writable)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode) & 0o777, 0o666)

        os.chmod(self.path, 0o600)
        if os.geteuid() != 0:
            with patch.object(d.os, "geteuid", return_value=os.geteuid() + 1):
                code, _, err = self.invoke(["on-boot"])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(err)["error"], "config_owner_changed")
            self.assertIn(b'"on_boot": false', self.path.read_bytes())

        target = self.base / "other.json"
        target.write_text('{"secret": true}\n', encoding="utf-8")
        self.path.unlink()
        self.path.symlink_to(target)
        code, _, err = self.invoke(["on-boot", "on"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_not_regular")
        self.assertEqual(target.read_text(encoding="utf-8"), '{"secret": true}\n')
        self.assertTrue(self.path.is_symlink())

    def test_on_boot_does_not_follow_a_symlink_parent(self):
        real = self.base / "real"
        real.mkdir(mode=0o700)
        moved = real / "daemon.json"
        self.path.replace(moved)
        link = self.base / "via"
        link.symlink_to(real, target_is_directory=True)
        dest = link / "daemon.json"
        before = moved.read_bytes()
        with patch.object(d, "default_daemon_config_path", return_value=dest):
            code, _, err = self.invoke(["on-boot", "on"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_not_regular")
        self.assertEqual(moved.read_bytes(), before)
        self.assertIs(json.loads(moved.read_text(encoding="utf-8"))["takeover"]["on_boot"], False)

    def test_init_writes_a_private_config_and_refuses_placeholders(self):
        self.path.unlink()
        inputs = self.write_inputs({
            "proxy_name": "VPS", "server": "fd7a:115c:a1e0::abcd", "port": 1081})
        code, out, err = self.invoke(["init", "--inputs", str(inputs),
                                   "--mihomo", "/usr/local/bin/mihomo"])
        self.assertEqual(code, 0, err)
        self.assertNotIn("fd7a:115c:a1e0::abcd", out)
        self.assertNotIn("203.0.113.20", out)
        body = json.loads(out)
        self.assertEqual(body["result"], "daemon_config_written")
        self.assertIs(body["on_boot"], False)
        self.assertIs(body["installed"], False)
        self.assertIs(body["loaded_daemon"], False)
        self.assertIs(body["takeover_started"], False)
        loaded = d.load_daemon_config(self.path, expected_uid=os.geteuid())
        self.assertIs(loaded["takeover"]["on_boot"], False)
        self.assertIsNone(loaded["takeover"]["profile"])
        self.assertIsNone(loaded["takeover"]["state_dir"])
        self.assertEqual(loaded["takeover"]["mihomo_path"], "/usr/local/bin/mihomo")
        self.assertEqual(loaded["takeover"]["inputs"]["server"], "fd7a:115c:a1e0::abcd")
        self.assertEqual(loaded["dashboard"]["port"], 8765)
        raw = self.path.read_text(encoding="utf-8")
        self.assertIn('"on_boot": false', raw)
        self.assertNotIn('"on_boot": "false"', raw)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode) & 0o777, 0o600)
        self.assertEqual(self.path.stat().st_uid, os.geteuid())
        self.assertFalse(self.path.is_symlink())

        code, _, err = self.invoke(["init", "--inputs", str(inputs)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "daemon_config_exists")
        self.assertEqual(self.path.read_text(encoding="utf-8"), raw)

    def test_init_refuses_placeholder_relative_mihomo_and_unsafe_paths(self):
        self.path.unlink()
        placeholder = self.write_inputs(
            {"proxy_name": "VPS", "server": "203.0.113.20", "port": 1080},
            name="placeholder.json")
        code, out, err = self.invoke(["init", "--inputs", str(placeholder)])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["error"], "placeholder_inputs")
        self.assertNotIn("203.0.113.20", out + err)
        self.assertFalse(self.path.exists())

        mixed = self.write_inputs(
            {"server": "203.0.113.20", "port": 1081}, name="mixed.json")
        code, _, err = self.invoke(["init", "--inputs", str(mixed)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "placeholder_server_requires_placeholder_port")
        self.assertFalse(self.path.exists())

        public = self.write_inputs({"server": "8.8.8.8", "port": 1080}, name="public.json")
        code, _, err = self.invoke(["init", "--inputs", str(public)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "invalid_server")
        self.assertFalse(self.path.exists())

        text_port = self.write_inputs(
            {"server": "fd7a:115c:a1e0::abcd", "port": "1081"}, name="text-port.json")
        code, _, err = self.invoke(["init", "--inputs", str(text_port)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "invalid_port")
        self.assertFalse(self.path.exists())

        good = self.write_inputs(
            {"server": "fd7a:115c:a1e0::abcd", "port": 1081}, name="good.json")
        code, _, err = self.invoke(["init", "--inputs", str(good), "--mihomo", "mihomo"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "invalid_mihomo_path")
        self.assertFalse(self.path.exists())

        code, _, err = self.invoke(["init"])
        self.assertEqual(code, 2)
        self.assertIn("init --inputs", err)
        self.assertFalse(self.path.exists())

        unsafe = self.base / "unsafe"
        unsafe.mkdir(mode=0o700)
        os.chmod(unsafe, 0o777)
        with patch.object(d, "default_daemon_config_path", return_value=unsafe / "daemon.json"):
            code, _, err = self.invoke(["init", "--inputs", str(good)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_group_or_world_writable")
        self.assertFalse((unsafe / "daemon.json").exists())

        real = self.base / "real"
        real.mkdir(mode=0o700)
        link = self.base / "via"
        link.symlink_to(real, target_is_directory=True)
        with patch.object(d, "default_daemon_config_path", return_value=link / "daemon.json"):
            code, _, err = self.invoke(["init", "--inputs", str(good)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(err)["error"], "config_not_regular")
        self.assertFalse((real / "daemon.json").exists())

    def test_init_creates_a_private_parent_when_the_directory_is_missing(self):
        nested = self.base / "fresh" / "nmd" / "daemon.json"
        inputs = self.write_inputs(
            {"server": "100.64.0.1", "port": 1080}, name="v4.json")
        with patch.object(d, "default_daemon_config_path", return_value=nested):
            code, out, err = self.invoke(["init", "--inputs", str(inputs)])
        self.assertEqual(code, 0, err)
        self.assertNotIn("100.64.0.1", out)
        self.assertEqual(stat.S_IMODE(nested.parent.stat().st_mode) & 0o777, 0o700)
        self.assertEqual(stat.S_IMODE(nested.parent.parent.stat().st_mode) & 0o777, 0o700)
        self.assertEqual(stat.S_IMODE(nested.stat().st_mode) & 0o777, 0o600)
        self.assertIs(json.loads(nested.read_text(encoding="utf-8"))["takeover"]["on_boot"], False)

    def test_existing_daemon_actions_still_reject_a_second_word(self):
        for action in d._DAEMON_ACTIONS:
            self.assertEqual(self.invoke([action, "extra"])[0], 2, action)
        self.assertEqual(self.invoke([])[0], 2)
        self.assertEqual(self.invoke(["bogus"])[0], 2)

    def test_manager_forwards_on_boot_only_on_macos(self):
        import manager
        with patch.object(manager.nmd_platform, "name", return_value="macos"), \
                patch("nmd_daemon.cli_daemon", return_value=0) as cli:
            with self.assertRaises(SystemExit) as ctx:
                manager.main(["macos", "daemon", "on-boot", "status"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(cli.call_args.args, (["on-boot", "status"],))
        with patch.object(manager.nmd_platform, "name", return_value="linux"):
            with self.assertRaises(SystemExit):
                manager.main(["macos", "daemon", "on-boot", "on"])


class SourceSafetyTests(unittest.TestCase):
    def test_source_keeps_the_mutation_surface_closed(self):
        source = (ROOT / "scripts/nmd_daemon.py").read_text(encoding="utf-8")
        for banned in (r"-set[a-z]*proxy", r"-setproxystat", r"-setproxybypassdomains",
                       r"-setnetworkserviceenabled", r"paramiko"):
            self.assertNotRegex(source, banned, banned)
        self.assertIn("macos_takeover.execute_mutating", source)
        self.assertIn("mutating_allowlisted", source)
        self.assertEqual((d.LABEL, d.SOCKET_PATH),
                         ("io.github.zzzhty.nmd-daemon", "/var/run/nmd-daemon.sock"))

    def test_cli_boundaries(self):
        script = str(ROOT / "scripts/nmd_daemon.py")
        import subprocess
        for argv, expected in ((["help"], 0), (["bogus"], 2), ([], 2)):
            result = subprocess.run([sys.executable, script, *argv],
                                    check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, argv)


if __name__ == "__main__":
    unittest.main()
