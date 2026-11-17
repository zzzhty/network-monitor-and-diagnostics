"""Phase C daemon tests: fully offline, nothing real is spawned or mutated.

The supervisor drives the same injected fixture host as the takeover tests
(Table/FakeProcess), and the IPC server runs on a real AF_UNIX socket in a
temporary directory, so the macOS CI runner never clears an exit node, never
starts mihomo, and never writes launchd state.
"""
import contextlib
import json
import os
from pathlib import Path
import socket
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
from test_macos_takeover import FakeProcess, Table, TS, MIHOMO

CONFIG = {"schema_version": 1, "dashboard": {"port": 8765},
          "takeover": {"inputs": {"proxy_name": "VPS", "server": "fd7a:115c:a1e0::abcd",
                                  "port": 1081},
                       "profile": None, "on_boot": False, "check_interval_seconds": 20,
                       "critical_failures": 3, "mihomo_path": MIHOMO, "state_dir": None}}


def make_supervisor(state, table, config=None, *, on_boot=False, boottime=lambda: 111):
    config = json.loads(json.dumps(config or CONFIG))
    config["takeover"]["on_boot"] = on_boot
    return d.RootSupervisor(
        config, state, runner=table.runner, mutator=table.mutator,
        spawner=table.spawner, tcp=table.tcp, exists=lambda path: path == TS,
        sleep=table.sleep, now=lambda: table.clock, boottime=boottime,
        socket_path=Path(state) / "nmd.sock")


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

    def test_health_failures_rollback_without_auto_retry(self):
        table = Table(dns_dirty_window=(1, 40), tcp_ok=False)
        sup = make_supervisor(self.state, table)
        self.assertEqual(sup.start_takeover()["result"], "takeover_active")
        self.assertTrue(sup._watchdog_once())  # cycle 1 fails
        self.assertEqual(sup.status()["failures"], 1)
        self.assertTrue(sup._watchdog_once())  # cycle 2
        self.assertEqual(sup.status()["failures"], 2)
        self.assertFalse(sup._watchdog_once())  # cycle 3 → rollback
        status = sup.status()
        self.assertEqual((status["phase"], status["result"]),
                         (d.PHASE_ROLLED_BACK, "critical_failures"))
        # No auto-retry: further cycles stay quiet, and a manual start works.
        self.assertTrue(sup._watchdog_once())
        self.assertEqual(sup.status()["phase"], d.PHASE_ROLLED_BACK)

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
        patches = [
            patch.object(d, "USER_PLIST_DIR", self.user_agents),
            patch.object(d, "ROOT_PLIST_DIR", self.root_daemons),
            patch.object(d, "SOCKET_PATH", self.base / "nmd.sock"),
            patch.object(manager, "ROOT", self.checkout),
            patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}),
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
