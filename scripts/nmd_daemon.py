"""Phase C daemon: a persistent Paseo-style supervisor for macOS.

Two cooperating processes. The root supervisor (launchd, KeepAlive) owns the
mihomo takeover: fresh snapshot before every start — including boot — health
cycles with no absolute deadline, immediate panic rollback when our process
dies, and an idempotent restore that reuses the Phase B primitives verbatim.
The user daemon owns the dashboard and the monitor collector. The two talk
over one root-owned UNIX socket with a closed command set; takeover.start is
reserved for uid 0 by peer credentials. All mutations still pass the Phase B
allowlist (macos_takeover.mutating_allowlisted); system proxy and bypass are
never touched. Linux's systemd monitor and the Windows scheduled task are
unchanged; this module is macOS-only.
"""

from __future__ import annotations

import contextlib
import errno
import grp
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

import macos_coexist
import macos_prepare
import macos_takeover

DAEMON_SCHEMA_VERSION = 1
LABEL = "io.github.zzzhty.nmd-daemon"
SOCKET_PATH = "/var/run/nmd-daemon.sock"
SOCKET_GROUP = "admin"
SOCKET_MODE = 0o660
DEFAULT_DASHBOARD_PORT = 8765
IPC_MAX_BYTES = 4096
IPC_TIMEOUT = 3.0
RECOVER_BACKOFF_SECONDS = 30
MTIME_POLL_SECONDS = 15
IDLE_POLL_SECONDS = 1.0
SUPPRESS_BOOT_RESULTS = ("stopped", "critical_failures", "mihomo_exited",
                         "takeover_error", "preflight_failed")

HELP = """\
usage: sudo python3 scripts/nmd_daemon.py supervise --config daemon.json --state-dir DIR
       python3 scripts/nmd_daemon.py run-user --config daemon.json

The root supervisor owns the takeover (fresh snapshot before every start,
health-driven rollback, panic recovery, no absolute deadline); the user
daemon supervises the collector and serves the dashboard. install/uninstall
and the launchd lifecycle arrive with the install stage.
"""


class DaemonError(Exception):
    """Stable error codes; never carries command output."""


# --- daemon configuration -----------------------------------------------------


def _bounded_int(value, low, high, name):
    if type(value) is not int or isinstance(value, bool) or not low <= value <= high:
        raise DaemonError(name)
    return value


def validate_daemon_config(value):
    """Exact-key config. ``inputs`` and ``profile`` delegate to Phase A."""
    if not isinstance(value, dict) or set(value) != {"schema_version", "dashboard", "takeover"}:
        raise DaemonError("invalid_daemon_config")
    if value["schema_version"] != 1:
        raise DaemonError("unsupported_schema")
    dashboard = value["dashboard"]
    if not isinstance(dashboard, dict) or set(dashboard) != {"port"}:
        raise DaemonError("invalid_dashboard")
    _bounded_int(dashboard["port"], 1, 65535, "invalid_port")
    takeover = value["takeover"]
    if not isinstance(takeover, dict) or set(takeover) != {
            "inputs", "profile", "on_boot", "check_interval_seconds",
            "critical_failures", "mihomo_path", "state_dir"}:
        raise DaemonError("invalid_takeover")
    if type(takeover["on_boot"]) is not bool:
        raise DaemonError("invalid_on_boot")
    _bounded_int(takeover["check_interval_seconds"], 5, 300, "invalid_check_interval")
    _bounded_int(takeover["critical_failures"], 1, 10, "invalid_critical_failures")
    if takeover["mihomo_path"] is not None and (
            not isinstance(takeover["mihomo_path"], str)
            or not Path(takeover["mihomo_path"]).is_absolute()):
        raise DaemonError("invalid_mihomo_path")
    if takeover["state_dir"] is not None and (
            not isinstance(takeover["state_dir"], str)
            or not Path(takeover["state_dir"]).is_absolute()):
        raise DaemonError("invalid_state_dir")
    try:
        inputs = macos_prepare.validate_inputs(takeover["inputs"])
    except ValueError as exc:
        raise DaemonError(f"invalid_inputs:{exc}") from None
    profile = takeover["profile"]
    if profile is not None:
        if macos_coexist.validate_experiment_profile(profile):
            raise DaemonError("invalid_profile")
    return dict(value, takeover=dict(takeover, inputs=inputs))


def default_daemon_config_path(root=None):
    """configDir/daemon.json: the recorded install dir, else the XDG default."""
    if root is not None:
        try:
            import manager
            recorded = manager.setting(Path(root), "configDir")
        except Exception:
            recorded = ""
        if recorded and Path(recorded).is_absolute():
            return Path(recorded) / "daemon.json"
    base = os.environ.get("XDG_CONFIG_HOME")
    base = Path(base) if base and Path(base).is_absolute() else Path.home() / ".config"
    return base / "nmd" / "daemon.json"


def load_daemon_config(path, *, expected_uid=None):
    """Read a regular, non-symlink config and reject a writable parent.

    ``open()`` follows the final symlink, so a check after the read can be
    shown a different inode than the one that was parsed. The fd is fstat'd
    before the bytes are trusted.
    """
    path = Path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise DaemonError("config_not_regular") from exc
        raise DaemonError("config_unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise DaemonError("config_not_regular")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise DaemonError("config_group_or_world_writable")
        if expected_uid is not None and info.st_uid != expected_uid:
            raise DaemonError("config_owner_changed")
        _require_trusted_path(path)
        data = os.read(fd, 65537)
    finally:
        os.close(fd)
    if len(data) > 65536:
        raise DaemonError("config_too_large")
    try:
        value = json.loads(data)
    except ValueError as exc:
        raise DaemonError("config_invalid_json") from exc
    return validate_daemon_config(value)


def write_daemon_config(path, value):
    validated = validate_daemon_config(value)
    path = Path(path)
    macos_prepare._create_private_parents(path.parent)
    payload = json.dumps(validated, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
    macos_prepare._atomic_private_write(path.parent, path.name, payload)
    return path


def _require_trusted_path(path):
    """Reject a symlink or a replaceable ancestor. The leaf may be the file."""
    try:
        macos_takeover.assert_private_ancestors(path)
    except macos_takeover.TakeoverError as exc:
        if str(exc) == "unsafe_path_parent":
            raise DaemonError("config_group_or_world_writable") from exc
        raise DaemonError("config_not_regular") from exc


def check_private_config(path, *, expected_uid=None):
    """The root supervisor re-checks this user-owned file before trusting it."""
    _require_trusted_path(path)
    info = os.lstat(path)
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise DaemonError("config_group_or_world_writable")
    if not stat.S_ISREG(info.st_mode):
        raise DaemonError("config_not_regular")
    if expected_uid is not None and info.st_uid != expected_uid:
        raise DaemonError("config_owner_changed")
    return True


# --- IPC: one JSON line per connection ----------------------------------------


def _uid_from_cred(platform, data):
    """Parse a uid from one platform's peer-credential buffer.

    Darwin ``struct xucred`` starts with ``u_int cr_version`` then ``uid_t
    cr_uid``. ``cr_ngroups`` is a short, so the buffer is not three ints, and
    a 12-byte ``getsockopt`` is rejected by the kernel. Linux ``struct ucred``
    is pid, uid, gid.
    """
    if not data:
        return -1
    if platform == "darwin":
        if len(data) < 8:
            return -1
        version, uid = struct.unpack_from("@Ii", data)
        if version != 0 or uid < 0:
            return -1
        return uid
    width = struct.calcsize("@iii")
    if len(data) < width:
        return -1
    _pid, uid, _gid = struct.unpack_from("@iii", data)
    return uid if uid >= 0 else -1


def peer_uid(conn):
    """Peer credentials: LOCAL_PEERCRED on Darwin, SO_PEERCRED on Linux."""
    try:
        if sys.platform == "darwin":
            option = getattr(socket, "LOCAL_PEERCRED", 0x001)
            level = getattr(socket, "SOL_LOCAL", 0)
            # sizeof(struct xucred) is 76 on LP64; ask for more and parse the prefix.
            data = conn.getsockopt(level, option, 256)
            platform = "darwin"
        else:
            option = getattr(socket, "SO_PEERCRED", 17)
            level = socket.SOL_SOCKET
            data = conn.getsockopt(level, option, struct.calcsize("@iii"))
            platform = "linux"
    except OSError:
        return -1
    return _uid_from_cred(platform, data)


class DaemonIPCServer:
    """Root-owned socket; strict single-object JSON; closed command set."""

    def __init__(self, socket_path, dispatch, *, peer_uid_fn=peer_uid,
                 group=SOCKET_GROUP, mode=SOCKET_MODE):
        self.socket_path = Path(socket_path)
        self.dispatch = dispatch
        self.peer_uid_fn = peer_uid_fn
        self.group = group
        self.mode = mode
        self._socket = None

    def bind(self):
        try:
            info = self.socket_path.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            # unlink() removes a symlink itself. A regular file at this path
            # is not ours to delete.
            if stat.S_ISLNK(info.st_mode) or stat.S_ISSOCK(info.st_mode):
                self.socket_path.unlink()
            else:
                raise DaemonError("socket_path_not_socket")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        if self.group is not None:
            with contextlib.suppress(KeyError, OSError, PermissionError):
                os.chown(self.socket_path, -1, grp.getgrnam(self.group).gr_gid)
        os.chmod(self.socket_path, self.mode)
        server.listen(4)
        self._socket = server
        return self

    def close(self):
        if self._socket is not None:
            with contextlib.suppress(OSError):
                self._socket.close()
            self._socket = None
            with contextlib.suppress(OSError):
                self.socket_path.unlink()

    def _answer(self, conn):
        conn.settimeout(IPC_TIMEOUT)
        try:
            chunks, total = [], 0
            while total <= IPC_MAX_BYTES:
                block = conn.recv(IPC_MAX_BYTES + 1 - total)
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if b"\n" in block:
                    break
            payload = b"".join(chunks)
        except OSError:
            return
        if not payload or len(payload) > IPC_MAX_BYTES:
            reply = {"error": "invalid_payload"}
        else:
            try:
                message = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                message = None
            if not isinstance(message, dict):
                reply = {"error": "invalid_payload"}
            else:
                try:
                    reply = self.dispatch(message, self.peer_uid_fn(conn))
                except DaemonError as exc:
                    reply = {"error": str(exc)}
                except Exception:
                    reply = {"error": "internal_error"}
        with contextlib.suppress(OSError):
            conn.sendall(json.dumps(reply, ensure_ascii=False).encode() + b"\n")

    def serve_forever(self, stop_event=None):
        stop_event = stop_event or threading.Event()
        if self._socket is None:
            self.bind()
        self._socket.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._answer(conn)
            finally:
                with contextlib.suppress(OSError):
                    conn.close()


class DaemonClientBridge:
    """TTL-cached status relay; a dead socket never blocks the dashboard."""

    def __init__(self, socket_path=SOCKET_PATH, ttl=5.0, clock=None):
        self._client = DaemonIPCClient(socket_path, timeout=1.5)
        self._ttl = ttl
        self._clock = clock or time.monotonic
        self._cached = None
        self._at = -1e12

    def status_cached(self):
        if self._cached is None or self._clock() - self._at >= self._ttl:
            try:
                self._cached = self._client.status()
            except DaemonError as exc:
                self._cached = {"error": str(exc)}
            self._at = self._clock()
        return self._cached

    def stop_takeover(self):
        try:
            return self._client.stop_takeover()
        except DaemonError as exc:
            return {"error": str(exc)}


class DaemonIPCClient:
    def __init__(self, socket_path, timeout=IPC_TIMEOUT):
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def _call(self, message):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(message).encode() + b"\n")
            # One request per connection: half-close so the server can treat
            # end-of-input as a complete (or truncated) payload.
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_WR)
            data = sock.recv(IPC_MAX_BYTES + 1)
        except OSError as exc:
            raise DaemonError("daemon_unavailable") from exc
        finally:
            sock.close()
        try:
            reply = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise DaemonError("invalid_reply") from None
        return reply if isinstance(reply, dict) else {"error": "invalid_reply"}

    def status(self):
        return self._call({"cmd": "status"})

    def stop_takeover(self):
        return self._call({"cmd": "takeover.stop"})

    def start_takeover(self):
        return self._call({"cmd": "takeover.start"})


# --- root supervisor ----------------------------------------------------------

SESSION_FILE = "daemon-session.json"
PHASE_DIRECT = "direct"
PHASE_STARTING = "starting"
PHASE_ACTIVE = "active"
PHASE_NEEDS_ROLLBACK = "needs_rollback"
PHASE_ROLLED_BACK = "rolled_back"
_PHASES = (PHASE_DIRECT, PHASE_STARTING, PHASE_ACTIVE, PHASE_NEEDS_ROLLBACK, PHASE_ROLLED_BACK)


def _darwin_boot_id():
    try:
        result = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.boottime"],
                                capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"sec\s*=\s*(\d+)", result.stdout)
    return int(match.group(1)) if match else None


def _linux_boot_id():
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def boot_id():
    if sys.platform == "darwin":
        return _darwin_boot_id()
    return _linux_boot_id()


def stage_geodata(target_dir, source_dir=None):
    """Delegate to the shared no-follow copy used by the foreground controller."""
    return macos_takeover.stage_geodata(target_dir, source_dir)


def run_mihomo_validate(mihomo, config_path, work_dir, timeout=30):
    """Delegate to the shared allowlisted ``-d`` validation."""
    return macos_takeover.run_mihomo_validate(mihomo, config_path, work_dir, timeout)


class RootSupervisor:
    """Owns the takeover; every host interaction is injectable for tests."""

    def __init__(self, config, state_dir, *, runner=None, mutator=None,
                 spawner=None, tcp=None, exists=None, sleep=None, now=None,
                 boottime=None, socket_path=SOCKET_PATH, validator=None,
                 geodata_dir=None):
        self.config = validate_daemon_config(config)
        takeover = self.config["takeover"]
        state_dir = Path(state_dir)
        if not state_dir.is_absolute():
            state_dir = Path.cwd() / state_dir
        if state_dir.is_symlink():
            raise DaemonError("state_dir_symlink")
        try:
            macos_takeover.assert_private_ancestors(state_dir)
        except macos_takeover.TakeoverError as exc:
            if str(exc) == "unsafe_path_symlink":
                raise DaemonError("state_dir_symlink") from exc
            raise DaemonError("unsafe_state_dir") from exc
        self.state_dir = state_dir
        self.runner = runner or macos_prepare.execute
        self.sleep = sleep or time.sleep
        self.now = now or time.monotonic
        self.boottime = boottime or boot_id
        self.validator = validator or run_mihomo_validate
        self.geodata_dir = geodata_dir
        mihomo = macos_takeover.first_mihomo(exists=exists, override=takeover["mihomo_path"])
        if mutator is None:
            def mutator(argv):  # noqa: E306
                return macos_takeover.execute_mutating(argv, mihomo_path=mihomo)
        self.mutator = mutator
        self.spawner = spawner
        if tcp is None:
            import macos_readonly
            tcp = macos_readonly.tcp_connect
        self.tcp = tcp
        self.exists = exists or (lambda path: Path(path).is_file() and os.access(path, os.X_OK))
        self.mihomo = mihomo
        self.tailscale = macos_takeover.first_tailscale(self.exists)
        self.socket_path = socket_path
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._settled = threading.Event()
        self._settled.set()
        self.phase = PHASE_DIRECT
        self.result = None
        self.snapshot_name = None
        self.last_rollback = None
        self.boot = None
        self.started_at = None
        self.failures = 0
        self.mutations = []
        self.checks = []
        self.process = None
        self._ipc = None

    # -- persistence ----------------------------------------------------------

    def _session_path(self):
        return self.state_dir / SESSION_FILE

    def _persist_session(self):
        payload = {"schema_version": DAEMON_SCHEMA_VERSION, "label": LABEL,
                   "boot_id": self.boot, "phase": self.phase, "result": self.result,
                   "snapshot_name": self.snapshot_name, "started_at": self.started_at,
                   "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}
        macos_prepare._create_private_parents(self.state_dir)
        macos_prepare._atomic_private_write(
            self.state_dir, SESSION_FILE,
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")

    def _load_session(self):
        try:
            data = json.loads(self._session_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _record_failed_start(self, outcome, extra):
        """Persist a run record even when the start never reached the cutover."""
        self.result = outcome
        self._persist_session()
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        record = {"schema_version": DAEMON_SCHEMA_VERSION, "kind": "nmd_daemon_run",
                  "result": outcome, "phase": self.phase,
                  "boot_id": self.boot, "started_at": self.started_at,
                  "mutations": [], "rollback": None}
        record.update(extra or {})
        macos_prepare._atomic_private_write(
            self.state_dir, f"takeover-{stamp}.json",
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")

    def _record_run(self, outcome, rollback):
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        record = {"schema_version": DAEMON_SCHEMA_VERSION, "kind": "nmd_daemon_run",
                  "result": outcome, "phase": self.phase,
                  "boot_id": self.boot, "started_at": self.started_at,
                  "mutations": list(self.mutations), "rollback": rollback}
        macos_prepare._atomic_private_write(
            self.state_dir, f"takeover-{stamp}.json",
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")

    # -- lifecycle ------------------------------------------------------------

    def _recover_leftovers(self):
        """An 'active' session from a dead supervisor is rolled back first."""
        session = self._load_session()
        if session is None:
            return
        self.boot = session.get("boot_id")
        self.result = session.get("result")
        self.started_at = session.get("started_at")
        name = session.get("snapshot_name")
        self.snapshot_name = name if isinstance(name, str) else None
        self.phase = session.get("phase") if session.get("phase") in _PHASES else PHASE_DIRECT
        if session.get("phase") in (PHASE_ACTIVE, PHASE_STARTING, PHASE_NEEDS_ROLLBACK):
            # starting: we may already have cleared the exit node. active: the
            # takeover is still logically on. needs_rollback: a previous
            # restore did not finish. All three use the pinned snapshot.
            try:
                rollback = self._rollback_now()
            except Exception as exc:
                rollback = {"result": f"rollback_error:{type(exc).__name__}"}
            self.last_rollback = rollback
            self.phase = (PHASE_ROLLED_BACK if rollback.get("result") == "rollback_restored"
                          else PHASE_NEEDS_ROLLBACK)
            self.result = "recovered_leftovers"
            self.process = None
            self._persist_session()
            self._record_run("recovered_leftovers", rollback)

    def _boot_policy(self):
        """True boot with on_boot and a healthy history resumes takeover.

        KeepAlive restarts within the same boot never auto-resume: that is the
        anti-flap rule, since launchd would otherwise re-takeover every 10s.
        """
        current = self.boottime()
        if current is None:
            return
        same_boot = current == self.boot
        self.boot = current
        if self.phase == PHASE_NEEDS_ROLLBACK:
            # Do not take a fresh snapshot, and do not start, while the
            # previous cutover is only partly undone.
            self._persist_session()
            return
        takeover = self.config["takeover"]
        should = (takeover["on_boot"] and not same_boot
                  and self.result not in SUPPRESS_BOOT_RESULTS
                  and self.phase not in (PHASE_ACTIVE, PHASE_STARTING))
        if should:
            self.start_takeover(reason="boot")
        else:
            self._persist_session()

    # -- takeover -------------------------------------------------------------

    def start_takeover(self, reason="manual"):
        """Fresh snapshot before every start — including boot. Then cutover."""
        self._lock.acquire()
        try:
            return self._start_takeover_locked(reason)
        finally:
            self._lock.release()

    def _start_takeover_locked(self, reason):
        if self.phase == PHASE_NEEDS_ROLLBACK:
            return {"error": "rollback_pending"}
        if self.phase == PHASE_ACTIVE:
            return {"result": "already_active"}
        takeover = self.config["takeover"]
        inputs = takeover["inputs"]
        if inputs["server"] == macos_coexist.PLACEHOLDER_SOCKS_HOST:
            return {"error": "placeholder_inputs"}
        profile = takeover["profile"] or json.loads(
            (Path(__file__).resolve().parents[1]
             / "examples/macos-mihomo-coexist.experiment.json").read_text(encoding="utf-8"))
        text = macos_prepare.render_config(profile, inputs)
        try:
            config_dir = macos_takeover.ensure_workdir(self.state_dir / "takeover")
        except macos_takeover.TakeoverError as exc:
            return {"error": str(exc)}
        config_path = config_dir / "config.yaml"
        macos_prepare._atomic_private_write(config_dir, "config.yaml", text.encode())
        if not macos_takeover.config_is_direct_regular(config_dir, config_path):
            return {"error": "mihomo_t_failed", "detail": "config_not_confined"}
        staged, missing = stage_geodata(config_dir, self.geodata_dir)
        ok, detail = self.validator(self.mihomo, config_path, config_dir)
        if not ok:
            self._record_failed_start("mihomo_t_failed",
                                      {"detail": detail, "geodata_staged": staged,
                                       "geodata_missing": missing})
            return {"error": "mihomo_t_failed", "detail": detail,
                    "geodata_staged": staged, "geodata_missing": missing}
        _, summary, snapshot_path = macos_prepare.collect_snapshot(
            "macos", self.state_dir, runner=self.runner, exists=self.exists)
        if summary.get("has_198_18") is True or summary.get("mihomo_running") is True:
            return {"error": "preflight_failed",
                    "has_198_18": summary.get("has_198_18"),
                    "mihomo_running": summary.get("mihomo_running")}
        self.snapshot_name = Path(snapshot_path).name if snapshot_path is not None else None
        try:
            macos_takeover.write_pin(self.state_dir, self.snapshot_name)
        except macos_takeover.TakeoverError as exc:
            return {"error": "snapshot_failed", "detail": str(exc)}
        self._settled.clear()
        self.phase = PHASE_STARTING
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        self._persist_session()
        if self._cancel.is_set():
            self.phase = PHASE_DIRECT
            self._cancel.clear()
            self._persist_session()
            self._settled.set()
            return {"result": "stopped", "reason": "manual_stop"}
        mutations = []
        process = None
        try:
            try:
                self.mutator([self.tailscale, "set", "--exit-node="])
            except macos_takeover.TakeoverError as exc:
                self.phase = PHASE_DIRECT
                self._record_failed_start("exit_node_clear_failed", {"detail": str(exc)})
                return {"error": "exit_node_clear_failed", "detail": str(exc)}
            mutations.append([self.tailscale, "set", "--exit-node="])
            if not macos_takeover.config_is_direct_regular(config_dir, config_path):
                self._finish_locked("config_not_confined", None, mutations)
                return {"error": "config_not_confined"}
            process = macos_takeover.MihomoProcess(
                macos_takeover.launch_argv(self.mihomo, config_dir, config_path),
                str(config_dir / "mihomo.log"))
            process.start(spawner=self.spawner)
            macos_takeover.write_owner(
                self.state_dir, process.pid, self.mihomo, str(config_dir),
                runner=self.runner)
            ready_by = self.now() + macos_takeover.READY_TIMEOUT_SECONDS
            while self.now() < ready_by:
                if self._cancel.is_set():
                    rollback = self._finish_locked("manual_stop", process, mutations)
                    return {"result": rollback.get("result", "stopped"), "reason": "manual_stop"}
                _, dns_text = macos_takeover.read_state(
                    ["/usr/sbin/scutil", "--dns"], runner=self.runner)
                parsed = macos_prepare._parse_scutil_dns(0, dns_text, None)
                if parsed["has_198_18"] is True:
                    break
                if not process.alive():
                    self._finish_locked("mihomo_exited_early", process, mutations)
                    return {"error": "mihomo_exited_early"}
                # Let stop/status run during the wait. Reacquire before touching state.
                self._lock.release()
                try:
                    self.sleep(macos_takeover.READY_POLL_SECONDS)
                finally:
                    self._lock.acquire()
                # Supervisor shutdown can finish the run while this lock is dropped.
                if self.phase != PHASE_STARTING:
                    rollback = self.last_rollback or {}
                    return {"result": rollback.get("result", "stopped"),
                            "reason": self.result or "stopped"}
            else:
                if self._cancel.is_set():
                    rollback = self._finish_locked("manual_stop", process, mutations)
                    return {"result": rollback.get("result", "stopped"), "reason": "manual_stop"}
                self._finish_locked("ready_timeout", process, mutations)
                return {"error": "ready_timeout"}
            if self._cancel.is_set():
                rollback = self._finish_locked("manual_stop", process, mutations)
                return {"result": rollback.get("result", "stopped"), "reason": "manual_stop"}
        except Exception as exc:
            if process is not None or mutations:
                self._finish_locked(f"takeover_error:{type(exc).__name__}", process, mutations)
            else:
                self.phase, self.result = PHASE_DIRECT, f"takeover_error:{type(exc).__name__}"
                self._persist_session()
            if isinstance(exc, macos_takeover.TakeoverError):
                return {"error": str(exc)}
            return {"error": type(exc).__name__}
        finally:
            self._settled.set()
        if self.phase != PHASE_STARTING:
            rollback = self.last_rollback or {}
            return {"result": rollback.get("result", "stopped"),
                    "reason": self.result or "stopped"}
        self.process = process
        self.mutations = mutations
        self.checks = macos_takeover._watch_checks(
            inputs, runner=self.runner, tcp=self.tcp, exists=self.exists)
        self.failures = 0
        self.phase = PHASE_ACTIVE
        self.result = None
        self._persist_session()
        return {"result": "takeover_active", "reason": reason,
                "geodata_staged": staged}

    def _rollback_now(self):
        return macos_takeover.rollback(
            self.state_dir, runner=self.runner, mutator=self.mutator,
            sleep=self.sleep, now=self.now, tailscale_path=self.tailscale,
            snapshot_name=self.snapshot_name)

    def _finish_locked(self, outcome, process, mutations):
        """Shared teardown+rollback for every exit path; caller holds the lock.

        A restore that did not actually put the snapshot values back stays
        ``needs_rollback``. Calling that ``rolled_back`` would make the next
        launchd restart skip it.
        """
        if process is not None:
            process.terminate_group()
        self.mutations = list(mutations)
        try:
            rollback = self._rollback_now()
        except Exception as exc:  # keep the supervisor alive on rollback crashes
            rollback = {"result": f"rollback_error:{type(exc).__name__}"}
        self.last_rollback = rollback
        self.phase = (PHASE_ROLLED_BACK if rollback.get("result") == "rollback_restored"
                      else PHASE_NEEDS_ROLLBACK)
        self.result = outcome
        self.failures = 0
        self.process = None
        self.checks = []
        self._cancel.clear()
        self._persist_session()
        self._record_run(outcome, rollback)
        return rollback

    def _retry_rollback(self):
        """One more attempt at an unfinished restore. Does not start a takeover."""
        with self._lock:
            if self.phase != PHASE_NEEDS_ROLLBACK:
                return True
            try:
                rollback = self._rollback_now()
            except Exception as exc:
                rollback = {"result": f"rollback_error:{type(exc).__name__}"}
            self.last_rollback = rollback
            if rollback.get("result") != "rollback_restored":
                return False
            self.phase = PHASE_ROLLED_BACK
            self._persist_session()
            self._record_run(self.result or "rollback_retried", rollback)
            return True

    def stop_takeover(self, reason="manual_stop"):
        self._cancel.set()
        with self._lock:
            if self.phase == PHASE_ACTIVE:
                rollback = self._finish_locked(reason, self.process, self.mutations)
                return {"result": rollback.get("result", "rollback_restored"),
                        "reason": reason}
            if self.phase != PHASE_STARTING:
                self._cancel.clear()
                return {"result": "not_active"}
        # The starter owns the teardown and clears the cancel when it finishes.
        if not self._settled.wait(macos_takeover.READY_TIMEOUT_SECONDS
                                  + macos_takeover.CLEANUP_TIMEOUT_SECONDS):
            return {"result": "stop_pending", "reason": reason}
        with self._lock:
            rollback = self.last_rollback or {}
            return {"result": rollback.get("result", self.result or "stopped"),
                    "reason": reason}

    # -- health ---------------------------------------------------------------

    def _watchdog_once(self):
        """One health cycle under the lock. False means the run ended."""
        with self._lock:
            if self.phase != PHASE_ACTIVE:
                return True
            if self.process is not None and not self.process.alive():
                self._finish_locked("mihomo_exited", self.process, self.mutations)
                return False
            cycle_failed = False
            for name, critical, check in self.checks:
                try:
                    ok = check()
                except macos_takeover.TakeoverError:
                    ok = False
                if ok or not critical:
                    continue
                cycle_failed = True
            if not cycle_failed:
                self.failures = 0
                return True
            self.failures += 1
            if self.failures >= self.config["takeover"]["critical_failures"]:
                self._finish_locked("critical_failures", self.process, self.mutations)
                return False
            return True

    # -- interface ------------------------------------------------------------

    def dispatch(self, message, uid):
        if (not isinstance(message, dict) or set(message) != {"cmd"}
                or not isinstance(message.get("cmd"), str)):
            return {"error": "invalid_command"}
        cmd = message["cmd"]
        if cmd == "status":
            return self.status()
        if cmd == "takeover.stop":
            outcome = self.stop_takeover()
            return {"result": outcome.get("result"), "reason": outcome.get("reason")}
        if cmd == "takeover.start":
            if uid != 0:
                return {"error": "not_authorized"}
            return self.start_takeover(reason="ipc")
        return {"error": "invalid_command"}

    def status(self):
        with self._lock:
            return {"schema_version": DAEMON_SCHEMA_VERSION, "label": LABEL,
                    "takeover_active": self.phase == PHASE_ACTIVE,
                    "phase": self.phase, "result": self.result,
                    "boot_id": self.boot, "on_boot": self.config["takeover"]["on_boot"],
                    "started_at": self.started_at,
                    "failures": self.failures,
                    "mihomo_pid": self.process.pid if self.process else None}

    def run(self, stop_event=None):
        stop_event = stop_event or threading.Event()
        self._recover_leftovers()
        self._boot_policy()
        self._ipc = DaemonIPCServer(self.socket_path, self.dispatch)
        ipc_stop = threading.Event()
        thread = threading.Thread(target=self._ipc.serve_forever, args=(ipc_stop,), daemon=True)
        thread.start()
        try:
            while not stop_event.is_set():
                if self.phase == PHASE_ACTIVE:
                    self._watchdog_once()
                    interval = self.config["takeover"]["check_interval_seconds"]
                elif self.phase == PHASE_NEEDS_ROLLBACK:
                    self._retry_rollback()
                    interval = self.config["takeover"]["check_interval_seconds"]
                else:
                    interval = IDLE_POLL_SECONDS
                stop_event.wait(interval)
        finally:
            ipc_stop.set()
            self._ipc.close()
            thread.join(timeout=2)
            with self._lock:
                if self.phase in (PHASE_ACTIVE, PHASE_STARTING, PHASE_NEEDS_ROLLBACK):
                    self._finish_locked("supervisor_stopping", self.process, self.mutations)


# --- user daemon (collector supervision; dashboard arrives in Stage 3) --------


class UserDaemon:
    """Owns the monitor collector; config changes restart the thread."""

    def __init__(self, *, monitor_config_path, state_dir, stop_event=None,
                 collect=None, load_config=None, interval=MTIME_POLL_SECONDS):
        self.monitor_config_path = Path(monitor_config_path)
        self.state_dir = Path(state_dir)
        self.stop_event = stop_event or threading.Event()
        if collect is None or load_config is None:
            import nmd_monitor
            collect = collect or nmd_monitor.collect
            load_config = load_config or nmd_monitor.load_config
        self.collect = collect
        self.load_config = load_config
        self.interval = interval
        self.collector_status = "stopped"
        self._thread = None
        self._collect_stop = None
        self._mtime = None

    def _config_mtime(self):
        try:
            return self.monitor_config_path.stat().st_mtime
        except OSError:
            return None

    def start_collector(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._collect_stop = threading.Event()
        self._thread = threading.Thread(target=self._run_collector,
                                        args=(self._collect_stop,), daemon=True)
        self._thread.start()

    def _run_collector(self, stop):
        while not stop.is_set():
            try:
                config = self.load_config(self.monitor_config_path)
                self.collector_status = "running"
                self.collect(config, self.state_dir, stop_event=stop)
                self.collector_status = "stopped"
                return
            except RuntimeError as exc:
                if "collector_already_running" not in str(exc):
                    self.collector_status = f"error:{type(exc).__name__}"
                    return
                # Someone else holds the collector lock: report and back off.
                self.collector_status = "externally_running"
                if stop.wait(RECOVER_BACKOFF_SECONDS):
                    return

    def stop_collector(self):
        if self._collect_stop is not None:
            self._collect_stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        self.collector_status = "stopped"

    def restart_collector(self):
        self.stop_collector()
        self.start_collector()

    def run(self):
        self._mtime = self._config_mtime()
        self.start_collector()
        try:
            while not self.stop_event.wait(self.interval):
                if self._config_mtime() != self._mtime:
                    self._mtime = self._config_mtime()
                    self.restart_collector()
        finally:
            self.stop_collector()


# --- install: launchd plists, receipts, lifecycle (user runs it, sudo helpers) --

DAEMON_PATH_KEYS = frozenset({"root_plist", "user_plist"})
ROOT_PLIST_DIR = Path("/Library/LaunchDaemons")
USER_PLIST_DIR = Path.home() / "Library" / "LaunchAgents"


def _xml(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _plist(label, program_arguments):
    items = "".join(f"\t\t<string>{_xml(item)}</string>\n" for item in program_arguments)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n'
            f'\t<key>Label</key><string>{_xml(label)}</string>\n'
            '\t<key>ProgramArguments</key>\n\t<array>\n' + items + '\t</array>\n'
            '\t<key>RunAtLoad</key><true/>\n'
            '\t<key>KeepAlive</key><true/>\n'
            '\t<key>ThrottleInterval</key><integer>10</integer>\n'
            '</dict>\n</plist>\n')


def root_plist_text(python, script, config_path, state_dir):
    """The root supervisor bakes install-time paths: root must never resolve
    an XDG default (that would land under /var/root)."""
    return _plist(LABEL, [python, script, "supervise",
                          "--config", str(config_path), "--state-dir", str(state_dir)])


def user_plist_text(python, script, config_path):
    return _plist(LABEL, [python, script, "run-user", "--config", str(config_path)])


def _fingerprint(path):
    import hashlib
    data = Path(path).read_bytes()
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def daemon_receipt(root):
    import manager
    raw = manager.setting(Path(root), "daemonReceipt")
    if not raw:
        return None
    try:
        receipt = json.loads(raw)
    except ValueError:
        raise DaemonError("daemon_invalid_receipt") from None
    if (receipt.get("version") != 1 or set(receipt.get("paths", {})) != DAEMON_PATH_KEYS
            or not isinstance(receipt.get("files"), dict)
            or set(receipt["files"]) != DAEMON_PATH_KEYS):
        raise DaemonError("daemon_invalid_receipt")
    return receipt


def save_daemon_receipt(root, receipt):
    import manager
    manager.setting(Path(root), "daemonReceipt", json.dumps(receipt, sort_keys=True))


def check_daemon_file(path, fingerprint, expected_uid):
    """Refuse foreign or modified artifacts, exactly like the desktop receipt."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return False  # absent is fine (idempotent off)
    import stat as stat_module
    info = path.lstat()
    if path.is_symlink() or not stat_module.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise DaemonError(f"daemon_file_not_owned:{path}")
    if info.st_uid != expected_uid or stat_module.S_IMODE(info.st_mode) & 0o022:
        raise DaemonError(f"daemon_file_not_owned:{path}")
    if fingerprint is not None and _fingerprint(path) != fingerprint:
        raise DaemonError(f"daemon_file_not_owned:{path}")
    return True


def _atomic_public_write(path, text):
    import tempfile as temp_module
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = temp_module.mkstemp(dir=str(path.parent), prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _run_helper(argv):
    """Run one sudo helper and parse its JSON-only stdout."""
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    try:
        reply = json.loads(result.stdout or "{}")
    except ValueError:
        reply = {"error": f"helper_failed:{result.returncode}"}
    if result.returncode != 0 and "error" not in reply:
        reply["error"] = f"helper_failed:{result.returncode}"
    return reply


def install_root_plist(config_path, state_dir):
    """euid-0 helper: write + bootstrap the root plist, print its fingerprint."""
    if os.geteuid() != 0:
        raise DaemonError("root_required")
    config_path, state_dir = Path(config_path).resolve(), Path(state_dir).resolve()
    if not config_path.is_file():
        raise DaemonError("config_missing")
    text = root_plist_text(sys.executable, str(Path(__file__).resolve()),
                           config_path, state_dir)
    ROOT_PLIST_DIR.mkdir(parents=True, exist_ok=True)
    path = ROOT_PLIST_DIR / f"{LABEL}.plist"
    if path.is_symlink():
        raise DaemonError("daemon_file_not_owned")
    if path.exists():
        try:
            if _fingerprint(path) != _fingerprint_of_text(text):
                raise DaemonError("daemon_file_not_owned")
        except OSError:
            raise DaemonError("daemon_file_not_owned") from None
    _atomic_public_write(path, text)
    # Written by root for root; tolerate EPERM for non-root test harnesses.
    with contextlib.suppress(PermissionError, OSError):
        os.chown(path, 0, 0)
    bootstrap = subprocess.run(["/bin/launchctl", "bootstrap", "system", str(path)],
                               capture_output=True, text=True)
    if bootstrap.returncode != 0 and "already" not in (bootstrap.stderr or ""):
        with contextlib.suppress(OSError):
            path.unlink()
        raise DaemonError("launchctl_bootstrap_failed")
    return {"root_plist": str(path), "fingerprint": _fingerprint(path)}


def _fingerprint_of_text(text):
    import hashlib
    return {"size": len(text.encode()), "sha256": hashlib.sha256(text.encode()).hexdigest()}


def uninstall_root_plist():
    if os.geteuid() != 0:
        raise DaemonError("root_required")
    path = ROOT_PLIST_DIR / f"{LABEL}.plist"
    subprocess.run(["/bin/launchctl", "bootout", f"system/{LABEL}"],
                   capture_output=True, text=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise DaemonError("daemon_file_not_owned")
        path.unlink()
    return {"uninstalled": str(path)}


def cli_daemon(argv):
    """`nmd macos daemon install|uninstall|start|stop|status|takeover-start`."""
    import manager
    if not argv or argv[0] not in ("install", "uninstall", "start", "stop",
                                   "status", "takeover-start", "takeover-stop"):
        sys.stderr.write(HELP)
        return 2
    action = argv[0]
    root = manager.ROOT
    if action == "takeover-stop":
        # Same trust as the panel button: any admin-group peer may stop.
        try:
            reply = DaemonIPCClient(SOCKET_PATH).stop_takeover()
        except DaemonError as exc:
            reply = {"error": str(exc)}
        print(json.dumps(reply, ensure_ascii=False, indent=2))
        return 0 if "error" not in reply else 1
    if action == "takeover-start":
        if os.geteuid() != 0:
            os.execvp("sudo", ["sudo", "--", sys.executable,
                               str(Path(__file__).resolve()), "daemon", *argv])
        reply = DaemonIPCClient(SOCKET_PATH).start_takeover()
        print(json.dumps(reply, ensure_ascii=False, indent=2))
        return 0 if "error" not in reply else 1
    receipt = daemon_receipt(root)
    if action == "status":
        report = {"installed": receipt is not None,
                  "root_plist": (receipt or {}).get("paths", {}).get("root_plist"),
                  "user_plist": (receipt or {}).get("paths", {}).get("user_plist")}
        try:
            report["daemon"] = DaemonIPCClient(SOCKET_PATH, timeout=1.5).status()
        except DaemonError as exc:
            report["daemon"] = {"error": str(exc)}
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if action == "install":
        manager.managed(root)
        config_path = default_daemon_config_path(root)
        if not Path(config_path).is_file():
            print(json.dumps({"error": "daemon_config_missing",
                              "hint": str(config_path)}), file=sys.stderr)
            return 1
        config = load_daemon_config(config_path)
        if config["takeover"]["inputs"]["server"] == macos_coexist.PLACEHOLDER_SOCKS_HOST:
            print(json.dumps({"error": "placeholder_inputs"}), file=sys.stderr)
            return 1
        state_dir = Path(config["takeover"]["state_dir"]
                         if config["takeover"]["state_dir"] is not None
                         else manager.setting(root, "stateDir"))
        user_plist = USER_PLIST_DIR / f"{LABEL}.plist"
        user_text = user_plist_text(sys.executable, str(Path(__file__).resolve()),
                                    Path(config_path).resolve())
        expected = {"size": len(user_text.encode()),
                    "sha256": _fingerprint_of_text(user_text)["sha256"]}
        uid = os.geteuid()
        if receipt is not None:
            check_daemon_file(user_plist, receipt["files"]["user_plist"], uid)
        elif user_plist.exists() or user_plist.is_symlink():
            raise DaemonError("daemon_file_not_owned")
        USER_PLIST_DIR.mkdir(parents=True, exist_ok=True)
        _atomic_public_write(user_plist, user_text)
        helper = _run_helper(["sudo", "--", sys.executable, str(Path(__file__).resolve()),
                              "install-root", "--config", str(Path(config_path).resolve()),
                              "--state-dir", str(state_dir)])
        if "error" in helper:
            with contextlib.suppress(OSError):
                user_plist.unlink()
            print(json.dumps(helper), file=sys.stderr)
            return 1
        receipt = {"version": 1, "root": str(root),
                   "paths": {"root_plist": helper["root_plist"], "user_plist": str(user_plist)},
                   "files": {"root_plist": helper["fingerprint"],
                             "user_plist": expected}}
        save_daemon_receipt(root, receipt)
        manager.setting(root, "daemonInstalled", "true")
        print(json.dumps({"result": "daemon_installed",
                          "root_plist": helper["root_plist"],
                          "user_plist": str(user_plist),
                          "note": "root 已 bootstrap；user agent 下次登录生效"}, ensure_ascii=False))
        return 0
    if action == "uninstall":
        if receipt is None:
            print(json.dumps({"result": "not_installed"}))
            return 0
        uid = os.geteuid()
        for key, path in receipt["paths"].items():
            expected_uid = 0 if key == "root_plist" else uid
            check_daemon_file(path, receipt["files"][key], expected_uid)
        with contextlib.suppress(DaemonError):
            DaemonIPCClient(SOCKET_PATH, timeout=1.5).stop_takeover()
        _bootout_user_agent()
        helper = _run_helper(["sudo", "--", sys.executable, str(Path(__file__).resolve()),
                              "uninstall-root"])
        if "error" in helper:
            print(json.dumps(helper), file=sys.stderr)
            return 1
        user_plist = Path(receipt["paths"]["user_plist"])
        if user_plist.exists() or user_plist.is_symlink():
            user_plist.unlink()
        manager.setting(root, "daemonReceipt", "")
        manager.setting(root, "daemonInstalled", "false")
        print(json.dumps({"result": "daemon_uninstalled"}))
        return 0
    if action == "start":
        helper = _run_helper(["sudo", "--", sys.executable, str(Path(__file__).resolve()),
                              "start-root"])
        print(json.dumps(helper, ensure_ascii=False))
        return 0 if "error" not in helper else 1
    if action == "stop":
        with contextlib.suppress(DaemonError):
            DaemonIPCClient(SOCKET_PATH, timeout=1.5).stop_takeover()
        helper = _run_helper(["sudo", "--", sys.executable, str(Path(__file__).resolve()),
                              "stop-root"])
        print(json.dumps(helper, ensure_ascii=False))
        return 0 if "error" not in helper else 1
    return 2


def _launchctl_ok(result):
    if result.returncode == 0:
        return True
    text = result.stderr or ""
    return any(token in text for token in ("already", "not loaded", "No such", "not found"))


def _root_control(action):
    """euid-0 helpers for start/stop without rewriting the plist.

    ``stop`` bootouts the job, so ``start`` cannot assume kickstart still has
    a loaded service. A reload after ``nmd update`` is stop && start: start
    bootstraps the installed plist when kickstart says it is not loaded.
    """
    if os.geteuid() != 0:
        raise DaemonError("root_required")
    if action == "stop":
        result = subprocess.run(["/bin/launchctl", "bootout", f"system/{LABEL}"],
                                capture_output=True, text=True)
        if not _launchctl_ok(result):
            raise DaemonError("launchctl_stop_failed")
        return {"result": "stop"}
    if action != "start":
        raise DaemonError("invalid_command")
    kick = subprocess.run(["/bin/launchctl", "kickstart", "-k", f"system/{LABEL}"],
                          capture_output=True, text=True)
    if kick.returncode == 0:
        return {"result": "start"}
    plist = ROOT_PLIST_DIR / f"{LABEL}.plist"
    if not plist.is_file() or plist.is_symlink():
        raise DaemonError("launchctl_start_failed")
    boot = subprocess.run(["/bin/launchctl", "bootstrap", "system", str(plist)],
                          capture_output=True, text=True)
    if not _launchctl_ok(boot):
        raise DaemonError("launchctl_start_failed")
    again = subprocess.run(["/bin/launchctl", "kickstart", "-k", f"system/{LABEL}"],
                           capture_output=True, text=True)
    if again.returncode != 0:
        raise DaemonError("launchctl_start_failed")
    return {"result": "start"}


def _bootout_user_agent():
    """Best-effort unload of the user LaunchAgent. Missing launchctl is fine."""
    try:
        subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"],
                       capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return


def cli_root_helper(argv):
    """Dispatch install-root/uninstall-root/start-root/stop-root (euid 0)."""
    if not argv or argv[0] not in ("install-root", "uninstall-root", "start-root", "stop-root"):
        print(json.dumps({"error": "invalid_command"}))
        return 1
    try:
        if argv[0] == "install-root":
            config_path = state_dir = None
            rest = argv[1:]
            index = 0
            while index < len(rest):
                if rest[index] == "--config" and index + 1 < len(rest):
                    config_path = rest[index + 1]
                elif rest[index] == "--state-dir" and index + 1 < len(rest):
                    state_dir = rest[index + 1]
                index += 2
            if config_path is None or state_dir is None:
                raise DaemonError("invalid_arguments")
            reply = install_root_plist(config_path, state_dir)
        elif argv[0] == "uninstall-root":
            reply = uninstall_root_plist()
        else:
            reply = _root_control(argv[0].replace("-root", ""))
    except DaemonError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(reply, ensure_ascii=False))
    return 0


# --- CLI ----------------------------------------------------------------------


def run_user_daemon(config, *, monitor_config_path=None):
    """Serve the dashboard in the main thread; supervise the collector beside it."""
    import nmd_monitor
    import observability
    takeover = config["takeover"]
    state_dir = Path(takeover["state_dir"] if takeover["state_dir"] is not None
                     else macos_prepare.default_state_dir())
    monitor_config = monitor_config_path or nmd_monitor.default_config_path()
    bridge = DaemonClientBridge(SOCKET_PATH)
    stopped = threading.Event()
    collector = UserDaemon(monitor_config_path=monitor_config, state_dir=state_dir,
                           stop_event=stopped)
    worker = threading.Thread(target=collector.run, daemon=True)
    worker.start()
    try:
        return observability.serve_dashboard(
            config["dashboard"]["port"], state_dir,
            config_path=monitor_config, daemon_client=bridge,
            collector_note="collector supervised by daemon")
    finally:
        stopped.set()
        worker.join(timeout=12)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in ([], ["help"], ["-h"], ["--help"]):
        stream = sys.stdout if argv else sys.stderr
        stream.write(HELP)
        return 0 if argv else 2
    if argv[0] in ("install-root", "uninstall-root", "start-root", "stop-root"):
        return cli_root_helper(argv)
    if argv[0] == "daemon":
        return cli_daemon(argv[1:])
    if argv[0] == "supervise":
        if os.geteuid() != 0:
            os.execvp("sudo", ["sudo", "--", sys.executable,
                               str(Path(__file__).resolve()), *argv])
        config_path, state_dir = _supervise_args(argv[1:])
        if config_path is None or state_dir is None:
            sys.stderr.write(HELP)
            return 2
        config = load_daemon_config(config_path)
        check_private_config(config_path)
        state_dir = Path(state_dir if config["takeover"]["state_dir"] is None
                         else config["takeover"]["state_dir"])
        # launchd does not set SUDO_USER, and sudo's HOME is /var/root.
        # The account that owns the config is the one whose geodata we copy.
        try:
            owner_uid = os.lstat(config_path).st_uid
        except OSError as exc:
            raise DaemonError("config_unreadable") from exc
        stopped = threading.Event()
        _install_signal_stop(stopped)
        RootSupervisor(config, state_dir,
                       geodata_dir=macos_takeover.geodata_dir_for_uid(owner_uid)).run(stopped)
        return 0
    if argv[0] == "run-user":
        config_path = None
        rest = argv[1:]
        if len(rest) == 2 and rest[0] == "--config":
            config_path = rest[1]
        elif rest:
            sys.stderr.write(HELP)
            return 2
        config = load_daemon_config(
            config_path if config_path is not None else default_daemon_config_path())
        run_user_daemon(config)
        return 0
    sys.stderr.write(HELP)
    return 2


def _install_signal_stop(stopped):
    import signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(ValueError):
            signal.signal(sig, lambda *_: stopped.set())


def _supervise_args(rest):
    config_path = state_dir = None
    index = 0
    while index < len(rest):
        if rest[index] == "--config" and index + 1 < len(rest):
            config_path = rest[index + 1]
            index += 2
        elif rest[index] == "--state-dir" and index + 1 < len(rest):
            state_dir = rest[index + 1]
            index += 2
        else:
            return None, None
    return config_path, state_dir


if __name__ == "__main__":
    raise SystemExit(main())
