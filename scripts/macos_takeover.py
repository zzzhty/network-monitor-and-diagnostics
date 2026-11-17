"""Phase B controller: sudo foreground takeover with an absolute deadline.

This is the repository's first mutating macOS component, and every mutation
is enumerated here: ``tailscale set`` limited to --exit-node* / --accept-dns,
``networksetup -setdnsservers``, and starting (or ``-t`` validating) one
mihomo process we own. System proxy and bypass settings are never touched.
The controller runs in the foreground under an absolute deadline (default
10 minutes, at most 8 hours, never renewed); STOP or the deadline rolls the
machine back idempotently from the pre-start snapshot. Only the mihomo
process group this run spawned is ever signalled.

The rollback contract implemented here is the one recorded in
docs/macos-mihomo-tailscale.md: snapshot first, confirm scutil has no 198.18
after the native DNS cleanup, then restore the Tailscale exit node,
allow-lan/accept-dns, and per-service NIC DNS. Two restores racing in the
same second serialize on a lock file and the second one no-ops.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

import macos_coexist
import macos_prepare
import macos_readonly

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_MINUTES = 10
MIN_MINUTES = 1
MAX_MINUTES = 480  # 过夜最长 8 小时，到期不续期。
CHECK_INTERVAL_SECONDS = 20
CRITICAL_THRESHOLD = 3  # 连续 3 次关键故障才回退。
READY_TIMEOUT_SECONDS = 60
READY_POLL_SECONDS = 2
CLEANUP_TIMEOUT_SECONDS = 15
COMMAND_TIMEOUT = 10

MIHOMO_CANDIDATES = (
    "/usr/local/bin/mihomo",
    "/opt/homebrew/bin/mihomo",
    "/usr/local/sbin/mihomo",
)
_EXIT_FLAG = re.compile(r"^--exit-node(=.*)?$")
_LAN_FLAG = "--exit-node-allow-lan-access"
_DNS_FLAGS = ("--accept-dns=true", "--accept-dns=false")
_SETUP_SET = "-setdnsservers"
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/()\-]{0,63}$")
_IP_TOKEN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9A-Fa-f:]+$")

HELP = """\
usage: sudo python3 scripts/macos_takeover.py takeover --inputs INPUTS.json \
      [--profile PROFILE.json] [--minutes N] [--mihomo PATH] [--state-dir DIR]
       sudo python3 scripts/macos_takeover.py rollback [--state-dir DIR]

Foreground takeover of macOS egress with an absolute deadline (default
10 minutes, 8 hours at most, never renewed). STOP or the deadline rolls back
idempotently from the newest pre-start snapshot. Only the mihomo process
group this run spawned is signalled; system proxy and bypass are never
changed. Run it under sudo.
"""


class TakeoverError(Exception):
    """Stable error codes; never carries command output."""


# --- argv gates --------------------------------------------------------------


def mutating_allowlisted(argv, mihomo_path=None):
    """The closed set of mutations this controller may ever perform.

    ``mihomo_path`` extends the binary set with the one absolute path this
    run was explicitly given via --mihomo; nothing else widens the gate.
    """
    if not isinstance(argv, (list, tuple)) or not argv:
        return False
    argv = list(argv)
    if argv[0] in macos_readonly.TAILSCALE_CANDIDATES and argv[1:2] == ["set"]:
        rest = argv[2:]
        if not rest:
            return False
        for item in rest:
            if item == _LAN_FLAG or item in _DNS_FLAGS:
                continue
            if _EXIT_FLAG.match(item):
                continue
            return False
        return True
    if argv[0:2] == ["/usr/sbin/networksetup", _SETUP_SET]:
        rest = argv[2:]
        if len(rest) < 2 or not _SERVICE_NAME.fullmatch(rest[0]):
            return False
        for item in rest[1:]:
            if item == "Empty" or _IP_TOKEN.match(item):
                continue
            return False
        return True
    allowed_mihomo = MIHOMO_CANDIDATES + ((mihomo_path,) if mihomo_path else ())
    if argv[0] in allowed_mihomo:
        if argv[1:3] == ["-t", "-f"] and len(argv) == 4:
            return True
        # Self-contained working dir: geodata and config live next to each other.
        if argv[1:2] == ["-d"] and Path(argv[2]).is_absolute():
            rest = argv[3:]
            if rest[:1] == ["-f"] and len(argv) == 5:
                return True
            if rest[:2] == ["-t", "-f"] and len(argv) == 6:
                return True
        if argv[1:2] == ["-f"] and len(argv) == 3:
            return True
    return False


def execute_mutating(argv, timeout=COMMAND_TIMEOUT, mihomo_path=None):
    """One gated mutation through the shared bounded runner."""
    if not mutating_allowlisted(list(argv), mihomo_path):
        raise TakeoverError("mutation_not_allowlisted")
    code, data, error = macos_readonly.bounded_run(list(argv), timeout, 65536)
    if error:
        raise TakeoverError(error)
    if code != 0:
        raise TakeoverError("mutation_failed")
    return code


def read_state(argv, timeout=COMMAND_TIMEOUT, runner=None):
    """Read-only observation through the Phase A allowlist."""
    if runner is None:
        runner = macos_prepare.execute
    code, text, error = runner(list(argv), timeout)
    if error:
        raise TakeoverError(error)
    return code, text


def validate_minutes(value):
    if type(value) is not int or isinstance(value, bool) \
            or not MIN_MINUTES <= value <= MAX_MINUTES:
        raise TakeoverError("invalid_minutes")
    return value


# --- spawner -----------------------------------------------------------------


class MihomoProcess:
    """The one child we own; its process group is the only thing we signal."""

    def __init__(self, argv, log_path):
        self.argv = list(argv)
        self.log_path = log_path
        self._handle = None

    def start(self, spawner=None):
        if spawner is not None:
            self._handle = spawner(self.argv, self.log_path)
            return self
        log = open(self.log_path, "ab", 0)
        try:
            self._handle = subprocess.Popen(
                self.argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin", "LANG": "C", "LC_ALL": "C"},
                start_new_session=True)
        finally:
            log.close()
        return self

    @property
    def pid(self):
        return self._handle.pid if self._handle else None

    def alive(self):
        return self._handle is not None and self._handle.poll() is None

    def terminate_group(self):
        """SIGTERM the group we created, then SIGKILL the leftovers."""
        if self._handle is None:
            return
        if self.alive():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(self._handle.pid), signal.SIGTERM)
            with contextlib.suppress(Exception):
                self._handle.wait(timeout=5)
        if self.alive():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(self._handle.pid), signal.SIGKILL)
            with contextlib.suppress(Exception):
                self._handle.wait(timeout=5)


def first_mihomo(exists=None, override=None):
    if override is not None:
        path = Path(override)
        if not path.is_absolute():
            raise TakeoverError("invalid_mihomo_path")
        return str(path)
    if exists is None:
        def exists(path):  # noqa: E306
            return Path(path).is_file() and os.access(path, os.X_OK)
    for candidate in MIHOMO_CANDIDATES:
        if exists(candidate):
            return candidate
    raise TakeoverError("mihomo_missing")


def first_tailscale(exists=None):
    if exists is None:
        def exists(path):  # noqa: E306
            return Path(path).is_file() and os.access(path, os.X_OK)
    for candidate in macos_readonly.TAILSCALE_CANDIDATES:
        if exists(candidate):
            return candidate
    raise TakeoverError("tailscale_missing")


# --- rollback ----------------------------------------------------------------


class RollbackLock:
    """Serialize restores; the same-second double restore no-ops."""

    def __init__(self, state_dir):
        self.path = Path(state_dir) / "rollback.lock"

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "a+b")
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        return False


def scutil_has_no_198_18(runner=None, deadline_seconds=CLEANUP_TIMEOUT_SECONDS,
                         sleep=None, now=None):
    """Poll until the native DNS cleanup is confirmed, then report."""
    sleep = sleep or time.sleep
    now = now or time.monotonic
    stop_at = now() + deadline_seconds
    last = None
    while True:
        _, text = read_state(["/usr/sbin/scutil", "--dns"], runner=runner)
        parsed = macos_prepare._parse_scutil_dns(0, text, None)
        last = parsed["has_198_18"]
        if last is False:
            return True
        if now() >= stop_at:
            return False
        sleep(1)


def restore_tailscale(prefs, tailscale_path, runner=None, mutator=None):
    """Idempotent restore from the snapshot prefs. Skips what already matches.

    If the snapshot could not read prefs at all, nothing is restored here:
    clearing whatever exit node happens to be set now would be a destructive
    guess, not a restore.
    """
    mutator = mutator or execute_mutating
    steps = []
    if not isinstance(prefs, dict) or prefs.get("status") != "observed":
        return ["prefs_unavailable_in_snapshot"]
    current = read_prefs(tailscale_path, runner=runner)
    want_exit = prefs.get("ExitNodeID") or prefs.get("ExitNodeIP")
    have_exit = current.get("ExitNodeID") or current.get("ExitNodeIP")
    if want_exit != have_exit:
        mutator([tailscale_path, "set", f"--exit-node={want_exit or ''}"])
        steps.append("exit_node_restored")
    elif want_exit:
        steps.append("exit_node_already_set")
    else:
        steps.append("exit_node_was_empty")
    if prefs.get("CorpDNS") is not None and prefs.get("CorpDNS") != current.get("CorpDNS"):
        mutator([tailscale_path, "set",
                 "--accept-dns=true" if prefs["CorpDNS"] else "--accept-dns=false"])
        steps.append("accept_dns_restored")
    else:
        steps.append("accept_dns_unchanged")
    return steps


def restore_service_dns(services, runner=None, mutator=None):
    """Per-service NIC DNS. An empty snapshot list means Automatic."""
    mutator = mutator or execute_mutating
    steps = []
    for row in services:
        name = row.get("service")
        wanted = row.get("dnsservers")
        if not _SERVICE_NAME.fullmatch(str(name)) or not isinstance(wanted, list):
            continue
        code, text = read_state(
            ["/usr/sbin/networksetup", "-getdnsservers", name], runner=runner)
        current = macos_prepare._parse_dnsservers(text)
        if current is not None and current == wanted:
            steps.append(f"{name}:unchanged")
            continue
        argv = ["/usr/sbin/networksetup", _SETUP_SET, name] + (
            ["Empty"] if not wanted else list(wanted))
        mutator(argv)
        steps.append(f"{name}:restored")
    return steps


def read_prefs(tailscale_path, runner=None):
    _, text = read_state([tailscale_path, "debug", "prefs"], runner=runner)
    return macos_prepare._parse_prefs(0, text, None)


def rollback(state_dir, *, runner=None, mutator=None, sleep=None, now=None,
             tailscale_path=None):
    """Restore the machine from the newest pre-start snapshot. Idempotent."""
    state = Path(state_dir)
    snapshots = sorted(state.glob("pre-start-*.json"))
    if not snapshots:
        raise TakeoverError("no_snapshot")
    snapshot = json.loads(snapshots[-1].read_text(encoding="utf-8"))
    tailscale = tailscale_path or first_tailscale()
    with RollbackLock(state):
        steps = []
        clean = scutil_has_no_198_18(runner=runner, sleep=sleep, now=now)
        steps.append("scutil_198_18_clear" if clean else "scutil_198_18_leftover")
        if not clean:
            return {"result": "rollback_blocked_dirty_dns", "steps": steps,
                    "snapshot": snapshots[-1].name}
        steps.extend(restore_tailscale(snapshot["tailscale"]["prefs"], tailscale,
                                       runner=runner, mutator=mutator))
        steps.extend(restore_service_dns(snapshot["dns"]["services"],
                                         runner=runner, mutator=mutator))
    return {"result": "rollback_restored", "steps": steps,
            "snapshot": snapshots[-1].name}


# --- takeover ----------------------------------------------------------------


def _watch_checks(inputs, runner=None, tcp=None, exists=None):
    """Read-only health checks; a critical one failing thrice rolls back."""
    checks = []
    if runner is not None:
        checks.append(("tailscale_status", True,
                       lambda: _tailscale_ok(runner, exists)))
    if tcp is not None and inputs:
        host, port = inputs["server"], inputs["port"]
        def vps_tcp():
            outcome = tcp(host, port, 5)
            return outcome.get("status") == "ok"
        checks.append(("vps_socks_tcp", True, vps_tcp))
    return checks


def _tailscale_ok(runner, exists=None):
    path = first_tailscale(exists)
    _, text = read_state([path, "status", "--json"], runner=runner)
    view = macos_coexist.normalize_tailscale_status(text, returncode=0)
    return view["availability"] == "healthy"


def takeover(*, inputs, profile=None, minutes=DEFAULT_MINUTES,
             mihomo_path=None, state_dir=None, runner=None, mutator=None,
             spawner=None, tcp=None, exists=None, sleep=None, now=None):
    """Drive one bounded run: preflight, cutover, watchdog, rollback, record.

    Every exit path after the cutover begins goes through the finally block:
    stop our process group, roll back from the snapshot, and persist the run
    record — including the same-second double-restore idempotency lock.
    """
    minutes = validate_minutes(minutes)
    runner = runner or macos_prepare.execute
    sleep = sleep or time.sleep
    now = now or time.monotonic
    mihomo = first_mihomo(exists=exists, override=mihomo_path)
    if mutator is None:
        def mutator(argv):  # noqa: E306
            return execute_mutating(argv, mihomo_path=mihomo)
    state_dir = Path(state_dir if state_dir is not None
                     else macos_prepare.default_state_dir())
    record = {"schema_version": SCHEMA_VERSION, "kind": "macos_takeover_run",
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
              "minutes": minutes, "mutations": [], "steps": [],
              "config_real": not (inputs["server"] == macos_coexist.PLACEHOLDER_SOCKS_HOST)}

    def mutate(argv):
        mutator(argv)
        record["mutations"].append(list(argv))

    def step(name):
        record["steps"].append(name)

    # 1. Config generation + real-machine mihomo -t validation, before any change.
    text = macos_prepare.render_config(profile, inputs)
    config_dir = state_dir / "takeover"
    config_path = config_dir / "config.yaml"
    macos_prepare._create_private_parents(config_dir)
    macos_prepare._atomic_private_write(config_dir, "config.yaml", text.encode())
    step("config_written")
    try:
        mutator([mihomo, "-t", "-f", str(config_path)])
    except TakeoverError as exc:
        record["result"] = f"config_invalid:{exc}"
        return record
    step("mihomo_t_passed")

    # 2. Pre-start snapshot + preconditions.
    _, summary, snapshot_path = macos_prepare.collect_snapshot(
        "macos", state_dir, runner=runner, exists=exists)
    ready = summary if isinstance(summary, dict) else {}
    record["snapshot"] = str(snapshot_path) if snapshot_path else None
    if ready.get("has_198_18") is True or ready.get("mihomo_running") is True:
        record["result"] = "preflight_failed"
        record["preflight"] = {key: ready.get(key)
                               for key in ("has_198_18", "mihomo_running")}
        return record
    step("snapshot_taken")

    tailscale = first_tailscale(exists)
    stop_requested = []

    def request_stop(*_):
        if not stop_requested:
            stop_requested.append(time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()))

    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(ValueError):
            previous[sig] = signal.signal(sig, request_stop)

    process = MihomoProcess([mihomo, "-f", str(config_path)],
                            str(config_dir / "mihomo.log"))

    def finish():
        for sig, handler in previous.items():
            with contextlib.suppress(ValueError, TypeError):
                signal.signal(sig, handler)
        process.terminate_group()
        step("mihomo_stopped")
        try:
            record["rollback"] = rollback(state_dir, runner=runner, mutator=mutator,
                                          sleep=sleep, now=now, tailscale_path=tailscale)
        except Exception as exc:  # never lose the record to a rollback crash
            record["rollback"] = {"result": f"rollback_error:{type(exc).__name__}"}
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        macos_prepare._atomic_private_write(
            state_dir, f"takeover-{stamp}.json",
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")

    try:
        # 3. Cutover: clear the exit node, then start the only process we own.
        mutate([tailscale, "set", "--exit-node="])
        step("exit_node_cleared")
        process.start(spawner=spawner)
        step("mihomo_started")

        deadline = now() + minutes * 60
        ready_by = now() + READY_TIMEOUT_SECONDS
        while now() < ready_by:
            _, dns_text = read_state(["/usr/sbin/scutil", "--dns"], runner=runner)
            parsed = macos_prepare._parse_scutil_dns(0, dns_text, None)
            if parsed["has_198_18"] is True:
                break
            if not process.alive():
                record["result"] = "mihomo_exited_early"
                return record
            sleep(READY_POLL_SECONDS)
        else:
            record["result"] = "ready_timeout"
            return record
        step("native_dns_ready")

        # 4. Watchdog: absolute deadline, 3 consecutive failed cycles roll back.
        # A cycle counts as failed when any critical check fails; a cycle with
        # every check passing resets the streak, per the recorded contract.
        checks = _watch_checks(inputs, runner=runner, tcp=tcp, exists=exists)
        failures = 0
        heartbeat = state_dir / "watchdog-heartbeat"
        while True:
            heartbeat.write_text(time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()))
            cycle_failed = False
            for name, critical, check in checks:
                try:
                    ok = check()
                except TakeoverError:
                    ok = False
                if ok or not critical:
                    continue
                cycle_failed = True
                record["steps"].append(f"critical:{name}")
            if cycle_failed:
                failures += 1
                record["steps"].append(f"critical_cycles:{failures}")
                if failures >= CRITICAL_THRESHOLD:
                    record["result"] = "critical_failures"
                    return record
            else:
                failures = 0
            if stop_requested:
                record["result"] = "stopped"
                record["stopped_at"] = stop_requested[0]
                return record
            if now() >= deadline:
                record["result"] = "deadline_reached"
                return record
            sleep(CHECK_INTERVAL_SECONDS)
    except TakeoverError as exc:
        record["result"] = f"takeover_error:{exc}"
        return record
    finally:
        finish()



def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in ([], ["help"], ["-h"], ["--help"]):
        stream = sys.stdout if argv else sys.stderr
        stream.write(HELP)
        return 0 if argv else 2
    if argv[0] not in ("takeover", "rollback"):
        sys.stderr.write(HELP)
        return 2
    if os.geteuid() != 0:
        # 显式 sudo 前台：非 root 时把自己原样交还给 sudo 重跑。
        os.execvp("sudo", ["sudo", "--", sys.executable, str(Path(__file__).resolve()), *argv])
    try:
        if argv[0] == "rollback":
            state_dir = None
            rest = argv[1:]
            if len(rest) == 2 and rest[0] == "--state-dir":
                state_dir = rest[1]
            elif rest:
                sys.stderr.write(HELP)
                return 2
            result = rollback(state_dir if state_dir is not None
                              else macos_prepare.default_state_dir())
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["result"] == "rollback_restored" else 1
        options, rest = _parse_takeover_args(argv[1:])
        if rest:
            sys.stderr.write(HELP)
            return 2
        record = takeover(**options)
    except TakeoverError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps({"result": record.get("result"),
                      "rollback": record.get("rollback", {}).get("result"),
                      "snapshot": record.get("snapshot")}, ensure_ascii=False, indent=2))
    return 0 if record.get("result") in ("stopped", "deadline_reached") else 1


def _parse_takeover_args(rest):
    values = {"inputs": None, "profile": None, "minutes": DEFAULT_MINUTES,
              "mihomo_path": None, "state_dir": None}
    index = 0
    while index < len(rest):
        flag, value = rest[index], None
        if flag in ("--inputs", "--profile", "--minutes", "--mihomo", "--state-dir"):
            if index + 1 >= len(rest):
                raise TakeoverError("invalid_arguments")
            value = rest[index + 1]
            index += 2
        else:
            raise TakeoverError("invalid_arguments")
        if flag == "--inputs":
            values["inputs"] = macos_prepare._load_json(value)
        elif flag == "--profile":
            values["profile"] = macos_prepare._load_json(value)
        elif flag == "--minutes":
            if not re.fullmatch(r"\d+", value):
                raise TakeoverError("invalid_minutes")
            values["minutes"] = int(value)
        elif flag == "--mihomo":
            values["mihomo_path"] = value
        else:
            values["state_dir"] = value
    if values["inputs"] is None:
        raise TakeoverError("inputs_required")
    values["inputs"] = macos_prepare.validate_inputs(values["inputs"])
    return values, []


if __name__ == "__main__":
    raise SystemExit(main())
