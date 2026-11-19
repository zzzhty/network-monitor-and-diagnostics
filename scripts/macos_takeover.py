"""Phase B controller: sudo foreground takeover with an absolute deadline.

This is the repository's first mutating macOS component, and every mutation
is enumerated here: ``tailscale set`` limited to --exit-node* / --accept-dns
/ --exit-node-allow-lan-access, ``networksetup -setdnsservers``, and starting
(or ``-t`` validating) one mihomo process we own. System proxy and bypass
settings are never touched. mihomo is only allowed to read a config that
lives inside the absolute ``-d`` work directory staged for that run.

The controller runs in the foreground under an absolute deadline (default
10 minutes, at most 8 hours, never renewed); STOP or the deadline rolls the
machine back idempotently from the snapshot taken before the cutover. Only
the mihomo process group this run recorded is ever signalled, and only after
its start time and command line still match that record. A standalone
``rollback`` uses the pinned snapshot too, so a second process can unwind a
dead controller without scanning for arbitrary mihomo processes and without
deleting files already in the state directory.

The rollback contract implemented here is the one recorded in
docs/macos-mihomo-tailscale.md: snapshot first, stop our process, confirm
scutil has no 198.18 after the native DNS cleanup, then restore the Tailscale
exit node, allow-lan, accept-dns, and per-service NIC DNS. Two restores
racing in the same second serialize on a lock file; the second one sees the
restored values and does not mutate again.

``accept`` also arms a restore sentinel in its own process group before any
network change. If the deadline watchdog exits before a completed restore,
the sentinel calls this same rollback, including the rule that a StableNodeID
is never passed to ``tailscale set``. The sentinel is not launchd. If it dies
as well, nothing here restarts it, so ``guarantees_restore_if_watchdog_dies``
stays false.

Sleep shows up as wall time moving ahead of the monotonic clock. After that
gap an active takeover is re-read. A still-correct managed state continues;
a broken route, native DNS, exit node, or system-proxy drift restores the
pinned snapshot. System proxy settings are never written.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
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
ACCEPT_MINUTES = 2  # 短时验收固定 2 分钟，不续期，也不能拉长成常驻。
CHECK_INTERVAL_SECONDS = 20
WATCHDOG_HANDSHAKE_SECONDS = 5
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
_LAN_TRUE = "--exit-node-allow-lan-access=true"
_LAN_FALSE = "--exit-node-allow-lan-access=false"
_LAN_FLAGS = frozenset({_LAN_FLAG, _LAN_TRUE, _LAN_FALSE})
_DNS_FLAGS = ("--accept-dns=true", "--accept-dns=false")
_SETUP_SET = "-setdnsservers"
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/()\-]{0,63}$")
# IPv4, IPv6, or IPv6 with a zone id (fe80::1%en0). The zone is a short
# interface token; shell metacharacters stay rejected.
_IP_TOKEN = re.compile(
    r"^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9A-Fa-f:]+(?:%[A-Za-z][A-Za-z0-9]{0,15})?$")
_SNAPSHOT_NAME = re.compile(r"^pre-start-\d{8}T\d{6}Z\.json$")
OWNER_FILE = "owned-mihomo.json"
PIN_FILE = "rollback-pin.json"
ENGAGED_FILE = "rollback-engaged"
READY_FILE = "rollback-watch-ready.json"
WATCH_RESULT_FILE = "rollback-watch-result.json"
SENTINEL_READY_FILE = "rollback-sentinel-ready.json"
SENTINEL_RESULT_FILE = "rollback-sentinel-result.json"
# Long enough for the watchdog to finish scutil cleanup and the exit-node
# write. Past this, a still-silent watchdog is treated as stuck.
SENTINEL_GRACE_SECONDS = 45
# Same threshold the monitor uses for a sleep or clock jump. Wall time during
# Darwin sleep keeps moving; CLOCK_MONOTONIC does not.
SLEEP_GAP_SECONDS = 2.0
# Honest public claim. The sentinel covers watchdog death only while the
# sentinel itself is still alive. accept does not install a LaunchDaemon, so
# a dead sentinel is not restarted. Do not flip this to True.
GUARANTEES_RESTORE_IF_WATCHDOG_DIES = False
DAEMON_SOCKET = "/var/run/nmd-daemon.sock"
GEODATA_FILES = ("geoip.metadb", "geosite.dat", "Country.mmdb", "geoip.dat")
GEODATA_MAX_BYTES = 64 * 1024 * 1024

HELP = """\
usage: nmd macos accept --inputs INPUTS.json --state-dir DIR \
      [--profile PROFILE.json] [--mihomo PATH] [--geodata-dir DIR]
       nmd macos takeover --inputs INPUTS.json \
      [--profile PROFILE.json] [--minutes N] [--mihomo PATH] [--state-dir DIR] \
      [--geodata-dir DIR]
       nmd macos rollback [--state-dir DIR]

`accept` is the two-minute acceptance run. Before any network change it
starts an independent root process group that already holds the pre-change
pin, and a second independent restore sentinel. If either does not become
ready, nothing is changed. STOP or the absolute deadline rolls back through
the existing rollback. The watchdog still rolls back from that same pin if
the controller is killed. If the watchdog exits before that restore finishes,
the sentinel runs the same rollback. The sentinel is another process: if it
dies too, restore is not guaranteed, and
guarantees_restore_if_watchdog_dies stays false. accept does not install
launchd, change on_boot, or stop an existing daemon.

After sleep and wake, wall time is compared with the monotonic clock. A
correct managed state continues. A broken route, native DNS, exit node, or
a system-proxy drift restores the pinned snapshot. System proxy and bypass
are never written. The absolute deadline is wall time, so sleep does not
extend the session. CI does not perform a real Mac sleep.

`takeover` is the longer foreground session (default 10 minutes, 8 hours at
most, never renewed). `rollback` restores the pinned snapshot. On macOS,
`accept` and `takeover` run `nmd macos preflight --tier takeover` before sudo;
a fail or unknown result does not re-exec. --help and -h print this text and
do not escalate. System proxy and bypass are never changed.
"""


_SECRET_TEXT = re.compile(r"(?i)\b(?:tskey-[A-Za-z0-9_-]*|authkey-\S+)")


def sanitize_cli_detail(value):
    """One short line of CLI stderr. Credentials are not kept."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str) or not value.strip():
        return None
    line = value.replace("\x00", "").strip().splitlines()[0]
    line = "".join(ch if ch.isprintable() else " " for ch in line)
    line = _SECRET_TEXT.sub("[redacted]", line)
    line = re.sub(r"\s+", " ", line).strip()
    if len(line) > 180:
        line = line[:180]
    return line or None


class TakeoverError(Exception):
    """Stable error codes. ``detail`` is sanitized CLI text, never a secret."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.detail = sanitize_cli_detail(detail)


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
            if item in _LAN_FLAGS or item in _DNS_FLAGS:
                continue
            if _EXIT_FLAG.match(item) and _safe_exit_value(item):
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
    # Validation and launch share one work directory. The config file has to
    # be a direct child of that absolute -d path; a bare -f can read any file
    # mihomo is willing to open, which is not a closed set.
    if argv[0] in allowed_mihomo and argv[1:2] == ["-d"] and _config_inside_workdir(argv[2:3], argv[-2:]):
        middle = argv[3:-2]
        if middle in ([], ["-t"]) and argv[-2] == "-f":
            return True
    return False


def _safe_exit_value(item):
    """``--exit-node`` or ``--exit-node=<ip|label>``. Empty clears the node.

    A StableNodeID, a node key, and ``auto:any`` are not accepted here.
    ``auto:any`` would select some other exit instead of the pinned one.
    """
    if item == "--exit-node":
        return True
    if not item.startswith("--exit-node="):
        return False
    return macos_prepare.cli_exit_token_allowed(item.split("=", 1)[1])


def _config_inside_workdir(work_arg, flag_and_config):
    """True when ``-f`` names a direct child of the absolute ``-d`` directory."""
    if len(work_arg) != 1 or len(flag_and_config) != 2 or flag_and_config[0] != "-f":
        return False
    work, config = Path(work_arg[0]), Path(flag_and_config[1])
    if not work.is_absolute() or not config.is_absolute():
        return False
    if ".." in work.parts or ".." in config.parts:
        return False
    return config.parent == work and config.name not in ("", ".", "..")


def _mutation_run(argv, timeout):
    """Run one already-allowlisted mutation and keep a capped stderr line.

    ``bounded_run`` drops stderr. A failed ``tailscale set`` is otherwise
    only ``mutation_failed``, which is what the live rollback showed.
    """
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    try:
        proc = subprocess.Popen(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError:
        return None, "tool_missing", None
    except PermissionError:
        return None, "permission_denied", None
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return None, "permission_denied", None
        return None, "launch_error", None
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            proc.communicate(timeout=2)
        return None, "timeout", None
    detail = sanitize_cli_detail(err)
    if out is not None and len(out) > 65536:
        return None, "output_too_large", detail
    return proc.returncode, None, detail


def execute_mutating(argv, timeout=COMMAND_TIMEOUT, mihomo_path=None):
    """One gated mutation. Non-zero exits keep sanitized stderr on the error."""
    if not mutating_allowlisted(list(argv), mihomo_path):
        raise TakeoverError("mutation_not_allowlisted")
    code, error, detail = _mutation_run(list(argv), timeout)
    if error:
        raise TakeoverError(error, detail)
    if code != 0:
        raise TakeoverError("mutation_failed", detail)
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


def classify_power_gap(previous_wall, wall, previous_mono, mono, *,
                       threshold=SLEEP_GAP_SECONDS):
    """``wake`` when wall time jumped ahead of the monotonic clock.

    Darwin suspend stops ``CLOCK_MONOTONIC`` and leaves ``time.time`` moving,
    which is the gap a process can see once it runs again. A backward wall
    jump is ``clock_step`` and is not treated as a wake. ``None`` means the
    samples do not show either.
    """
    try:
        wall_delta = float(wall) - float(previous_wall)
        mono_delta = float(mono) - float(previous_mono)
    except (TypeError, ValueError):
        return None
    if mono_delta < 0:
        return None
    if wall_delta <= -float(threshold):
        return "clock_step"
    if wall_delta > 0 and wall_delta - mono_delta >= float(threshold):
        return "wake"
    return None


_PROXY_STATUSES = frozenset({"observed", "unavailable", "unknown"})
_PROXY_REASONS = frozenset({
    "command_failed", "read_failed", "invalid_proxy_output",
    "proxy_flags_unreadable", "timeout", "unavailable",
})


def proxy_enabled_map(proxy):
    """Protocol name to enabled flag from an observed proxy document.

    ``None`` means the document cannot be trusted: it is not a dict,
    ``protocols`` is not a dict, or any protocol row has no boolean
    ``enabled``. An empty dict means the read succeeded and named no
    protocol. A missing row is not stored as ``False``.
    """
    if not isinstance(proxy, dict):
        return None
    protocols = proxy.get("protocols")
    if not isinstance(protocols, dict):
        return None
    found = {}
    for name, row in protocols.items():
        if not isinstance(name, str) or not name or not isinstance(row, dict):
            return None
        enabled = row.get("enabled")
        if not isinstance(enabled, bool):
            return None
        found[name] = enabled
    return found


def proxy_enabled_names(mapping):
    """Sorted names that are on. ``None`` if the map itself is unusable."""
    if not isinstance(mapping, dict):
        return None
    names = []
    for name, enabled in mapping.items():
        if not isinstance(name, str) or not isinstance(enabled, bool):
            return None
        if enabled:
            names.append(name)
    names.sort()
    return names


def _proxy_token(value, allowed):
    if value is None:
        return None
    if isinstance(value, str) and value in allowed:
        return value
    return "unspecified"


def expected_proxy_from_snapshot(snapshot):
    """The pre-takeover proxy flags, or None when they were not observed.

    An observed document with no protocol rows is ``{}``. A document that
    says observed but has a protocol row without a boolean ``enabled`` is
    ``None``: that is not an empty disabled map.
    """
    if not isinstance(snapshot, dict):
        return None
    proxy = snapshot.get("proxy")
    if not isinstance(proxy, dict) or proxy.get("status") != "observed":
        return None
    return proxy_enabled_map(proxy)


def _snapshot_proxy_meta(snapshot):
    proxy = snapshot.get("proxy") if isinstance(snapshot, dict) else None
    if not isinstance(proxy, dict):
        return None, None
    return (_proxy_token(proxy.get("status"), _PROXY_STATUSES),
            _proxy_token(proxy.get("reason"), _PROXY_REASONS))


def _proxy_wake_evidence(expected, live, observed, expected_status, expected_reason):
    """Bool maps and status tokens only. No servers, ports, or bypass values."""
    observed = observed if isinstance(observed, dict) else {}
    return {
        "expected_status": _proxy_token(expected_status, _PROXY_STATUSES),
        "expected_reason": _proxy_token(expected_reason, _PROXY_REASONS),
        "expected_enabled": dict(expected) if isinstance(expected, dict) else None,
        "live_status": _proxy_token(observed.get("proxy_status"), _PROXY_STATUSES),
        "live_reason": _proxy_token(observed.get("proxy_reason"), _PROXY_REASONS),
        "live_enabled": dict(live) if isinstance(live, dict) else None,
    }


def wake_decision(*, woke, deadline_due, mihomo_alive, observed,
                  expected_proxy, require_native_dns=True,
                  expected_proxy_status=None, expected_proxy_reason=None):
    """Continue only when the managed takeover still matches the cutover.

    System proxy is compared and never written. Drift is a change in which
    protocols are enabled. After a successful read, a missing protocol and an
    explicit ``False`` are the same: nothing is on. A failed, non-dictionary,
    or flag-less read is ``proxy_unknown`` and still restores. An absolute
    deadline that has already passed is a rollback even when the state looks
    fine. ``require_native_dns`` is false while native DNS is still coming up.
    """
    if deadline_due:
        return {"action": "rollback", "reasons": ["deadline_reached"]}
    if not woke:
        return {"action": "continue", "reasons": []}
    reasons = []
    if mihomo_alive is not True:
        reasons.append("mihomo_not_alive")
    observed = observed if isinstance(observed, dict) else {}
    has_198_18 = observed.get("has_198_18")
    if has_198_18 is None:
        reasons.append("dns_unknown")
    elif require_native_dns and has_198_18 is not True:
        reasons.append("native_dns_missing")
    exit_cleared = observed.get("exit_cleared")
    if exit_cleared is None:
        reasons.append("exit_unknown")
    elif exit_cleared is not True:
        reasons.append("exit_node_not_cleared")
    default_route = observed.get("default_route_present")
    if default_route is None:
        reasons.append("route_unknown")
    elif default_route is not True:
        reasons.append("default_route_missing")
    live_proxy = observed.get("proxy_enabled")
    expected_names = proxy_enabled_names(expected_proxy)
    live_names = proxy_enabled_names(live_proxy)
    if expected_names is None or live_names is None:
        reasons.append("proxy_unknown")
    elif expected_names != live_names:
        reasons.append("proxy_drift")
    evidence = _proxy_wake_evidence(
        expected_proxy, live_proxy, observed, expected_proxy_status, expected_proxy_reason)
    if reasons:
        return {"action": "rollback", "reasons": reasons, "proxy": evidence}
    return {"action": "continue", "reasons": [], "proxy": evidence}


# --- path trust --------------------------------------------------------------

# macOS ships /tmp, /var and /etc as root-owned symlinks into /private.
# Any other symlink on a config or state path is an attacker-controlled
# redirect. The walk uses lstat and never Path.resolve().
_SYSTEM_ALIAS = {
    "/tmp": "/private/tmp",
    "/var": "/private/var",
    "/etc": "/private/etc",
}
_STICKY_TEMPS = frozenset({
    "/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp",
})
_LSTART = re.compile(
    r"^[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}$")
_PS_IDENTITY = re.compile(
    r"^([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4})\s+(\S.*\S|\S)\s*$")
_ACCOUNT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")


def _absolute_lexical(path):
    """Absolute path with ``..`` rejected. Symlinks stay as written."""
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    if ".." in path.parts or "." in path.parts[1:]:
        raise TakeoverError("unsafe_path_component")
    return path


def _trusted_system_alias(path, info):
    expected = _SYSTEM_ALIAS.get(path.as_posix())
    if expected is None or info.st_uid != 0:
        return False
    try:
        target = os.readlink(path)
    except OSError:
        return False
    return os.path.normpath("/" + target.lstrip("/")) == expected


def _ancestor_writable_ok(path, info):
    """Group/world write is allowed only on the four sticky temp directories."""
    mode = stat.S_IMODE(info.st_mode)
    if not mode & 0o022:
        return True
    if path.as_posix() not in _STICKY_TEMPS:
        return False
    return info.st_uid == 0 and bool(mode & stat.S_ISVTX)


def assert_private_ancestors(path):
    """Refuse a symlink or a replaceable parent above ``path``.

    Missing tail components are fine: the caller may still be about to
    create them. A leaf that exists must be a private directory or a
    private regular file. This does not close a swap that happens after
    the walk returns.
    """
    path = _absolute_lexical(path)
    try:
        root_info = os.lstat("/")
    except OSError as exc:
        raise TakeoverError("path_unusable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise TakeoverError("unsafe_path_component")
    if not _ancestor_writable_ok(Path("/"), root_info):
        raise TakeoverError("unsafe_path_parent")
    current = Path("/")
    parts = path.parts[1:]
    if not parts:
        raise TakeoverError("unsafe_path_component")
    for index, name in enumerate(parts):
        if name in ("", ".", ".."):
            raise TakeoverError("unsafe_path_component")
        current = current / name
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return path
        except OSError as exc:
            raise TakeoverError("path_unusable") from exc
        if stat.S_ISLNK(info.st_mode):
            if not _trusted_system_alias(current, info):
                raise TakeoverError("unsafe_path_symlink")
            continue
        last = index == len(parts) - 1
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            if last and mode & 0o022:
                raise TakeoverError("unsafe_path_parent")
            if not last and not _ancestor_writable_ok(current, info):
                raise TakeoverError("unsafe_path_parent")
            continue
        if last and stat.S_ISREG(info.st_mode):
            if mode & 0o022:
                raise TakeoverError("unsafe_path_parent")
            return path
        raise TakeoverError("unsafe_path_component")
    return path


def _private_directory(path):
    """A real directory with no group/world write, under trusted ancestors."""
    path = assert_private_ancestors(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise TakeoverError("invalid_geodata_dir") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise TakeoverError("invalid_geodata_dir")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise TakeoverError("invalid_geodata_dir")
    return path, info


def _safe_mihomo_config_dir(home, owner_uid):
    """``~/.config/mihomo`` only when that exact directory is privately owned."""
    home = Path(home)
    if not home.is_absolute() or ".." in home.parts:
        return None
    source = home / ".config" / "mihomo"
    try:
        path, info = _private_directory(source)
    except TakeoverError:
        return None
    if info.st_uid != owner_uid:
        return None
    return path


def _sudo_user_home():
    """Home from the account that invoked sudo, never from root's HOME."""
    import pwd
    name = os.environ.get("SUDO_USER", "")
    if not _ACCOUNT_NAME.fullmatch(name) or name == "root":
        return None
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        return None
    if account.pw_uid == 0:
        return None
    return account


def default_geodata_dir():
    """Geodata directory for this process, or None when that home is not safe.

    ``sudo`` on macOS sets HOME to ``/var/root``. Reading that directory
    makes a normal user's config look missing. A root foreground run uses
    ``SUDO_USER``'s home; without that account it stages nothing.
    """
    if os.geteuid() == 0:
        account = _sudo_user_home()
        if account is None:
            return None
        return _safe_mihomo_config_dir(account.pw_dir, account.pw_uid)
    return _safe_mihomo_config_dir(Path.home(), os.geteuid())


def geodata_dir_for_uid(uid):
    """Geodata for a non-root account. launchd has no SUDO_USER, so the
    daemon uses the config file's owner. uid 0 stages nothing.
    """
    import pwd
    if type(uid) is not int or isinstance(uid, bool) or uid <= 0:
        return None
    try:
        account = pwd.getpwuid(uid)
    except KeyError:
        return None
    if account.pw_uid == 0:
        return None
    return _safe_mihomo_config_dir(account.pw_dir, account.pw_uid)


def resolve_geodata_dir(override):
    """Explicit directory, or the safe default. An explicit unsafe path errors."""
    if override is None:
        return default_geodata_dir()
    path = Path(override)
    if not path.is_absolute():
        raise TakeoverError("invalid_geodata_dir")
    return _private_directory(path)[0]


# --- self-contained mihomo work dir ------------------------------------------


def ensure_workdir(path):
    """Create the mihomo work directory and refuse a symlink or a shared mode.

    ``mkdir`` on an existing path is a no-op, and ``exists()`` follows a
    symlink, so a work directory that is already a link would otherwise
    receive the config. Ancestors are checked before the create; the leaf
    is checked again after it.
    """
    path = assert_private_ancestors(path)
    macos_prepare._create_private_parents(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise TakeoverError("work_dir_unusable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise TakeoverError("work_dir_symlink")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise TakeoverError("work_dir_writable")
    return path


def config_is_direct_regular(work_dir, config_path):
    """True when ``-f`` is a regular file and a direct child of a real ``-d``."""
    work, config = Path(work_dir), Path(config_path)
    try:
        work_info = work.lstat()
        info = config.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(work_info.st_mode) or not stat.S_ISDIR(work_info.st_mode):
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False
    return config.parent == work and config.name not in ("", ".", "..")


def stage_geodata(target_dir, source_dir=None):
    """Copy regular geodata next to the config. Symlinks are never followed.

    ``source_dir is None`` stages nothing. Callers that want the account
    default pass ``resolve_geodata_dir(None)``; this function does not
    guess ``Path.home()``, because under sudo that is ``/var/root``.
    Missing files are reported. Nothing is downloaded here. A symlink already
    sitting in the work directory is removed rather than treated as staged,
    so a later ``mihomo -d`` cannot write through it. An unsafe source
    reports every file missing and copies nothing.
    """
    target_dir = Path(target_dir)
    if source_dir is None:
        return [], list(GEODATA_FILES)
    try:
        source_dir = _private_directory(source_dir)[0]
    except TakeoverError:
        return [], list(GEODATA_FILES)
    staged, missing = [], []
    for name in GEODATA_FILES:
        target = target_dir / name
        try:
            info = target.lstat()
        except FileNotFoundError:
            info = None
        except OSError:
            missing.append(name)
            continue
        if info is not None and stat.S_ISLNK(info.st_mode):
            with contextlib.suppress(OSError):
                target.unlink()
            info = None
        if info is not None and stat.S_ISREG(info.st_mode):
            staged.append(name)
            continue
        if info is not None:
            missing.append(name)
            continue
        source = source_dir / name
        try:
            src_info = source.lstat()
        except OSError:
            missing.append(name)
            continue
        if (stat.S_ISLNK(src_info.st_mode) or not stat.S_ISREG(src_info.st_mode)
                or src_info.st_size > GEODATA_MAX_BYTES):
            missing.append(name)
            continue
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(source, flags)
        except OSError:
            missing.append(name)
            continue
        try:
            data = os.read(fd, GEODATA_MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > GEODATA_MAX_BYTES:
            missing.append(name)
            continue
        macos_prepare._atomic_private_write(target_dir, name, data)
        staged.append(name)
    return staged, missing


def run_mihomo_validate(mihomo, config_path, work_dir, timeout=30):
    """Allowlisted ``mihomo -t`` with stderr kept. ``bounded_run`` drops it,
    and for validation the failure text is the whole point.

    Returns ``(ok, detail)`` and does not raise: a rejected argv is a failed
    validation, not a cutover.
    """
    argv = validate_argv(mihomo, work_dir, config_path)
    if not mutating_allowlisted(argv, mihomo_path=mihomo):
        return False, "mutation_not_allowlisted"
    if not config_is_direct_regular(work_dir, config_path):
        return False, "config_not_confined"
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False, "validate timeout"
    except OSError:
        return False, "mihomo not executable"
    tail = (result.stderr or result.stdout or "").strip()[-400:]
    return result.returncode == 0, tail


def validate_argv(mihomo, work_dir, config_path):
    """The only ``mihomo -t`` shape this controller will run."""
    return [mihomo, "-d", str(work_dir), "-t", "-f", str(config_path)]


def launch_argv(mihomo, work_dir, config_path):
    return [mihomo, "-d", str(work_dir), "-f", str(config_path)]


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
    """Poll until the native DNS cleanup is confirmed, then report.

    A single unreadable ``scutil`` is not a reason to abort the whole restore.
    It stays "not confirmed" until the deadline, and the caller then refuses
    to put the old exit node back on top of a resolver it could not check.
    """
    sleep = sleep or time.sleep
    now = now or time.monotonic
    stop_at = now() + deadline_seconds
    while True:
        try:
            _, text = read_state(["/usr/sbin/scutil", "--dns"], runner=runner)
        except TakeoverError:
            confirmed = None
        else:
            confirmed = macos_prepare._parse_scutil_dns(0, text, None)["has_198_18"]
        if confirmed is False:
            return True
        if now() >= stop_at:
            return False
        sleep(1)


def _exit_set_argv(tailscale_path, value):
    flag = f"--exit-node={value or ''}"
    if not _safe_exit_value(flag):
        return None
    return [tailscale_path, "set", flag]


def _read_status_document(tailscale_path, runner):
    try:
        code, text = read_state([tailscale_path, "status", "--json"], runner=runner)
    except TakeoverError:
        return None
    if code != 0 or not isinstance(text, str):
        return None
    try:
        document = json.loads(text)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def _choose_exit_token(prefs, tailscale_path, runner, status_document, exit_node_cli):
    """IP or MagicDNS label for the pinned exit. Never the StableNodeID."""
    exit_id, _exit_ip = macos_prepare.exit_identity(prefs)
    document = status_document
    if document is None:
        document = _read_status_document(tailscale_path, runner)
    token = macos_prepare.exit_node_cli_value(prefs, document)
    if token:
        return token
    if (isinstance(exit_node_cli, str)
            and macos_prepare.cli_exit_token_allowed(exit_node_cli)
            and exit_node_cli != exit_id):
        return exit_node_cli
    return None


def _apply_mutation(mutator, argv, steps, failures, ok_step, fail_step):
    try:
        mutator(argv)
    except TakeoverError as exc:
        steps.append(fail_step)
        failures.append({"step": fail_step, "error": str(exc), "detail": exc.detail})
    else:
        steps.append(ok_step)


def restore_tailscale(prefs, tailscale_path, runner=None, mutator=None, *,
                      status_document=None, exit_node_cli=None):
    """Idempotent restore from the snapshot prefs. Skips what already matches.

    If the snapshot could not read prefs at all, nothing is restored here:
    clearing whatever exit node happens to be set now would be a destructive
    guess, not a restore. A live prefs read that fails is reported and also
    changes nothing; the caller treats that as an incomplete rollback.

    The exit-node argument is an IP or a MagicDNS base name. One failed
    ``tailscale set`` does not skip accept-dns, allow-lan, or later NIC DNS.
    """
    mutator = mutator or execute_mutating
    steps = []
    failures = []
    if not isinstance(prefs, dict) or prefs.get("status") != "observed":
        return ["prefs_unavailable_in_snapshot"], failures
    try:
        current = read_prefs(tailscale_path, runner=runner)
    except TakeoverError as exc:
        return ["prefs_unreadable"], [{"step": "prefs", "error": str(exc), "detail": exc.detail}]
    if macos_prepare.exits_match(prefs, current):
        want_id, want_ip = macos_prepare.exit_identity(prefs)
        steps.append("exit_node_already_set" if want_id or want_ip else "exit_node_was_empty")
    else:
        want_id, want_ip = macos_prepare.exit_identity(prefs)
        if want_id is None and want_ip is None:
            argv = _exit_set_argv(tailscale_path, "")
        else:
            token = _choose_exit_token(
                prefs, tailscale_path, runner, status_document, exit_node_cli)
            argv = _exit_set_argv(tailscale_path, token) if token else None
        if argv is None:
            steps.append("exit_node_unrestorable")
        else:
            _apply_mutation(mutator, argv, steps, failures,
                            "exit_node_restored", "exit_node:failed")
    want_dns = prefs.get("CorpDNS")
    if isinstance(want_dns, bool) and want_dns is not current.get("CorpDNS"):
        _apply_mutation(
            mutator,
            [tailscale_path, "set", "--accept-dns=true" if want_dns else "--accept-dns=false"],
            steps, failures, "accept_dns_restored", "accept_dns:failed")
    else:
        steps.append("accept_dns_unchanged")
    want_lan = prefs.get("ExitNodeAllowLANAccess")
    if isinstance(want_lan, bool) and want_lan is not current.get("ExitNodeAllowLANAccess"):
        _apply_mutation(
            mutator, [tailscale_path, "set", _LAN_TRUE if want_lan else _LAN_FALSE],
            steps, failures, "allow_lan_restored", "allow_lan:failed")
    else:
        steps.append("allow_lan_unchanged")
    return steps, failures


def restore_service_dns(services, runner=None, mutator=None):
    """Per-service NIC DNS. An empty snapshot list means Automatic.

    One service failing does not skip the rest. The failed name is marked
    so the rollback stays incomplete and can be retried.
    """
    mutator = mutator or execute_mutating
    steps = []
    for row in services:
        name = row.get("service")
        wanted = row.get("dnsservers")
        if not _SERVICE_NAME.fullmatch(str(name)) or not isinstance(wanted, list):
            continue
        try:
            code, text = read_state(
                ["/usr/sbin/networksetup", "-getdnsservers", name], runner=runner)
        except TakeoverError:
            steps.append(f"{name}:failed")
            continue
        current = None if code != 0 else macos_prepare._parse_dnsservers(text)
        if current is not None and current == wanted:
            steps.append(f"{name}:unchanged")
            continue
        argv = ["/usr/sbin/networksetup", _SETUP_SET, name] + (
            ["Empty"] if not wanted else list(wanted))
        try:
            mutator(argv)
        except TakeoverError:
            steps.append(f"{name}:failed")
            continue
        steps.append(f"{name}:restored")
    return steps


def read_prefs(tailscale_path, runner=None):
    _, text = read_state([tailscale_path, "debug", "prefs"], runner=runner)
    return macos_prepare._parse_prefs(0, text, None)


def observe_takeover_state(runner, *, tailscale_path):
    """Read-only picture of the managed takeover. Nothing here is mutated.

    ``None`` fields mean the read could not be trusted. Callers fail closed
    on those instead of treating them as healthy.
    """
    has_198_18 = None
    try:
        code, text = read_state(["/usr/sbin/scutil", "--dns"], runner=runner)
    except TakeoverError:
        code, text = None, ""
    if code == 0:
        has_198_18 = macos_prepare._parse_scutil_dns(0, text, None).get("has_198_18")

    proxy_enabled = None
    proxy_status = "unavailable"
    proxy_reason = "read_failed"
    try:
        code, text = read_state(["/usr/sbin/scutil", "--proxy"], runner=runner)
    except TakeoverError:
        code = None
    else:
        if code != 0:
            proxy_reason = "command_failed"
        else:
            parsed = macos_prepare._parse_scutil_proxy(0, text, None)
            proxy_status = parsed.get("status") if isinstance(parsed.get("status"), str) else "unknown"
            proxy_reason = parsed.get("reason") if isinstance(parsed.get("reason"), str) else None
            if proxy_status == "observed":
                proxy_enabled = proxy_enabled_map(parsed)
                if proxy_enabled is None:
                    proxy_status = "unknown"
                    proxy_reason = "proxy_flags_unreadable"

    default_route_present = None
    try:
        code, text = read_state(
            ["/usr/sbin/netstat", "-rn", "-f", "inet"], runner=runner)
    except TakeoverError:
        code, text = None, ""
    if code == 0:
        routes = macos_prepare._parse_routes(code, text, None, 4)
        if routes.get("status") == "observed":
            default_route_present = bool(routes.get("default"))

    exit_cleared = None
    if tailscale_path:
        try:
            prefs = read_prefs(tailscale_path, runner=runner)
        except TakeoverError:
            prefs = None
        if isinstance(prefs, dict) and prefs.get("status") == "observed":
            exit_id, exit_ip = macos_prepare.exit_identity(prefs)
            exit_cleared = not exit_id and exit_ip is None
    return {"has_198_18": has_198_18, "exit_cleared": exit_cleared,
            "default_route_present": default_route_present,
            "proxy_enabled": proxy_enabled,
            "proxy_status": _proxy_token(proxy_status, _PROXY_STATUSES),
            "proxy_reason": _proxy_token(proxy_reason, _PROXY_REASONS)}


def assess_managed_takeover(state_dir, snapshot_name, *, runner, tailscale_path,
                            mihomo_alive, require_native_dns, deadline_due=False):
    """Wake decision from the pinned snapshot and a fresh read-only observation."""
    if deadline_due:
        return wake_decision(woke=True, deadline_due=True, mihomo_alive=mihomo_alive,
                             observed={}, expected_proxy=None,
                             require_native_dns=require_native_dns)
    try:
        snapshot = _load_snapshot(_select_snapshot(state_dir, snapshot_name))
    except TakeoverError:
        snapshot = None
    observed = observe_takeover_state(runner, tailscale_path=tailscale_path)
    if snapshot is None:
        reasons = ["snapshot_unreadable"]
        if observed.get("has_198_18") is None:
            reasons.append("dns_unknown")
        return {"action": "rollback", "reasons": reasons}
    expected_status, expected_reason = _snapshot_proxy_meta(snapshot)
    return wake_decision(
        woke=True, deadline_due=False, mihomo_alive=mihomo_alive,
        observed=observed, expected_proxy=expected_proxy_from_snapshot(snapshot),
        require_native_dns=require_native_dns,
        expected_proxy_status=expected_status, expected_proxy_reason=expected_reason)


def _read_regular(path, limit):
    """Read a regular file without following a final symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise TakeoverError("snapshot_unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise TakeoverError("snapshot_unreadable")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise TakeoverError("snapshot_unreadable")
    return data


def _regular_snapshots(state):
    try:
        entries = list(Path(state).iterdir())
    except OSError as exc:
        raise TakeoverError("no_snapshot") from exc
    found = []
    for path in entries:
        if not _SNAPSHOT_NAME.fullmatch(path.name):
            continue
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            continue
        found.append(path)
    return sorted(found, key=lambda item: item.name)


def _select_snapshot(state, snapshot_name):
    """The snapshot this cutover pinned, else the newest regular file.

    Symlinks are ignored. A newer file written after the exit node was
    cleared must not replace the pre-cutover values when the caller still
    knows which file those values are in.
    """
    found = _regular_snapshots(state)
    if snapshot_name is not None:
        if not isinstance(snapshot_name, str) or not _SNAPSHOT_NAME.fullmatch(snapshot_name):
            raise TakeoverError("invalid_snapshot_name")
        matches = [item for item in found if item.name == snapshot_name]
        if not matches:
            raise TakeoverError("snapshot_missing")
        return matches[0]
    if not found:
        raise TakeoverError("no_snapshot")
    return found[-1]


def _load_snapshot(path):
    try:
        document = json.loads(_read_regular(path, 1_048_576).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TakeoverError("snapshot_unreadable") from exc
    if not isinstance(document, dict):
        raise TakeoverError("snapshot_unreadable")
    tailscale = document.get("tailscale")
    dns = document.get("dns")
    if not isinstance(tailscale, dict) or not isinstance(dns, dict):
        raise TakeoverError("snapshot_unreadable")
    if not isinstance(dns.get("services"), list):
        raise TakeoverError("snapshot_unreadable")
    return document


def write_pin(state_dir, snapshot_name):
    """Remember which pre-start file the cutover must restore.

    Written before the exit node is cleared, so a later snapshot of the
    already-cleared machine cannot become the restore source.
    """
    if not isinstance(snapshot_name, str) or not _SNAPSHOT_NAME.fullmatch(snapshot_name):
        raise TakeoverError("invalid_snapshot_name")
    directory = Path(state_dir)
    if directory.is_symlink():
        raise TakeoverError("state_dir_symlink")
    payload = {"schema_version": SCHEMA_VERSION, "snapshot": snapshot_name}
    macos_prepare._create_private_parents(directory)
    macos_prepare._atomic_private_write(
        directory, PIN_FILE,
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode() + b"\n")


def read_pin(state_dir):
    """The pinned snapshot name, or None when this state dir never pinned one.

    A symlink or an unreadable pin is refused. Falling through to a newer
    file would restore whatever happened to be snapshotted after the cutover.
    """
    path = Path(state_dir) / PIN_FILE
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TakeoverError("pin_unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise TakeoverError("pin_untrusted")
    try:
        data = json.loads(_read_regular(path, 4096).decode("utf-8"))
    except (TakeoverError, UnicodeDecodeError, ValueError) as exc:
        raise TakeoverError("pin_untrusted") from exc
    name = data.get("snapshot") if isinstance(data, dict) else None
    if not isinstance(name, str) or not _SNAPSHOT_NAME.fullmatch(name):
        raise TakeoverError("pin_untrusted")
    return name


def _parse_ps_identity(text):
    """``lstart`` plus argv tokens from ``ps -o lstart=,args=`` under LC_ALL=C."""
    if not isinstance(text, str):
        return None
    line = text.strip().splitlines()
    if len(line) != 1:
        return None
    match = _PS_IDENTITY.fullmatch(line[0].strip())
    if match is None or not _LSTART.fullmatch(match.group(1)):
        return None
    tokens = match.group(2).split()
    if not tokens:
        return None
    return match.group(1), tokens


def _probe_process(pid, runner):
    """The live start time and argv, or None when ps cannot show that pid."""
    try:
        code, text = read_state(
            ["/bin/ps", "-p", str(pid), "-o", "lstart=,args="], runner=runner)
    except (TakeoverError, ValueError, OSError):
        return "unconfirmed"
    if code not in (0, 1):
        return "unconfirmed"
    parsed = _parse_ps_identity(text) if code == 0 else None
    if parsed is None:
        return None if not str(text or "").strip() else "unconfirmed"
    return parsed


def _command_matches(mihomo, work_dir, tokens):
    """True when argv0 is this mihomo and ``-d`` is exactly the work directory."""
    if not tokens or not isinstance(mihomo, str) or not isinstance(work_dir, str):
        return False
    if any(token != token.strip() or not token for token in (mihomo, work_dir)):
        return False
    argv0 = tokens[0]
    base = argv0.rsplit("/", 1)[-1]
    recorded = mihomo.rsplit("/", 1)[-1]
    if argv0 != mihomo and not (base == "mihomo" and recorded == "mihomo"):
        return False
    return any(tokens[index] == "-d" and tokens[index + 1] == work_dir
               for index in range(len(tokens) - 1))


def write_owner(state_dir, pid, mihomo, work_dir, *, runner=None):
    """Record the one process group rollback is allowed to signal.

    The pid alone is not an identity: it is stored together with the ps
    start time and the exact argv ps reported, and only when that argv is
    this mihomo and this work directory. A probe that misses the process
    still writes the file, without those fields, so a later rollback
    refuses to signal.
    """
    if type(pid) is not int or isinstance(pid, bool) or pid <= 1:
        return
    if not isinstance(mihomo, str) or not mihomo.startswith("/"):
        return
    if not isinstance(work_dir, str) or not work_dir.startswith("/") or ".." in Path(work_dir).parts:
        return
    payload = {"schema_version": SCHEMA_VERSION, "pid": pid, "mihomo": mihomo,
               "work_dir": work_dir,
               "started_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}
    probed = _probe_process(pid, runner)
    if isinstance(probed, tuple):
        lstart, tokens = probed
        if _command_matches(mihomo, work_dir, tokens):
            payload["lstart"] = lstart
            payload["args"] = " ".join(tokens)
    directory = Path(state_dir)
    macos_prepare._create_private_parents(directory)
    macos_prepare._atomic_private_write(
        directory, OWNER_FILE,
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode() + b"\n")


def _read_owner(state_dir):
    path = Path(state_dir) / OWNER_FILE
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return "untrusted"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return "untrusted"
    try:
        data = json.loads(_read_regular(path, 4096).decode("utf-8"))
    except (TakeoverError, UnicodeDecodeError, ValueError):
        return "untrusted"
    return data if isinstance(data, dict) else "untrusted"


def _owner_confirmed(owner):
    if not isinstance(owner, dict):
        return False
    lstart = owner.get("lstart")
    args = owner.get("args")
    work = owner.get("work_dir")
    mihomo = owner.get("mihomo")
    if not isinstance(lstart, str) or _LSTART.fullmatch(lstart) is None:
        return False
    if not isinstance(args, str) or not args or len(args) > 4096:
        return False
    if not isinstance(work, str) or not work.startswith("/"):
        return False
    if not isinstance(mihomo, str) or not mihomo.startswith("/"):
        return False
    return True


def stop_owned_mihomo(state_dir, runner=None):
    """Signal the recorded session leader only when the same process is still there.

    pid plus the comm name is not enough: a recycled pid can belong to
    another mihomo that is also a session leader. The start time and the
    full argv captured at launch both have to match, and ``-d`` has to be
    this run's work directory. A dead controller uses this to roll back.
    A mismatch does not signal. A pid that is already gone is
    ``owner_not_running`` and the restore continues.
    """
    owner = _read_owner(state_dir)
    if owner is None:
        return "no_owner"
    if owner == "untrusted":
        return "owner_untrusted"
    pid = owner.get("pid") if isinstance(owner, dict) else None
    if type(pid) is not int or isinstance(pid, bool) or pid <= 1:
        return "owner_invalid"
    if not _owner_confirmed(owner):
        return "owner_unconfirmed"
    probed = _probe_process(pid, runner)
    if probed == "unconfirmed":
        return "owner_unconfirmed"
    if probed is None:
        return "owner_not_running"
    lstart, tokens = probed
    if lstart != owner["lstart"] or " ".join(tokens) != owner["args"]:
        return "owner_identity_mismatch"
    if not _command_matches(owner["mihomo"], owner["work_dir"], tokens):
        return "owner_identity_mismatch"
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return "owner_not_running"
    if pgid != pid:
        return "owner_not_session_leader"
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGTERM)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)
    return "owner_signalled"


def _rollback_incomplete(steps):
    if "prefs_unreadable" in steps or "exit_node_unrestorable" in steps:
        return True
    return any(step.endswith(":failed") for step in steps)


def rollback(state_dir, *, runner=None, mutator=None, sleep=None, now=None,
             tailscale_path=None, snapshot_name=None):
    """Restore the machine from the pinned snapshot, or the newest regular one.

    The recorded mihomo is signalled first so native DNS can leave before
    the exit node is put back. Idempotent: a second call that finds the
    live values already match the snapshot does not mutate. Nothing in the
    state directory is deleted: the pinned snapshot, the pin, and any
    pre-existing file stay where they are.
    """
    state = _absolute_lexical(state_dir)
    if state.is_symlink():
        raise TakeoverError("state_dir_symlink")
    assert_private_ancestors(state)
    if snapshot_name is None:
        snapshot_name = read_pin(state)
    chosen = _select_snapshot(state, snapshot_name)
    snapshot = _load_snapshot(chosen)
    tailscale = tailscale_path or first_tailscale()
    with RollbackLock(state):
        _mark_engaged(state, chosen.name)
        steps = [stop_owned_mihomo(state, runner=runner)]
        clean = scutil_has_no_198_18(runner=runner, sleep=sleep, now=now)
        steps.append("scutil_198_18_clear" if clean else "scutil_198_18_leftover")
        if not clean:
            return {"result": "rollback_blocked_dirty_dns", "steps": steps,
                    "snapshot": chosen.name}
        tail = snapshot.get("tailscale") if isinstance(snapshot.get("tailscale"), dict) else {}
        restored, failures = restore_tailscale(
            tail.get("prefs"), tailscale, runner=runner, mutator=mutator,
            exit_node_cli=tail.get("exit_node_cli"))
        steps.extend(restored)
        dns = snapshot.get("dns") if isinstance(snapshot.get("dns"), dict) else {}
        steps.extend(restore_service_dns(dns.get("services") or [],
                                         runner=runner, mutator=mutator))
    result = "rollback_incomplete" if _rollback_incomplete(steps) else "rollback_restored"
    payload = {"result": result, "steps": steps, "snapshot": chosen.name}
    if failures:
        payload["failures"] = failures
    return payload


def _mark_engaged(state_dir, snapshot_name):
    """Remember that this pin is being restored, before any restore mutation."""
    macos_prepare._atomic_private_write(
        Path(state_dir), ENGAGED_FILE, (snapshot_name + "\n").encode("ascii"))


def _engaged_result(deadline_unix):
    """The shared deadline writing the marker is a normal end, not an error."""
    if deadline_unix is not None and int(time.time()) >= int(deadline_unix):
        return "deadline_reached"
    return "rollback_already_engaged"


def _mutation_blocked(state_dir, snapshot_name):
    """True when this run must not start or change anything else.

    A marker for this pin, or an unreadable marker, blocks. A marker that
    names an older snapshot does not block a later run in the same directory.
    """
    path = Path(state_dir) / ENGAGED_FILE
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return True
    try:
        text = _read_regular(path, 200).decode("utf-8").strip()
    except (TakeoverError, UnicodeDecodeError):
        return True
    if text == snapshot_name or not _SNAPSHOT_NAME.fullmatch(text):
        return True
    return False


def _production_state_paths():
    found = set()
    homes = [Path.home()]
    account = _sudo_user_home()
    if account is not None:
        homes.append(Path(account.pw_dir))
    for home in homes:
        try:
            found.add(_absolute_lexical(home / ".local/state/nmd-monitor").as_posix())
        except TakeoverError:
            continue
    return found


def assert_acceptance_state(path):
    """Private state for this run. The root 0700 production directory is refused."""
    path = assert_private_ancestors(Path(path))
    if path.as_posix() in _production_state_paths():
        raise TakeoverError("production_state_forbidden")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise TakeoverError("state_dir_unusable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise TakeoverError("state_dir_symlink")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise TakeoverError("state_dir_writable")
    allowed = {0, os.geteuid()}
    account = _sudo_user_home()
    if account is not None:
        allowed.add(account.pw_uid)
    if info.st_uid not in allowed:
        raise TakeoverError("state_owner_untrusted")
    return path


def _ready_process_running(state_dir, filename):
    """True when a ready file names a process that may still restore this directory."""
    document = _read_ready_document(Path(state_dir) / filename)
    if not isinstance(document, dict) or document.get("ready") is not True:
        return False
    pid = document.get("pid")
    deadline = document.get("deadline_unix")
    if type(pid) is not int or isinstance(pid, bool) or type(deadline) is not int or isinstance(deadline, bool):
        return True
    # Deadline starts the restore. It does not mean the process has exited.
    return _pid_alive(pid) is not False


def _watchdog_still_running(state_dir):
    """True when a previous acceptance watchdog may still roll this directory back."""
    return _ready_process_running(state_dir, READY_FILE)


def _sentinel_still_running(state_dir):
    """True when a previous restore sentinel may still roll this directory back."""
    return _ready_process_running(state_dir, SENTINEL_READY_FILE)


def _daemon_conflict(path=DAEMON_SOCKET):
    """True when the root supervisor socket is present or cannot be classified.

    Only ``supervise`` binds this path. A user collector and an unloaded
    system plist do not. Presence is enough. This does not connect, and it
    does not stop the existing run-user daemon.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def confirm_ready(document, *, expected_pin, expected_deadline, child_pid,
                  parent_pgid, probe):
    """The watchdog is ready only when every field is confirmed.

    A missing field, a mismatched pin, or a probe that cannot prove the
    child is an independent root process group is not ready.
    """
    if not isinstance(document, dict) or document.get("ready") is not True:
        return {"ready": False, "reason": "ready_unknown"}
    if document.get("pin") != expected_pin or document.get("deadline_unix") != expected_deadline:
        return {"ready": False, "reason": "ready_unknown"}
    if document.get("pid") != child_pid or document.get("euid") != 0:
        return {"ready": False, "reason": "ready_unknown"}
    pgid = document.get("pgid")
    if type(pgid) is not int or isinstance(pgid, bool) or pgid == parent_pgid:
        return {"ready": False, "reason": "not_independent"}
    try:
        probed = probe(child_pid)
    except (OSError, ValueError, TypeError):
        probed = None
    if not isinstance(probed, dict) or probed.get("alive") is not True:
        return {"ready": False, "reason": "ready_unknown"}
    if probed.get("pgid") != pgid or probed.get("uid") != 0:
        return {"ready": False, "reason": "ready_unknown"}
    return {"ready": True, "pid": child_pid, "pgid": pgid, "pin": expected_pin}


def _read_ready_document(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return {"ready": False}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return {"ready": False}
    try:
        data = json.loads(_read_regular(path, 4096).decode("utf-8"))
    except (TakeoverError, UnicodeDecodeError, ValueError):
        return {"ready": False}
    return data if isinstance(data, dict) else {"ready": False}


def _probe_child(pid):
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError:
        return {"alive": False}
    except OSError:
        return {"alive": None}
    return {"alive": True, "pgid": pgid, "uid": os.geteuid()}


def _stop_child(child):
    pid = getattr(child, "pid", None)
    if not isinstance(pid, int):
        return
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.kill(pid, signal.SIGTERM)
    wait = getattr(child, "wait", None)
    if wait is not None:
        with contextlib.suppress(Exception):
            wait(timeout=2)


def _pid_alive(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def _watch_result_restored(state_dir, *, pin, deadline_unix, watchdog_pid):
    """True only when this watchdog recorded a completed restore for this run.

    A reused state directory can still hold the previous run's
    ``rollback_restored``. That file is not this run: the pin, the absolute
    deadline, and the watchdog pid all have to match.
    """
    document = _read_ready_document(Path(state_dir) / WATCH_RESULT_FILE)
    if not isinstance(document, dict) or document.get("result") != "rollback_restored":
        return False
    if document.get("pin") != pin or type(deadline_unix) is not int:
        return False
    if document.get("deadline_unix") != deadline_unix or type(watchdog_pid) is not int:
        return False
    return document.get("pid") == watchdog_pid


def run_rollback_watch(state_dir, *, pin, deadline_unix, parent_pid, now=None,
                       sleep=None, alive=None, rollback_fn=None):
    """Child entry: hold the pin, then call the existing rollback.

    Ready is written only after the pin and snapshot both load. The loop
    then waits for the deadline or for the controller process to disappear.
    This process dying is the sentinel's job. The sentinel is another
    process, so this function still must not claim a hard guarantee.
    """
    state = assert_acceptance_state(state_dir)
    now = now or time.time
    sleep = sleep or time.sleep
    alive = alive or _pid_alive
    rollback_fn = rollback_fn or rollback
    reason = "pin_unreadable"
    ready = False
    try:
        loaded = read_pin(state)
        if loaded == pin:
            _load_snapshot(_select_snapshot(state, pin))
            ready = True
            reason = "ready"
        else:
            reason = "pin_mismatch"
    except TakeoverError:
        ready = False
    document = {"schema_version": SCHEMA_VERSION, "ready": ready, "reason": reason,
                "pid": os.getpid(), "pgid": os.getpgrp(), "euid": os.geteuid(),
                "pin": pin, "deadline_unix": deadline_unix, "parent_pid": parent_pid}
    macos_prepare._atomic_private_write(
        state, READY_FILE,
        json.dumps(document, sort_keys=True).encode("utf-8") + b"\n")
    if not ready:
        return {"ready": False, "reason": reason}
    trigger = "deadline"
    while now() < deadline_unix:
        if not alive(parent_pid):
            trigger = "parent_dead"
            break
        sleep(0.2)
    result = rollback_fn(state, snapshot_name=pin)
    if isinstance(result, dict):
        result = dict(result)
        result["trigger"] = trigger
        result["pin"] = pin
        result["deadline_unix"] = deadline_unix if type(deadline_unix) is int else None
        result["pid"] = os.getpid()
        result["guarantees_restore_if_watchdog_dies"] = GUARANTEES_RESTORE_IF_WATCHDOG_DIES
    macos_prepare._atomic_private_write(
        state, WATCH_RESULT_FILE,
        json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n")
    return result


def run_restore_sentinel(state_dir, *, pin, deadline_unix, watchdog_pid, parent_pid,
                         now=None, sleep=None, alive=None, rollback_fn=None):
    """If the watchdog exits before a completed restore, run that rollback.

    Ready is written only after the same pin and snapshot load. The loop does
    not restore while the watchdog is alive and the deadline grace remains.
    A recorded ``rollback_restored`` means this watchdog already finished this
    pin, deadline, and pid. A previous run's result file does not count, and
    this process does not mutate again when the current one does. Any earlier
    watchdog exit, or silence past the grace, uses the pinned snapshot and
    the existing rollback. Exit-node arguments therefore stay on the PR #8
    contract.

    This process dying too is not covered. The returned claim stays false.
    ``parent_pid`` is recorded so a later reader can see which controller
    armed the sentinel; the trigger is the watchdog, not the parent.
    """
    state = assert_acceptance_state(state_dir)
    now = now or time.time
    sleep = sleep or time.sleep
    alive = alive or _pid_alive
    rollback_fn = rollback_fn or rollback
    if type(watchdog_pid) is not int or isinstance(watchdog_pid, bool) or watchdog_pid <= 1:
        raise TakeoverError("invalid_arguments")
    reason = "pin_unreadable"
    ready = False
    try:
        loaded = read_pin(state)
        if loaded == pin:
            _load_snapshot(_select_snapshot(state, pin))
            ready = True
            reason = "ready"
        else:
            reason = "pin_mismatch"
    except TakeoverError:
        ready = False
    document = {"schema_version": SCHEMA_VERSION, "ready": ready, "reason": reason,
                "pid": os.getpid(), "pgid": os.getpgrp(), "euid": os.geteuid(),
                "pin": pin, "deadline_unix": deadline_unix,
                "watchdog_pid": watchdog_pid, "parent_pid": parent_pid,
                "guarantees_restore_if_watchdog_dies": GUARANTEES_RESTORE_IF_WATCHDOG_DIES}
    macos_prepare._atomic_private_write(
        state, SENTINEL_READY_FILE,
        json.dumps(document, sort_keys=True).encode("utf-8") + b"\n")
    if not ready:
        return {"ready": False, "reason": reason,
                "guarantees_restore_if_watchdog_dies": GUARANTEES_RESTORE_IF_WATCHDOG_DIES}
    trigger = None
    while trigger is None:
        if _watch_result_restored(
                state, pin=pin, deadline_unix=deadline_unix, watchdog_pid=watchdog_pid):
            trigger = "watchdog_restored"
            break
        if alive(watchdog_pid) is False:
            trigger = "watchdog_dead"
            break
        if now() >= int(deadline_unix) + SENTINEL_GRACE_SECONDS:
            trigger = "watchdog_stuck"
            break
        sleep(0.2)
    if trigger == "watchdog_restored":
        result = {"result": "rollback_restored", "steps": [], "trigger": trigger,
                  "pin": pin,
                  "deadline_unix": deadline_unix if type(deadline_unix) is int else None,
                  "pid": watchdog_pid,
                  "guarantees_restore_if_watchdog_dies": GUARANTEES_RESTORE_IF_WATCHDOG_DIES}
    else:
        result = rollback_fn(state, snapshot_name=pin)
        if not isinstance(result, dict):
            result = {"result": None}
        else:
            result = dict(result)
        result["trigger"] = trigger
        result["pin"] = pin
        result["deadline_unix"] = deadline_unix if type(deadline_unix) is int else None
        result["pid"] = watchdog_pid
        result["guarantees_restore_if_watchdog_dies"] = GUARANTEES_RESTORE_IF_WATCHDOG_DIES
    macos_prepare._atomic_private_write(
        state, SENTINEL_RESULT_FILE,
        json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n")
    return result


def _prepare_ready_file(path):
    """Remove a regular ready file. A symlink or an unusable inode is not ready."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False
    with contextlib.suppress(OSError):
        path.unlink()
    return True


def arm_external_watchdog(state_dir, pin, deadline_unix, *, spawn=None, probe=None,
                          sleep=None, now=None, spawn_sentinel=None):
    """Start the watchdog and accept it only after the ready file is confirmed."""
    state_dir = Path(state_dir)
    ready_path = state_dir / READY_FILE
    try:
        info = ready_path.lstat()
    except FileNotFoundError:
        info = None
    except OSError:
        return {"ready": False, "reason": "ready_unknown"}
    if info is not None and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
        return {"ready": False, "reason": "ready_unknown"}
    if info is not None:
        with contextlib.suppress(OSError):
            ready_path.unlink()
    # A reused directory still holds the previous run's success. Leaving it
    # makes the new sentinel exit before it is armed.
    for name in (WATCH_RESULT_FILE, SENTINEL_RESULT_FILE):
        if not _prepare_ready_file(state_dir / name):
            return {"ready": False, "reason": "ready_unknown"}
    child = spawn(state_dir, pin, deadline_unix) if spawn is not None else _spawn_watch(
        state_dir, pin, deadline_unix)
    if child is None or not isinstance(getattr(child, "pid", None), int):
        return {"ready": False, "reason": "watchdog_not_started"}
    sleep = sleep or time.sleep
    now = now or time.monotonic
    stop_at = now() + WATCHDOG_HANDSHAKE_SECONDS
    document = None
    while now() < stop_at:
        if child.poll() is not None:
            return {"ready": False, "reason": "watchdog_exited", "pid": child.pid}
        document = _read_ready_document(ready_path)
        if document is not None:
            break
        sleep(0.05)
    else:
        _stop_child(child)
        return {"ready": False, "reason": "watchdog_handshake_timeout", "pid": child.pid}
    confirmed = confirm_ready(
        document, expected_pin=pin, expected_deadline=deadline_unix,
        child_pid=child.pid, parent_pgid=os.getpgrp(), probe=probe or _probe_child)
    if confirmed.get("ready") is not True:
        _stop_child(child)
        return confirmed
    sentinel_path = state_dir / SENTINEL_READY_FILE
    if not _prepare_ready_file(sentinel_path):
        _stop_child(child)
        return {"ready": False, "reason": "ready_unknown"}
    if spawn_sentinel is not None:
        sentinel = spawn_sentinel(state_dir, pin, deadline_unix, child.pid)
    else:
        sentinel = _spawn_sentinel(state_dir, pin, deadline_unix, child.pid)
    if sentinel is None or not isinstance(getattr(sentinel, "pid", None), int):
        _stop_child(child)
        return {"ready": False, "reason": "sentinel_not_started"}
    stop_at = now() + WATCHDOG_HANDSHAKE_SECONDS
    document = None
    while now() < stop_at:
        if sentinel.poll() is not None:
            _stop_child(child)
            return {"ready": False, "reason": "sentinel_exited", "pid": sentinel.pid}
        document = _read_ready_document(sentinel_path)
        if document is not None:
            break
        sleep(0.05)
    else:
        _stop_child(sentinel)
        _stop_child(child)
        return {"ready": False, "reason": "sentinel_not_ready", "pid": sentinel.pid}
    sentinel_confirmed = confirm_ready(
        document, expected_pin=pin, expected_deadline=deadline_unix,
        child_pid=sentinel.pid, parent_pgid=os.getpgrp(), probe=probe or _probe_child)
    if sentinel_confirmed.get("ready") is not True:
        _stop_child(sentinel)
        _stop_child(child)
        sentinel_confirmed["ready"] = False
        return sentinel_confirmed
    confirmed["sentinel_ready"] = True
    confirmed["sentinel_pid"] = sentinel.pid
    confirmed["sentinel_pgid"] = sentinel_confirmed.get("pgid")
    confirmed["guarantees_restore_if_watchdog_dies"] = GUARANTEES_RESTORE_IF_WATCHDOG_DIES
    return confirmed


def _owner_allowed(uid):
    allowed = {0, os.geteuid()}
    account = _sudo_user_home()
    if account is not None:
        allowed.add(account.pw_uid)
    return uid in allowed


def _trusted_regular(path, *, root_only):
    """A regular file whose ancestors are safe. Symlinks are handled by the caller."""
    path = assert_private_ancestors(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise TakeoverError("untrusted_exec_path") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise TakeoverError("untrusted_exec_path")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise TakeoverError("untrusted_exec_path")
    if root_only:
        if info.st_uid != 0:
            raise TakeoverError("untrusted_exec_path")
    elif not _owner_allowed(info.st_uid):
        raise TakeoverError("untrusted_exec_path")
    return path


def _lexical_join(base, raw):
    """One symlink target, without touching the filesystem."""
    if raw.startswith("/"):
        parts = []
        for name in Path(raw).parts:
            if name in ("", ".", "/"):
                continue
            if name == "..":
                if not parts:
                    raise TakeoverError("untrusted_exec_path")
                parts.pop()
                continue
            parts.append(name)
        return Path("/" + "/".join(parts))
    current = Path(base)
    for name in Path(raw).parts:
        if name in ("", "."):
            continue
        if name == "..":
            if current == Path("/"):
                raise TakeoverError("untrusted_exec_path")
            current = current.parent
            continue
        current = current / name
    return current


def _trusted_interpreter():
    """The interpreter already running, or its one direct regular target."""
    path = Path(sys.executable)
    if not path.is_absolute():
        raise TakeoverError("untrusted_exec_path")
    try:
        info = path.lstat()
    except OSError as exc:
        raise TakeoverError("untrusted_exec_path") from exc
    if stat.S_ISLNK(info.st_mode):
        if info.st_uid not in (0, os.geteuid()):
            raise TakeoverError("untrusted_exec_path")
        try:
            raw = os.readlink(path)
        except OSError as exc:
            raise TakeoverError("untrusted_exec_path") from exc
        path = _lexical_join(path.parent, raw)
    return _trusted_regular(path, root_only=False)


def _trusted_script(path):
    return _trusted_regular(Path(path), root_only=False)


def _trusted_sudo():
    return _trusted_regular(Path("/usr/bin/sudo"), root_only=True)


def reexec_root(script_path, script_argv):
    """Replace this process with absolute sudo. PATH is not searched."""
    sudo = _trusted_sudo()
    python = _trusted_interpreter()
    script = _trusted_script(script_path)
    try:
        os.execv(str(sudo), [str(sudo), "--", str(python), str(script), *list(script_argv)])
    except OSError as exc:
        raise TakeoverError("untrusted_exec_path") from exc


def _child_env():
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    account = _sudo_user_home()
    if account is not None:
        env["SUDO_USER"] = account.pw_name
    return env


def _spawn_logged(argv, state_dir, log_name):
    log = open(Path(state_dir) / log_name, "ab")
    try:
        return subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True, env=_child_env())
    finally:
        log.close()


def _spawn_watch(state_dir, pin, deadline_unix):
    python = _trusted_interpreter()
    script = _trusted_script(Path(__file__).resolve())
    argv = [str(python), str(script), "rollback-watch",
            "--state-dir", str(state_dir), "--pin", pin,
            "--deadline", str(int(deadline_unix)), "--parent", str(os.getpid())]
    return _spawn_logged(argv, state_dir, "rollback-watch.log")


def _spawn_sentinel(state_dir, pin, deadline_unix, watchdog_pid):
    python = _trusted_interpreter()
    script = _trusted_script(Path(__file__).resolve())
    argv = [str(python), str(script), "rollback-sentinel",
            "--state-dir", str(state_dir), "--pin", pin,
            "--deadline", str(int(deadline_unix)),
            "--watchdog", str(int(watchdog_pid)), "--parent", str(os.getpid())]
    return _spawn_logged(argv, state_dir, "rollback-sentinel.log")


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


def _write_heartbeat(path):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    except OSError:
        return
    if info is not None and stat.S_ISLNK(info.st_mode):
        with contextlib.suppress(OSError):
            path.unlink()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()).encode()
    macos_prepare._atomic_private_write(path.parent, path.name, stamp)


def takeover(*, inputs, profile=None, minutes=DEFAULT_MINUTES,
             mihomo_path=None, state_dir=None, runner=None, mutator=None,
             spawner=None, tcp=None, exists=None, sleep=None, now=None,
             wall=None, geodata_dir=None, external_rollback=False,
             geo_auto_update=True, arm_watchdog=None):
    """Drive one bounded run: preflight, cutover, watchdog, rollback, record.

    Every exit path after the cutover begins goes through the finally block:
    stop our process group, roll back from the snapshot taken before the
    cutover, and persist the run record. The absolute deadline is never renewed.
    """
    minutes = validate_minutes(minutes)
    runner = runner or macos_prepare.execute
    sleep = sleep or time.sleep
    # Tests inject one clock through ``now``. Production deadlines use wall
    # time so a Darwin sleep, which stops the monotonic clock, cannot extend
    # the session. Wake detection compares the two clocks.
    injected_now = now is not None
    now = now or time.monotonic

    def wall_sample():
        if wall is not None:
            return wall()
        if injected_now:
            return now()
        return time.time()
    if tcp is None:
        tcp = macos_readonly.tcp_connect
    mihomo = first_mihomo(exists=exists, override=mihomo_path)
    injected_mutator = mutator is not None
    if mutator is None:
        def mutator(argv):  # noqa: E306
            return execute_mutating(argv, mihomo_path=mihomo)
    state_dir = Path(state_dir if state_dir is not None
                     else macos_prepare.default_state_dir())
    if external_rollback:
        state_dir = assert_acceptance_state(state_dir)
        if _daemon_conflict():
            raise TakeoverError("daemon_conflict")
        if _watchdog_still_running(state_dir):
            raise TakeoverError("watchdog_conflict")
        if _sentinel_still_running(state_dir):
            raise TakeoverError("sentinel_conflict")
    else:
        state_dir = _absolute_lexical(state_dir)
        if state_dir.is_symlink():
            raise TakeoverError("state_dir_symlink")
        assert_private_ancestors(state_dir)
    geodata_source = resolve_geodata_dir(geodata_dir)
    record = {"schema_version": SCHEMA_VERSION, "kind": "macos_takeover_run",
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
              "minutes": minutes, "mutations": [], "steps": [],
              "config_real": not (inputs["server"] == macos_coexist.PLACEHOLDER_SOCKS_HOST)}

    pin_holder = [None]

    def mutate(argv):
        if external_rollback:
            with RollbackLock(state_dir):
                if _mutation_blocked(state_dir, pin_holder[0]):
                    raise TakeoverError("rollback_already_engaged")
                mutator(argv)
        else:
            mutator(argv)
        record["mutations"].append(list(argv))

    def step(name):
        record["steps"].append(name)

    # 1. Config generation + self-contained mihomo -t, before any network change.
    text = macos_prepare.render_config(profile, inputs, geo_auto_update=geo_auto_update)
    config_dir = ensure_workdir(state_dir / "takeover")
    config_path = config_dir / "config.yaml"
    macos_prepare._atomic_private_write(config_dir, "config.yaml", text.encode())
    staged, missing = stage_geodata(config_dir, geodata_source)
    record["geodata_staged"] = staged
    record["geodata_missing"] = missing
    step("config_written")
    if not config_is_direct_regular(config_dir, config_path):
        record["result"] = "config_invalid"
        record["detail"] = "config_not_confined"
        return record
    check = validate_argv(mihomo, config_dir, config_path)
    if injected_mutator:
        try:
            mutator(check)
        except TakeoverError as exc:
            record["result"] = f"config_invalid:{exc}"
            return record
    else:
        ok, detail = run_mihomo_validate(mihomo, config_path, config_dir)
        if not ok:
            record["result"] = "config_invalid"
            record["detail"] = detail
            return record
    step("mihomo_t_passed")

    # 2. Pre-start snapshot + preconditions. This file is the restore source.
    _, summary, snapshot_path = macos_prepare.collect_snapshot(
        "macos", state_dir, runner=runner, exists=exists)
    ready = summary if isinstance(summary, dict) else {}
    record["snapshot"] = str(snapshot_path) if snapshot_path else None
    snapshot_name = Path(record["snapshot"]).name if record.get("snapshot") else None
    import macos_preflight
    conflict = macos_preflight.snapshot_conflict(
        ready, snapshot_name=snapshot_name, strict=bool(external_rollback))
    if conflict is not None:
        record["result"] = conflict["result"]
        record["preflight"] = conflict["preflight"]
        return record
    write_pin(state_dir, snapshot_name)
    pin_holder[0] = snapshot_name
    step("snapshot_taken")
    deadline_unix = None
    watchdog_pid = None
    if external_rollback:
        deadline_unix = int(time.time()) + minutes * 60
        record["guarantees_restore_if_watchdog_dies"] = GUARANTEES_RESTORE_IF_WATCHDOG_DIES
        record["restore_sentinel_armed"] = False
        if arm_watchdog is None:
            armed = arm_external_watchdog(state_dir, snapshot_name, deadline_unix)
        else:
            armed = arm_watchdog(state_dir, snapshot_name, deadline_unix)
        record["watchdog"] = {key: armed.get(key)
                              for key in ("ready", "reason", "pid", "pgid", "pin",
                                          "sentinel_pid", "sentinel_ready")
                              if isinstance(armed, dict) and key in armed}
        if not isinstance(armed, dict) or armed.get("ready") is not True:
            record["result"] = "watchdog_not_ready"
            return record
        watchdog_pid = armed.get("pid")
        record["restore_sentinel_armed"] = armed.get("sentinel_ready") is True
        step("watchdog_ready")
        if record["restore_sentinel_armed"]:
            step("sentinel_ready")

    tailscale = first_tailscale(exists)
    stop_requested = []

    def request_stop(*_):
        if not stop_requested:
            stop_requested.append(time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()))

    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(ValueError):
            previous[sig] = signal.signal(sig, request_stop)

    process = MihomoProcess(launch_argv(mihomo, config_dir, config_path),
                            str(config_dir / "mihomo.log"))

    def finish():
        for sig, handler in previous.items():
            with contextlib.suppress(ValueError, TypeError):
                signal.signal(sig, handler)
        process.terminate_group()
        step("mihomo_stopped")
        try:
            record["rollback"] = rollback(
                state_dir, runner=runner, mutator=mutator, sleep=sleep, now=now,
                tailscale_path=tailscale, snapshot_name=snapshot_name)
        except Exception as exc:  # never lose the record to a rollback crash
            record["rollback"] = {
                "result": f"rollback_error:{type(exc).__name__}",
                "error": str(exc) if isinstance(exc, TakeoverError) else type(exc).__name__,
            }
            detail = getattr(exc, "detail", None)
            if detail:
                record["rollback"]["detail"] = detail
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        macos_prepare._atomic_private_write(
            state_dir, f"takeover-{stamp}.json",
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")

    deadline_mark = [None]
    power_prev = [None]

    def watchdog_lost():
        if not external_rollback:
            return False
        if type(watchdog_pid) is not int or isinstance(watchdog_pid, bool):
            return False
        return _pid_alive(watchdog_pid) is False

    def note_power():
        sample = (wall_sample(), now())
        previous = power_prev[0]
        power_prev[0] = sample
        if previous is None:
            return None
        return classify_power_gap(previous[0], sample[0], previous[1], sample[1])

    def respond_to_power(require_native_dns):
        """Rollback when the watchdog is gone, the deadline has passed, or wake is wrong.

        The first sample only sets a baseline. A wake that still matches the
        managed takeover is recorded and the run continues.
        """
        gap = note_power()
        if watchdog_lost():
            record["result"] = "watchdog_died"
            return True
        if deadline_mark[0] is not None and wall_sample() >= deadline_mark[0]:
            record["result"] = "deadline_reached"
            return True
        if gap != "wake":
            return False
        decision = assess_managed_takeover(
            state_dir, snapshot_name, runner=runner, tailscale_path=tailscale,
            mihomo_alive=process.alive(), require_native_dns=require_native_dns)
        record["wake"] = decision
        if decision["action"] != "rollback":
            step("wake:continue")
            return False
        record["result"] = "wake_restore"
        step("wake:restore")
        return True

    try:
        # 3. Cutover: clear the exit node, then start the only process we own.
        mutate([tailscale, "set", "--exit-node="])
        step("exit_node_cleared")
        if watchdog_lost():
            record["result"] = "watchdog_died"
            return record
        if not config_is_direct_regular(config_dir, config_path):
            raise TakeoverError("config_not_confined")
        if external_rollback:
            with RollbackLock(state_dir):
                if _mutation_blocked(state_dir, snapshot_name):
                    raise TakeoverError("rollback_already_engaged")
                process.start(spawner=spawner)
                try:
                    write_owner(state_dir, process.pid, mihomo, str(config_dir), runner=runner)
                except Exception:
                    process.terminate_group()
                    raise
        else:
            process.start(spawner=spawner)
            write_owner(state_dir, process.pid, mihomo, str(config_dir), runner=runner)
        step("mihomo_started")

        ready_by = now() + READY_TIMEOUT_SECONDS
        ready_wall_by = wall_sample() + READY_TIMEOUT_SECONDS
        while now() < ready_by and wall_sample() < ready_wall_by:
            if respond_to_power(require_native_dns=False):
                return record
            if external_rollback and _mutation_blocked(state_dir, snapshot_name):
                record["result"] = _engaged_result(deadline_unix)
                return record
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
        # TCP connect success is not an application success; it only says the
        # configured SOCKS port accepted a handshake. The deadline is wall time
        # once this loop starts, so a sleep does not add time to the session.
        checks = _watch_checks(inputs, runner=runner, tcp=tcp, exists=exists)
        failures = 0
        deadline_mark[0] = wall_sample() + minutes * 60
        while True:
            if respond_to_power(require_native_dns=True):
                return record
            if external_rollback and _mutation_blocked(state_dir, snapshot_name):
                record["result"] = _engaged_result(deadline_unix)
                return record
            _write_heartbeat(state_dir / "watchdog-heartbeat")
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
            sleep(CHECK_INTERVAL_SECONDS)
    except TakeoverError as exc:
        record["result"] = f"takeover_error:{exc}"
        return record
    finally:
        finish()



_COMMANDS = ("accept", "takeover", "rollback", "rollback-watch", "rollback-sentinel")
_FLAG_VALUES = {
    "accept": ("--inputs", "--profile", "--mihomo", "--state-dir", "--geodata-dir"),
    "takeover": ("--inputs", "--profile", "--minutes", "--mihomo", "--state-dir", "--geodata-dir"),
    "rollback": ("--state-dir",),
    "rollback-watch": ("--state-dir", "--pin", "--deadline", "--parent"),
    "rollback-sentinel": ("--state-dir", "--pin", "--deadline", "--watchdog", "--parent"),
}


def _wants_help(argv):
    return any(arg in ("-h", "--help") for arg in argv)


def _syntax(argv):
    """Flag shape only. This does not read inputs and does not escalate."""
    if not argv or argv[0] not in _COMMANDS:
        raise TakeoverError("invalid_arguments")
    allowed = _FLAG_VALUES[argv[0]]
    seen = set()
    index = 1
    while index < len(argv):
        flag = argv[index]
        if flag not in allowed or index + 1 >= len(argv) or argv[index + 1].startswith("-"):
            raise TakeoverError("invalid_arguments")
        if flag in seen:
            raise TakeoverError("invalid_arguments")
        seen.add(flag)
        index += 2
    if argv[0] in ("accept", "takeover") and "--inputs" not in seen:
        raise TakeoverError("inputs_required")
    if argv[0] == "accept" and "--state-dir" not in seen:
        raise TakeoverError("state_dir_required")
    if argv[0] in ("rollback-watch", "rollback-sentinel") and seen != set(allowed):
        raise TakeoverError("invalid_arguments")
    return seen


def _load_trusted_json(value):
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    return macos_prepare._load_json(_trusted_regular(path, root_only=False))


def _accept(options):
    if options.get("profile") is None:
        options["profile"] = _load_trusted_json(
            REPO_ROOT / "examples/macos-mihomo-coexist.experiment.json")
    options["minutes"] = ACCEPT_MINUTES
    record = takeover(external_rollback=True, geo_auto_update=False, **{
        key: options[key] for key in (
            "inputs", "profile", "minutes", "mihomo_path", "state_dir", "geodata_dir")})
    return record


def _watch_cli(argv):
    values = {}
    index = 1
    while index < len(argv):
        values[argv[index]] = argv[index + 1]
        index += 2
    if not re.fullmatch(r"\d+", values["--deadline"]) or not re.fullmatch(r"\d+", values["--parent"]):
        raise TakeoverError("invalid_arguments")
    if not _SNAPSHOT_NAME.fullmatch(values["--pin"]):
        raise TakeoverError("invalid_snapshot_name")
    result = run_rollback_watch(
        values["--state-dir"], pin=values["--pin"],
        deadline_unix=int(values["--deadline"]), parent_pid=int(values["--parent"]))
    print(json.dumps({"result": result.get("result") if isinstance(result, dict) else None,
                      "trigger": result.get("trigger") if isinstance(result, dict) else None,
                      "guarantees_restore_if_watchdog_dies": GUARANTEES_RESTORE_IF_WATCHDOG_DIES},
                     ensure_ascii=False))
    return 0 if isinstance(result, dict) and result.get("result") == "rollback_restored" else 1


def _sentinel_cli(argv):
    values = {}
    index = 1
    while index < len(argv):
        values[argv[index]] = argv[index + 1]
        index += 2
    for flag in ("--deadline", "--parent", "--watchdog"):
        if not re.fullmatch(r"\d+", values[flag]):
            raise TakeoverError("invalid_arguments")
    if int(values["--watchdog"]) <= 1:
        raise TakeoverError("invalid_arguments")
    if not _SNAPSHOT_NAME.fullmatch(values["--pin"]):
        raise TakeoverError("invalid_snapshot_name")
    result = run_restore_sentinel(
        values["--state-dir"], pin=values["--pin"],
        deadline_unix=int(values["--deadline"]),
        watchdog_pid=int(values["--watchdog"]),
        parent_pid=int(values["--parent"]))
    print(json.dumps({"result": result.get("result") if isinstance(result, dict) else None,
                      "trigger": result.get("trigger") if isinstance(result, dict) else None,
                      "guarantees_restore_if_watchdog_dies": GUARANTEES_RESTORE_IF_WATCHDOG_DIES},
                     ensure_ascii=False))
    return 0 if isinstance(result, dict) and result.get("result") == "rollback_restored" else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv == ["help"] or _wants_help(argv):
        stream = sys.stdout if argv else sys.stderr
        stream.write(HELP)
        return 0 if argv else 2
    if argv[0] not in _COMMANDS:
        sys.stderr.write(HELP)
        return 2
    try:
        _syntax(argv)
    except TakeoverError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    if argv[0] in ("accept", "takeover"):
        # Read-only tier runs before sudo. A failure here does not re-exec.
        import macos_preflight
        if macos_preflight.host_is_darwin() and os.geteuid() != 0:
            try:
                options, rest = _parse_takeover_args(argv[1:])
            except TakeoverError as exc:
                print(json.dumps({"error": str(exc)}), file=sys.stderr)
                return 2
            if rest:
                sys.stderr.write(HELP)
                return 2
            report = macos_preflight.for_foreground(options)
            if report.get("blocking"):
                print(json.dumps(dict(report, refused_action=argv[0]),
                                 ensure_ascii=False, indent=2))
                return macos_preflight.exit_code(report)
    try:
        if os.geteuid() != 0:
            reexec_root(Path(__file__).resolve(), argv)
            return 2
        # Already root: still refuse an interpreter or script that fails the
        # same owner, mode, and ancestor checks. This does not search PATH.
        _trusted_interpreter()
        _trusted_script(Path(__file__).resolve())
    except TakeoverError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    try:
        if argv[0] == "rollback-watch":
            return _watch_cli(argv)
        if argv[0] == "rollback-sentinel":
            return _sentinel_cli(argv)
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
            payload = {"result": result["result"], "snapshot": result.get("snapshot")}
            if result.get("failures"):
                payload["failures"] = result["failures"]
            print(json.dumps(payload, ensure_ascii=False))
            return 0 if result["result"] == "rollback_restored" else 1
        options, rest = _parse_takeover_args(argv[1:])
        if rest:
            sys.stderr.write(HELP)
            return 2
        record = _accept(options) if argv[0] == "accept" else takeover(**options)
    except TakeoverError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    rollback_record = record.get("rollback") or {}
    rollback_result = rollback_record.get("result")
    summary = {"result": record.get("result"), "rollback": rollback_result,
               "snapshot": record.get("snapshot")}
    if rollback_record.get("failures"):
        summary["failures"] = rollback_record["failures"]
    if rollback_record.get("error"):
        summary["error"] = rollback_record["error"]
    if rollback_record.get("detail"):
        summary["detail"] = rollback_record["detail"]
    if argv[0] == "accept":
        summary["guarantees_restore_if_watchdog_dies"] = GUARANTEES_RESTORE_IF_WATCHDOG_DIES
        summary["restore_sentinel_armed"] = record.get("restore_sentinel_armed") is True
    print(json.dumps(summary, ensure_ascii=False))
    if argv[0] == "accept":
        return 0 if record.get("result") in ("stopped", "deadline_reached") and rollback_result == "rollback_restored" else 1
    return 0 if record.get("result") in ("stopped", "deadline_reached") else 1


def _parse_takeover_args(rest):
    values = {"inputs": None, "profile": None, "minutes": DEFAULT_MINUTES,
              "mihomo_path": None, "state_dir": None, "geodata_dir": None}
    index = 0
    while index < len(rest):
        flag, value = rest[index], None
        if flag in ("--inputs", "--profile", "--minutes", "--mihomo",
                    "--state-dir", "--geodata-dir"):
            if index + 1 >= len(rest):
                raise TakeoverError("invalid_arguments")
            value = rest[index + 1]
            index += 2
        else:
            raise TakeoverError("invalid_arguments")
        if flag == "--inputs":
            values["inputs"] = _load_trusted_json(value)
        elif flag == "--profile":
            values["profile"] = _load_trusted_json(value)
        elif flag == "--minutes":
            if not re.fullmatch(r"\d+", value):
                raise TakeoverError("invalid_minutes")
            values["minutes"] = int(value)
        elif flag == "--mihomo":
            values["mihomo_path"] = value
        elif flag == "--geodata-dir":
            values["geodata_dir"] = value
        else:
            values["state_dir"] = value
    if values["inputs"] is None:
        raise TakeoverError("inputs_required")
    values["inputs"] = macos_prepare.validate_inputs(values["inputs"])
    return values, []


if __name__ == "__main__":
    raise SystemExit(main())
