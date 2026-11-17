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
"""

from __future__ import annotations

import contextlib
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
_EXIT_VALUE = re.compile(r"^[A-Za-z0-9:_./+-]{0,200}$")
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
pin. If that watchdog does not become ready, nothing is changed. STOP or the
absolute deadline rolls back through the existing rollback. The watchdog
still rolls back from that same pin if the controller is killed. It does not
install launchd, change on_boot, or stop an existing daemon. If the watchdog
process itself also dies, restore is not guaranteed.

`takeover` is the longer foreground session (default 10 minutes, 8 hours at
most, never renewed). `rollback` restores the pinned snapshot. --help and -h
print this text and do not escalate. System proxy and bypass are never changed.
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
    """``--exit-node`` or ``--exit-node=<token>``. Empty clears the node."""
    if item == "--exit-node":
        return True
    if not item.startswith("--exit-node="):
        return False
    return _EXIT_VALUE.fullmatch(item.split("=", 1)[1]) is not None


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


def restore_tailscale(prefs, tailscale_path, runner=None, mutator=None):
    """Idempotent restore from the snapshot prefs. Skips what already matches.

    If the snapshot could not read prefs at all, nothing is restored here:
    clearing whatever exit node happens to be set now would be a destructive
    guess, not a restore. A live prefs read that fails is reported and also
    changes nothing; the caller treats that as an incomplete rollback.
    """
    mutator = mutator or execute_mutating
    steps = []
    if not isinstance(prefs, dict) or prefs.get("status") != "observed":
        return ["prefs_unavailable_in_snapshot"]
    try:
        current = read_prefs(tailscale_path, runner=runner)
    except TakeoverError:
        return ["prefs_unreadable"]
    want_exit = prefs.get("ExitNodeID") or prefs.get("ExitNodeIP")
    have_exit = current.get("ExitNodeID") or current.get("ExitNodeIP")
    if want_exit != have_exit:
        argv = _exit_set_argv(tailscale_path, want_exit)
        if argv is None:
            steps.append("exit_node_unrestorable")
        else:
            mutator(argv)
            steps.append("exit_node_restored")
    elif want_exit:
        steps.append("exit_node_already_set")
    else:
        steps.append("exit_node_was_empty")
    want_dns = prefs.get("CorpDNS")
    if isinstance(want_dns, bool) and want_dns is not current.get("CorpDNS"):
        mutator([tailscale_path, "set",
                 "--accept-dns=true" if want_dns else "--accept-dns=false"])
        steps.append("accept_dns_restored")
    else:
        steps.append("accept_dns_unchanged")
    want_lan = prefs.get("ExitNodeAllowLANAccess")
    if isinstance(want_lan, bool) and want_lan is not current.get("ExitNodeAllowLANAccess"):
        mutator([tailscale_path, "set", _LAN_TRUE if want_lan else _LAN_FALSE])
        steps.append("allow_lan_restored")
    else:
        steps.append("allow_lan_unchanged")
    return steps


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
        steps.extend(restore_tailscale(snapshot["tailscale"]["prefs"], tailscale,
                                       runner=runner, mutator=mutator))
        steps.extend(restore_service_dns(snapshot["dns"]["services"],
                                         runner=runner, mutator=mutator))
    result = "rollback_incomplete" if _rollback_incomplete(steps) else "rollback_restored"
    return {"result": result, "steps": steps, "snapshot": chosen.name}


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


def _watchdog_still_running(state_dir):
    """True when a previous acceptance watchdog may still roll this directory back."""
    document = _read_ready_document(Path(state_dir) / READY_FILE)
    if not isinstance(document, dict) or document.get("ready") is not True:
        return False
    pid = document.get("pid")
    deadline = document.get("deadline_unix")
    if type(pid) is not int or isinstance(pid, bool) or type(deadline) is not int or isinstance(deadline, bool):
        return True
    # Deadline starts the restore. It does not mean the process has exited.
    return _pid_alive(pid) is not False


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


def run_rollback_watch(state_dir, *, pin, deadline_unix, parent_pid, now=None,
                       sleep=None, alive=None, rollback_fn=None):
    """Child entry: hold the pin, then call the existing rollback.

    Ready is written only after the pin and snapshot both load. The loop
    then waits for the deadline or for the controller process to disappear.
    This process dying too is not covered; the caller must not claim it is.
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
        result["guarantees_restore_if_watchdog_dies"] = False
    macos_prepare._atomic_private_write(
        state, WATCH_RESULT_FILE,
        json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n")
    return result


def arm_external_watchdog(state_dir, pin, deadline_unix, *, spawn=None, probe=None,
                          sleep=None, now=None):
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


def _spawn_watch(state_dir, pin, deadline_unix):
    python = _trusted_interpreter()
    script = _trusted_script(Path(__file__).resolve())
    argv = [str(python), str(script), "rollback-watch",
            "--state-dir", str(state_dir), "--pin", pin,
            "--deadline", str(int(deadline_unix)), "--parent", str(os.getpid())]
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    account = _sudo_user_home()
    if account is not None:
        env["SUDO_USER"] = account.pw_name
    log = open(Path(state_dir) / "rollback-watch.log", "ab")
    try:
        return subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True, env=env)
    finally:
        log.close()


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
             geodata_dir=None, external_rollback=False, geo_auto_update=True,
             arm_watchdog=None):
    """Drive one bounded run: preflight, cutover, watchdog, rollback, record.

    Every exit path after the cutover begins goes through the finally block:
    stop our process group, roll back from the snapshot taken before the
    cutover, and persist the run record. The absolute deadline is never renewed.
    """
    minutes = validate_minutes(minutes)
    runner = runner or macos_prepare.execute
    sleep = sleep or time.sleep
    now = now or time.monotonic
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
    if external_rollback and (snapshot_name is None
                              or ready.get("has_198_18") is not False
                              or ready.get("mihomo_running") is not False):
        unknown = (snapshot_name is None or ready.get("has_198_18") is None
                   or ready.get("mihomo_running") is None)
        record["result"] = "preflight_unknown" if unknown else "preflight_failed"
        record["preflight"] = {key: ready.get(key)
                               for key in ("has_198_18", "mihomo_running")}
        return record
    if ready.get("has_198_18") is True or ready.get("mihomo_running") is True:
        record["result"] = "preflight_failed"
        record["preflight"] = {key: ready.get(key)
                               for key in ("has_198_18", "mihomo_running")}
        return record
    write_pin(state_dir, snapshot_name)
    pin_holder[0] = snapshot_name
    step("snapshot_taken")
    deadline_unix = None
    if external_rollback:
        deadline_unix = int(time.time()) + minutes * 60
        record["guarantees_restore_if_watchdog_dies"] = False
        if arm_watchdog is None:
            armed = arm_external_watchdog(state_dir, snapshot_name, deadline_unix)
        else:
            armed = arm_watchdog(state_dir, snapshot_name, deadline_unix)
        record["watchdog"] = {key: armed.get(key)
                              for key in ("ready", "reason", "pid", "pgid", "pin")
                              if isinstance(armed, dict) and key in armed}
        if not isinstance(armed, dict) or armed.get("ready") is not True:
            record["result"] = "watchdog_not_ready"
            return record
        step("watchdog_ready")

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
            record["rollback"] = {"result": f"rollback_error:{type(exc).__name__}"}
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        macos_prepare._atomic_private_write(
            state_dir, f"takeover-{stamp}.json",
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")

    try:
        # 3. Cutover: clear the exit node, then start the only process we own.
        mutate([tailscale, "set", "--exit-node="])
        step("exit_node_cleared")
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

        deadline = now() + minutes * 60
        ready_by = now() + READY_TIMEOUT_SECONDS
        while now() < ready_by:
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
        # configured SOCKS port accepted a handshake.
        checks = _watch_checks(inputs, runner=runner, tcp=tcp, exists=exists)
        failures = 0
        while True:
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
            if now() >= deadline:
                record["result"] = "deadline_reached"
                return record
            sleep(CHECK_INTERVAL_SECONDS)
    except TakeoverError as exc:
        record["result"] = f"takeover_error:{exc}"
        return record
    finally:
        finish()



_COMMANDS = ("accept", "takeover", "rollback", "rollback-watch")
_FLAG_VALUES = {
    "accept": ("--inputs", "--profile", "--mihomo", "--state-dir", "--geodata-dir"),
    "takeover": ("--inputs", "--profile", "--minutes", "--mihomo", "--state-dir", "--geodata-dir"),
    "rollback": ("--state-dir",),
    "rollback-watch": ("--state-dir", "--pin", "--deadline", "--parent"),
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
    if argv[0] == "rollback-watch" and seen != set(allowed):
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
                      "guarantees_restore_if_watchdog_dies": False},
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
            print(json.dumps({"result": result["result"], "snapshot": result.get("snapshot")},
                             ensure_ascii=False))
            return 0 if result["result"] == "rollback_restored" else 1
        options, rest = _parse_takeover_args(argv[1:])
        if rest:
            sys.stderr.write(HELP)
            return 2
        record = _accept(options) if argv[0] == "accept" else takeover(**options)
    except TakeoverError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    rollback_result = (record.get("rollback") or {}).get("result")
    summary = {"result": record.get("result"), "rollback": rollback_result,
               "snapshot": record.get("snapshot")}
    if argv[0] == "accept":
        summary["guarantees_restore_if_watchdog_dies"] = False
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
