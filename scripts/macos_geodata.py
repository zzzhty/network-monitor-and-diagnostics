"""Download the geodata files the generated macOS config actually loads.

The bytes come from the same MetaCubeX ``meta-rules-dat`` release
``fetch-assets.sh`` already uses. Linux still runs that script and still
stores ``GeoSite.dat`` next to ``geoip.metadb``. This module is the macOS
preparation step: it writes ``geosite.dat`` and, when GEOIP rules need it,
``geoip.metadb``. It does not download ``geoip.dat``. Mihomo 1.19 leaves
``geodata-mode`` off unless the config says otherwise, and the generated
document never sets it, so GEOIP is resolved from the MMDB file
(``geoip.metadb``, or an existing ``Country.mmdb`` / ``geoip.db``).

Each download is checked against the ``.sha256sum`` published beside that
asset. Size is not treated as authenticity. ``fetch-assets.sh`` does not
verify those sidecars; its behavior is unchanged.

Nothing here runs from preflight, help, status, or the read-only panel.
``accept``, ``takeover``, and a daemon start/restart/takeover-start call
``prepare_for_foreground`` / ``prepare_for_daemon`` only when that command
is about to need the files, and only before sudo, stop, or start.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import macos_prepare
import macos_takeover

SCHEMA_VERSION = 1
ENSURE_COMMAND = "nmd macos geodata ensure"
GEOSITE_NAME = "geosite.dat"
GEOIP_NAME = "geoip.metadb"
GEOSITE_NAMES = ("geosite.dat", "GeoSite.dat")
# geodata-mode is unset on the generated document. mihomo 1.19 then uses
# MMDB(), which equal-folds these names. geoip.dat is a different format.
GEOIP_MMDB_NAMES = ("geoip.metadb", "Country.mmdb", "geoip.db")
GEOSITE_URL = (
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat")
GEOIP_URL = (
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb")
_RELEASE = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"
SOURCES = {
    GEOSITE_NAME: {"url": GEOSITE_URL, "checksum_url": _RELEASE + "geosite.dat.sha256sum",
                   "kind": "geosite"},
    GEOIP_NAME: {"url": GEOIP_URL, "checksum_url": _RELEASE + "geoip.metadb.sha256sum",
                 "kind": "mmdb"},
}
_ALLOWED_HOSTS = frozenset({
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
})
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 180
_RETRIES = 3
_MAX_REDIRECTS = 5
_CHECKSUM_MAX = 256
_RETRYABLE = frozenset({
    "timeout", "connection_failed", "http_unavailable", "truncated", "checksum_mismatch",
})
_SUM_LINE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9._-]+)\n?\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_]{1,40}\Z")
_MMDB_MARK = b"\xab\xcd\xefMaxMind.com"
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})

HELP = """\
usage: nmd macos geodata ensure [--geodata-dir DIR] [--inputs FILE] [--profile FILE]

Download geodata required by the generated rules when a valid file is not
already in the destination. GEOSITE uses geosite.dat. GEOIP uses the MMDB
file geoip.metadb; an existing Country.mmdb or geoip.db counts, and
geoip.dat is not downloaded. The destination is --geodata-dir, or
~/.config/mihomo for this account.

Does not sudo, stop, start, or change routes, DNS, proxy, or Tailscale.
nmd macos preflight, help, status, and the read-only panel do not download.
Run this, or accept / takeover / daemon start, as the account that owns the
files. Do not use sudo for this command.

Exit 0 when every needed file is present, 1 on failure, 2 on a usage error.
"""


class GeodataError(Exception):
    def __init__(self, reason):
        if not isinstance(reason, str) or _TOKEN.fullmatch(reason) is None:
            reason = "geodata_failed"
        super().__init__(reason)
        self.reason = reason


class _StopRedirect(urllib.request.HTTPRedirectHandler):
    """Surface the redirect to ``fetch_https`` instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


_OPENER = urllib.request.build_opener(_StopRedirect)


def ensure_command(geodata_dir=None):
    """The command preflight prints. A custom directory is quoted for the shell."""
    command = ENSURE_COMMAND
    if geodata_dir:
        command += " --geodata-dir " + shlex.quote(str(geodata_dir))
    return command


def geodata_remediation(geodata_dir=None):
    return (
        "运行 " + ensure_command(geodata_dir) + " 下载缺少的文件。"
        "GEOSITE 要 geosite.dat（GeoSite.dat 同样认）。"
        "生成配置不写 geodata-mode，GEOIP 用 MMDB：geoip.metadb；"
        "已经有的 Country.mmdb 或 geoip.db 也算，不下载 geoip.dat。"
        "只读预检、help、status 和面板不会下载。")


def valid_geosite(data):
    """True for a geosite payload, not an error page. Not a trust decision."""
    if not isinstance(data, (bytes, bytearray)):
        return False
    if len(data) < 32 or len(data) > macos_takeover.GEODATA_MAX_BYTES:
        return False
    if _looks_like_error(data):
        return False
    return data[0] == 0x0A


def valid_mmdb(data):
    """True when the MaxMind metadata marker is present. Size alone is not enough."""
    if not isinstance(data, (bytes, bytearray)):
        return False
    if len(data) < 128 or len(data) > macos_takeover.GEODATA_MAX_BYTES:
        return False
    if _looks_like_error(data):
        return False
    window = data[-131072:] if len(data) > 131072 else data
    return _MMDB_MARK in window


def valid_payload(kind, data):
    if kind == "geosite":
        return valid_geosite(data)
    if kind == "mmdb":
        return valid_mmdb(data)
    return False


def parse_sha256sum(body, filename):
    """Publisher sidecar: 64 hex digits, two spaces, the asset name."""
    if not isinstance(body, (bytes, bytearray)) or not body or len(body) > _CHECKSUM_MAX:
        raise GeodataError("checksum_rejected")
    if _looks_like_error(body):
        raise GeodataError("checksum_rejected")
    match = _SUM_LINE.fullmatch(body)
    if match is None or match.group(2).decode("ascii") != filename:
        raise GeodataError("checksum_rejected")
    return match.group(1).decode("ascii")


def fetch_verified(name, *, transport=None):
    """Return bytes that match the sidecar and the expected format."""
    spec = SOURCES[name]
    last = None
    for _attempt in range(_RETRIES):
        try:
            raw = _transfer(spec["checksum_url"], max_bytes=_CHECKSUM_MAX, transport=transport)
            digest = parse_sha256sum(raw, name)
            data = _transfer(spec["url"], max_bytes=macos_takeover.GEODATA_MAX_BYTES,
                             transport=transport)
            if hashlib.sha256(data).hexdigest() != digest:
                raise GeodataError("checksum_mismatch")
            if not valid_payload(spec["kind"], data):
                raise GeodataError("format_rejected")
            return data
        except GeodataError as exc:
            last = exc
            if exc.reason not in _RETRYABLE:
                raise
    raise last


def fetch_https(url, *, max_bytes, connect_timeout=_CONNECT_TIMEOUT,
                read_timeout=_READ_TIMEOUT, opener=None):
    """One HTTPS GET. Redirects stay on the release hosts. Bodies are capped."""
    current = url
    opener = opener or _OPENER
    for _redirect in range(_MAX_REDIRECTS + 1):
        _check_url(current)
        request = urllib.request.Request(current, headers={"User-Agent": "nmd-geodata"},
                                          method="GET")
        try:
            response = opener.open(request, timeout=connect_timeout)
        except GeodataError:
            raise
        except urllib.error.HTTPError as exc:
            response = exc
        except (TimeoutError, socket.timeout):
            raise GeodataError("timeout") from None
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, (TimeoutError, socket.timeout)):
                raise GeodataError("timeout") from None
            raise GeodataError("connection_failed") from None
        except OSError:
            raise GeodataError("connection_failed") from None
        try:
            status = getattr(response, "status", None) or response.getcode()
            headers = response.headers
            if status in (301, 302, 303, 307, 308):
                location = headers.get("Location") if headers is not None else None
                if not location:
                    raise GeodataError("redirect_rejected")
                current = urllib.parse.urljoin(current, location)
                continue
            if status in (429, 502, 503, 504):
                raise GeodataError("http_unavailable")
            if status != 200:
                raise GeodataError("http_rejected")
            return _read_limited(response, max_bytes, read_timeout)
        finally:
            with contextlib.suppress(Exception):
                response.close()
    raise GeodataError("redirect_rejected")


def ensure_into(directory, *, needs_site, needs_ip, transport=None, create=False):
    """Install only missing required files. Existing valid files are not replaced."""
    needed = _needed(needs_site, needs_ip)
    if os.geteuid() == 0:
        return _result(False, "root_refused", directory=None, needed=needed)
    if not needed:
        return _result(True, None, directory=None, needed=[])
    try:
        directory = _open_destination(directory, create=create)
        with _directory_lock(directory):
            present, pending, problem = _plan(directory, needed)
            if problem:
                return _result(False, problem, directory=directory, needed=needed,
                               present=present)
            downloaded = []
            for canonical, target in pending:
                try:
                    payload = fetch_verified(canonical, transport=transport)
                    _promote(directory, target, payload)
                except GeodataError as exc:
                    return _result(False, exc.reason, directory=directory, needed=needed,
                                   present=present, downloaded=downloaded)
                downloaded.append(canonical)
                present.append(canonical)
    except GeodataError as exc:
        return _result(False, exc.reason, directory=None, needed=needed)
    return _result(True, None, directory=directory, needed=needed,
                   present=present, downloaded=downloaded)


def prepare_for_foreground(options, *, transport=None):
    """User-level ensure before accept/takeover re-exec. No sudo."""
    import macos_preflight
    if not macos_preflight.host_is_darwin():
        return _result(True, None, directory=None, needed=[], skipped=True)
    if os.geteuid() == 0:
        return _result(False, "root_refused", directory=None, needed=[])
    options = options or {}
    document = macos_preflight.inspect_document(options.get("profile"), options.get("inputs"))
    if document.get("status") != "pass":
        reason = document.get("reason") if isinstance(document.get("reason"), str) else "invalid_config"
        return _result(False, reason, directory=None, needed=[])
    override = options.get("geodata_dir")
    if override:
        path = Path(override)
        if not path.is_absolute():
            return _result(False, "invalid_geodata_dir", directory=None, needed=[])
        create = not path.exists() and not path.is_symlink()
        directory = path
    else:
        directory, create = _default_destination()
    return ensure_into(
        directory, needs_site=bool(document.get("needs_site")),
        needs_ip=bool(document.get("needs_ip")), transport=transport, create=create)


def prepare_for_daemon(action, *, transport=None):
    """Ensure before daemon start/restart/takeover-start. Does not stop or sudo."""
    import macos_preflight
    if not macos_preflight.host_is_darwin():
        return _result(True, None, directory=None, needed=[], skipped=True)
    if action not in ("start", "restart", "takeover-start"):
        return _result(True, None, directory=None, needed=[], skipped=True)
    if os.geteuid() == 0:
        return _result(False, "root_refused", directory=None, needed=[])
    if not _daemon_wants_geodata(action):
        return _result(True, None, directory=None, needed=[], skipped=True)
    needs_site, needs_ip, problem = _installed_needs()
    if problem:
        return _result(False, problem, directory=None, needed=[])
    directory, create = _default_destination()
    return ensure_into(directory, needs_site=needs_site, needs_ip=needs_ip,
                       transport=transport, create=create)


def main(argv=None):
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(item in ("-h", "--help") for item in argv) or argv == ["help"]:
        sys.stdout.write(HELP)
        return 0 if argv else 2
    if not argv or argv[0] != "ensure":
        sys.stderr.write(HELP)
        return 2
    try:
        options = _parse_ensure(argv[1:])
    except (GeodataError, ValueError, OSError, macos_takeover.TakeoverError) as exc:
        sys.stderr.write(HELP)
        reason = exc.reason if isinstance(exc, GeodataError) else _token(str(exc), "invalid_arguments")
        print(_dumps({"schema_version": SCHEMA_VERSION, "kind": "macos_geodata_ensure",
                      "ok": False, "result": "fail", "reason": reason}),
              file=sys.stderr)
        return 2
    import macos_preflight
    if not macos_preflight.host_is_darwin():
        print(_dumps(_result(True, None, directory=None, needed=[],
                             result="not_applicable")))
        return 0
    if options["from_config"]:
        needs_site, needs_ip, problem = _installed_needs()
        if problem:
            body = _result(False, problem, directory=None, needed=[])
            print(_dumps(body))
            return 1
        directory, create = _default_destination()
        explicit = None
    else:
        import macos_preflight as preflight
        document = preflight.inspect_document(options["profile"], options["inputs"])
        if document.get("status") != "pass":
            reason = document.get("reason") if isinstance(document.get("reason"), str) else "invalid_config"
            body = _result(False, reason, directory=None, needed=[])
            print(_dumps(body))
            return 1
        needs_site = bool(document.get("needs_site"))
        needs_ip = bool(document.get("needs_ip"))
        explicit = options["geodata_dir"]
        if explicit:
            directory, create = Path(explicit), (not Path(explicit).exists()
                                                 and not Path(explicit).is_symlink())
        else:
            directory, create = _default_destination()
    body = ensure_into(directory, needs_site=needs_site, needs_ip=needs_ip, create=create)
    probed = None
    if body.get("directory"):
        probed = macos_preflight.probe_geodata(body["directory"], needs_site, needs_ip)
        body["preflight_geodata"] = probed.get("status")
        if needs_site or needs_ip:
            if probed.get("status") != "pass":
                body["ok"] = False
                body["result"] = "fail"
                if not body.get("reason"):
                    body["reason"] = probed.get("reason") or "geodata_missing"
    print(_dumps(body))
    return 0 if body.get("ok") else 1


def _needed(needs_site, needs_ip):
    names = []
    if needs_site:
        names.append(GEOSITE_NAME)
    if needs_ip:
        names.append(GEOIP_NAME)
    return names


def _looks_like_error(data):
    head = bytes(data[:512]).lstrip().lower()
    return head.startswith((b"<html", b"<!doctype", b"<?xml", b"{", b"["))


def _check_url(url):
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.port not in (None, 443) or host not in _ALLOWED_HOSTS):
        raise GeodataError("redirect_rejected")


def _transfer(url, *, max_bytes, transport):
    if transport is None:
        return fetch_https(url, max_bytes=max_bytes)
    try:
        data = transport(url, max_bytes=max_bytes)
    except GeodataError:
        raise
    except (TimeoutError, socket.timeout):
        raise GeodataError("timeout") from None
    except OSError:
        raise GeodataError("connection_failed") from None
    if not isinstance(data, (bytes, bytearray)):
        raise GeodataError("format_rejected")
    if len(data) > max_bytes:
        raise GeodataError("too_large")
    return bytes(data)


def _read_limited(response, max_bytes, read_timeout):
    headers = response.headers
    if headers is not None:
        ctype = (headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype in _HTML_TYPES:
            raise GeodataError("html_body")
        declared = headers.get("Content-Length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                raise GeodataError("truncated") from None
            if size <= 0:
                raise GeodataError("empty")
            if size > max_bytes:
                raise GeodataError("too_large")
        else:
            size = None
    else:
        size = None
    deadline = time.monotonic() + read_timeout
    chunks = []
    total = 0
    while total <= max_bytes:
        if time.monotonic() > deadline:
            raise GeodataError("timeout")
        try:
            block = response.read(64 * 1024)
        except (TimeoutError, socket.timeout):
            raise GeodataError("timeout") from None
        except OSError:
            raise GeodataError("connection_failed") from None
        if not block:
            break
        total += len(block)
        if total > max_bytes:
            raise GeodataError("too_large")
        chunks.append(block)
    data = b"".join(chunks)
    if not data:
        raise GeodataError("empty")
    if size is not None and size != len(data):
        raise GeodataError("truncated")
    return data


def _open_destination(path, *, create):
    path = Path(path)
    if not path.is_absolute():
        raise GeodataError("invalid_geodata_dir")
    if path.is_symlink():
        raise GeodataError("symlink")
    if not path.exists():
        if not create:
            raise GeodataError("geodata_dir_missing")
        try:
            macos_takeover.assert_private_ancestors(path)
        except macos_takeover.TakeoverError as exc:
            raise GeodataError(_token(str(exc), "unsafe_directory")) from None
        try:
            macos_prepare._create_private_parents(path)
        except OSError:
            raise GeodataError("io_error") from None
    try:
        resolved, info = macos_takeover._private_directory(path)
    except macos_takeover.TakeoverError as exc:
        raise GeodataError(_token(str(exc), "invalid_geodata_dir")) from None
    if info.st_uid != os.geteuid():
        raise GeodataError("foreign_owner")
    return resolved


@contextlib.contextmanager
def _directory_lock(directory):
    path = Path(directory) / ".nmd-geodata.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif path.is_symlink():
        raise GeodataError("symlink")
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise GeodataError("symlink") from None
        raise GeodataError("lock_failed") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise GeodataError("symlink")
        if info.st_uid != os.geteuid():
            raise GeodataError("foreign_owner")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _plan(directory, needed):
    present = []
    pending = []
    for canonical in needed:
        aliases = GEOSITE_NAMES if canonical == GEOSITE_NAME else GEOIP_MMDB_NAMES
        kind = SOURCES[canonical]["kind"]
        state, target = _asset_state(directory, aliases, kind)
        if state == "present":
            present.append(canonical)
            continue
        if state == "missing":
            pending.append((canonical, target or (Path(directory) / canonical)))
            continue
        return present, [], state
    return present, pending, None


def _asset_state(directory, aliases, kind):
    """``present`` with a path, or ``missing`` with the owned file to replace."""
    folded = {name.casefold() for name in aliases}
    try:
        entries = list(os.scandir(directory))
    except OSError:
        raise GeodataError("unreadable") from None
    saw_symlink = False
    saw_foreign = False
    saw_unreadable = False
    owned_bad = None
    for entry in entries:
        if entry.name.casefold() not in folded:
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            saw_unreadable = True
            continue
        path = Path(entry.path)
        if stat.S_ISLNK(info.st_mode):
            saw_symlink = True
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        ours = info.st_uid == os.geteuid()
        if info.st_size <= 0 or info.st_size > macos_takeover.GEODATA_MAX_BYTES:
            if ours:
                owned_bad = path
            else:
                saw_foreign = True
            continue
        try:
            data = _read_nofollow(path, macos_takeover.GEODATA_MAX_BYTES)
        except GeodataError as exc:
            if exc.reason == "symlink":
                saw_symlink = True
            else:
                saw_unreadable = True
            continue
        if valid_payload(kind, data):
            return "present", path
        if ours:
            owned_bad = path
        else:
            saw_foreign = True
    if saw_foreign and owned_bad is None:
        return "foreign_owner", None
    if saw_symlink and owned_bad is None:
        return "symlink", None
    if saw_unreadable and owned_bad is None:
        return "unreadable", None
    return "missing", owned_bad


def _read_nofollow(path, max_bytes):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif Path(path).is_symlink():
        raise GeodataError("symlink")
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise GeodataError("symlink") from None
        raise GeodataError("unreadable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise GeodataError("symlink")
        if info.st_size <= 0 or info.st_size > max_bytes:
            return b""
        data = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if len(data) != info.st_size or len(data) > max_bytes:
        raise GeodataError("unreadable")
    return data


def _promote(directory, target, payload):
    target = Path(target)
    try:
        if target.parent != Path(directory):
            raise GeodataError("invalid_geodata_dir")
    except OSError:
        raise GeodataError("io_error") from None
    try:
        info = target.lstat()
    except FileNotFoundError:
        info = None
    except OSError:
        raise GeodataError("unreadable") from None
    if info is not None:
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise GeodataError("symlink")
        if info.st_uid != os.geteuid():
            raise GeodataError("foreign_owner")
    fd, temporary = tempfile.mkstemp(dir=str(directory), prefix="." + target.name + ".")
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise GeodataError("io_error")
            view = view[written:]
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temporary, target)
        temporary = None
    except OSError:
        raise GeodataError("io_error") from None
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary)


def _default_destination():
    try:
        current = macos_takeover.resolve_geodata_dir(None)
    except macos_takeover.TakeoverError:
        current = None
    if current is not None:
        return current, False
    return Path.home() / ".config" / "mihomo", True


def _daemon_wants_geodata(action):
    import macos_preflight
    if action == "takeover-start":
        return True
    root = _manager_root()
    config, _problem = macos_preflight._load_installed_config(root)
    takeover = config.get("takeover") if isinstance(config, dict) else None
    if isinstance(takeover, dict) and takeover.get("on_boot") is True:
        return True
    activity = macos_preflight.probe_activity()
    return not isinstance(activity, dict) or activity.get("state") == "unknown"


def _installed_needs():
    import macos_preflight
    import nmd_daemon
    root = _manager_root()
    path = Path(nmd_daemon.default_daemon_config_path(root))
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False, False, "daemon_config_missing"
    except OSError:
        return False, False, "unreadable"
    if stat.S_ISLNK(info.st_mode):
        return False, False, "symlink"
    if info.st_uid != os.geteuid():
        return False, False, "config_owner_mismatch"
    config, problem = macos_preflight._load_installed_config(root)
    takeover = config.get("takeover") if isinstance(config, dict) else None
    if problem or not isinstance(takeover, dict):
        return False, False, problem or "invalid_config"
    document = macos_preflight.inspect_document(
        takeover.get("profile"), takeover.get("inputs"))
    if document.get("status") != "pass":
        reason = document.get("reason") if isinstance(document.get("reason"), str) else "invalid_config"
        return False, False, reason
    return bool(document.get("needs_site")), bool(document.get("needs_ip")), None


def _manager_root():
    import manager
    return manager.ROOT


def _parse_ensure(argv):
    options = {"geodata_dir": None, "inputs": None, "profile": None, "from_config": True}
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag not in ("--geodata-dir", "--inputs", "--profile"):
            raise GeodataError("invalid_arguments")
        if index + 1 >= len(argv):
            raise GeodataError("invalid_arguments")
        value = argv[index + 1]
        index += 2
        if flag == "--geodata-dir":
            options["geodata_dir"] = value
        elif flag == "--inputs":
            options["inputs"] = macos_takeover._load_trusted_json(value)
            options["from_config"] = False
        else:
            options["profile"] = macos_takeover._load_trusted_json(value)
    if options["profile"] is not None and options["inputs"] is None:
        raise GeodataError("inputs_required")
    if options["inputs"] is not None:
        options["inputs"] = macos_prepare.validate_inputs(options["inputs"])
    return options


def _result(ok, reason, *, directory, needed, present=None, downloaded=None,
            skipped=False, result=None):
    if result is None:
        result = "pass" if ok else "fail"
    if reason is not None:
        reason = _token(reason, "geodata_failed")
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "macos_geodata_ensure",
        "ok": bool(ok),
        "result": result,
        "reason": reason,
        "directory": str(directory) if directory else None,
        "needed": list(needed or []),
        "present": list(present or []),
        "downloaded": list(downloaded or []),
    }
    if skipped:
        body["skipped"] = True
    return body


def _token(value, fallback):
    if isinstance(value, str) and _TOKEN.fullmatch(value):
        return value
    return fallback


def _dumps(body):
    import json
    return json.dumps(body, ensure_ascii=False, indent=2)
