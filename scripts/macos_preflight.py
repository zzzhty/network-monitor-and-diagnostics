"""Read-only, tiered preflight for the macOS experimental path.

Three tiers, so opening a panel does not depend on takeover-only tools:

* ``readonly`` — dashboard and diagnostics for the current user.
* ``daemon`` — what the root supervisor needs before ``start`` or ``restart``.
  ``apply`` uses that restart. When ``on_boot`` is true, or the daemon's
  status cannot be read, the takeover checks are required as well, because
  that start can change the network.
* ``takeover`` — before any network change: mihomo, the official Tailscale
  client, geodata, offline config, and port conflicts.

The command prints one JSON document and does not install, download, sudo,
stop, start, or edit routes, DNS, proxy, or Tailscale. A ``fail`` or
``unknown`` result is blocking. ``unknown`` is a probe that did not answer,
not a guess that the check passed.

``tun.dns-mode: native`` needs mihomo 1.19.33 or newer. That floor is the
one recorded in ``docs/macos-mihomo-tailscale.md`` for this mode. It is not
a general product minimum, and it is not the observed 1.19.34 build.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

import macos_coexist
import macos_prepare
import macos_readonly
import macos_takeover

SCHEMA_VERSION = 1
TIERS = ("readonly", "daemon", "takeover")
# Documented requirement for tun.dns-mode native. Not MIHOMO_VERSION_OBSERVED.
NATIVE_DNS_MODE_VERSION = (1, 19, 33)
_VERSION_TEXT = ".".join(str(part) for part in NATIVE_DNS_MODE_VERSION)
_GEOIP_NAMES = ("geoip.metadb", "Country.mmdb", "geoip.dat")
_CODE = re.compile(r"[A-Za-z0-9_.:-]{1,80}")
_VERSION = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

HELP = """\
usage: nmd macos preflight [--tier readonly|daemon|takeover]

Read-only checks. The default tier is readonly. Nothing is installed,
downloaded, stopped, started, or changed. Exit 0 is pass, 1 is fail,
3 is unknown, 2 is a usage error. unknown blocks the same way fail does.

  readonly   panel and diagnostics. Does not require mihomo or Tailscale.
  daemon     before daemon start/restart and before nmd apply reloads one.
             Also requires the takeover tier when on_boot is true, or when
             the running daemon's status cannot be read.
  takeover   before accept, takeover, or daemon takeover-start.

JSON only. A failed check leaves the running service and the network as they are.
"""


def host_is_darwin():
    return sys.platform == "darwin"


def exit_code(report):
    result = report.get("result") if isinstance(report, dict) else None
    if result in ("pass", "not_applicable"):
        return 0
    if result == "unknown":
        return 3
    return 1


def snapshot_conflict(summary, *, snapshot_name, strict):
    """The existing ready/unknown split, in one place.

    Strict mode (the two-minute accept) refuses anything that is not an
    explicit false. A normal takeover only refuses a positive conflict;
    a null probe stays the caller's existing non-strict behavior.
    """
    summary = summary if isinstance(summary, dict) else {}
    fields = {key: summary.get(key) for key in ("has_198_18", "mihomo_running")}
    if strict and (snapshot_name is None or fields["has_198_18"] is not False
                   or fields["mihomo_running"] is not False):
        unknown = (snapshot_name is None or fields["has_198_18"] is None
                   or fields["mihomo_running"] is None)
        return {"result": "preflight_unknown" if unknown else "preflight_failed",
                "preflight": fields}
    if fields["has_198_18"] is True or fields["mihomo_running"] is True:
        return {"result": "preflight_failed", "preflight": fields}
    return None


def _not_applicable(tier):
    return {"schema_version": SCHEMA_VERSION, "kind": "macos_preflight",
            "tier": tier, "result": "not_applicable", "blocking": False,
            "required_tiers": [], "checks": [], "remediation": [],
            "effects": {"preflight_mutates": False}}


def _code(value, fallback):
    text = str(value or "")
    if _CODE.fullmatch(text):
        return text
    head = text.split(":", 1)[0]
    if _CODE.fullmatch(head):
        return head
    return fallback


def _check(check_id, status, *, required, reason=None, summary, remediation=None, **extra):
    if required and status not in ("pass", "fail", "unknown"):
        status = "unknown"
        reason = reason or "not_run"
    item = {"id": check_id, "status": status, "required": bool(required),
            "summary": summary}
    if reason:
        item["reason"] = reason
    if status in ("fail", "unknown") and remediation:
        item["remediation"] = remediation
    for key, value in extra.items():
        if value is not None:
            item[key] = value
    return item


def _parsed_version(text):
    if not isinstance(text, str):
        return None
    match = _VERSION.search(text)
    if match is None:
        return None
    return tuple(int(match.group(index)) for index in range(1, 4))


def _version_label(parsed):
    if not isinstance(parsed, tuple) or len(parsed) != 3:
        return None
    return ".".join(str(part) for part in parsed)


def probe_executable(path):
    """``pass`` / ``fail`` / ``unknown``. Does not spawn the binary."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "fail"
    except OSError:
        return "unknown"
    if stat.S_ISLNK(info.st_mode):
        try:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return "pass"
        except OSError:
            return "unknown"
        return "fail"
    if not stat.S_ISREG(info.st_mode):
        return "fail"
    try:
        return "pass" if os.access(path, os.X_OK) else "fail"
    except OSError:
        return "unknown"


def probe_version(path):
    """Bounded ``mihomo -v``. Stdout only; stderr is discarded by the runner."""
    try:
        code, data, error = macos_readonly.bounded_run([str(path), "-v"], 3, 4096)
    except (OSError, ValueError):
        return {"status": "unknown", "parsed": None, "reason": "probe_error"}
    if error:
        reason = error if error in macos_readonly._PUBLIC_ERRORS else "command_failed"
        return {"status": "unknown", "parsed": None, "reason": reason}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"status": "unknown", "parsed": None, "reason": "invalid_text"}
    parsed = _parsed_version(text)
    if code != 0:
        return {"status": "unknown", "parsed": parsed, "reason": "command_failed"}
    if parsed is None:
        return {"status": "unknown", "parsed": None, "reason": "unparsed"}
    return {"status": "pass", "parsed": parsed, "reason": None}


def probe_tailscale_cli():
    for candidate in macos_readonly.TAILSCALE_CANDIDATES:
        status = probe_executable(candidate)
        if status == "pass":
            return {"status": "pass", "path": candidate, "reason": None}
        if status == "unknown":
            return {"status": "unknown", "path": candidate, "reason": "stat_failed"}
    return {"status": "fail", "path": None, "reason": "missing"}


def probe_tailscale_status(path):
    """Official CLI ``status --json``, then the existing whitelist parser."""
    try:
        code, text, error = macos_readonly.execute(
            [path, "status", "--json"], macos_readonly._TAILSCALE_TIMEOUT)
    except (OSError, ValueError):
        return {"status": "unknown", "availability": None, "reason": "probe_error"}
    if error:
        reason = error if error in macos_readonly._PUBLIC_ERRORS else "command_failed"
        return {"status": "unknown", "availability": "unavailable", "reason": reason}
    try:
        view = macos_coexist.normalize_tailscale_status(
            text, returncode=0 if code == 0 else code)
    except (TypeError, ValueError):
        return {"status": "unknown", "availability": None, "reason": "invalid_status"}
    availability = view.get("availability")
    if availability == "healthy":
        return {"status": "pass", "availability": "healthy", "reason": None}
    if availability == "offline":
        return {"status": "fail", "availability": "offline", "reason": "not_running"}
    if availability == "unknown":
        return {"status": "unknown", "availability": "unknown", "reason": "missing_field"}
    return {"status": "unknown", "availability": availability or "unavailable",
            "reason": view.get("reason") or "unavailable"}


def probe_listen(port, host="127.0.0.1", timeout=1.0):
    """``free`` / ``busy`` / ``unknown``. Connects once; never binds or sends data."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return "unknown"
    if port == 22:
        return "unknown"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        return "free"
    except socket.timeout:
        return "unknown"
    except OSError as exc:
        if exc.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH):
            return "free"
        return "unknown"
    else:
        return "busy"
    finally:
        sock.close()


def probe_snapshot():
    """In-memory snapshot summary. Does not write the snapshot file."""
    if not host_is_darwin():
        return {"status": "unknown", "reason": "not_darwin",
                "has_198_18": None, "mihomo_running": None}
    try:
        snapshot = macos_prepare.build_snapshot("macos")
        summary = macos_prepare.summarize_snapshot(snapshot)
    except (OSError, ValueError, TypeError):
        return {"status": "unknown", "reason": "snapshot_error",
                "has_198_18": None, "mihomo_running": None}
    if not isinstance(summary, dict) or snapshot.get("status") != "observed":
        return {"status": "unknown", "reason": "not_observed",
                "has_198_18": None, "mihomo_running": None}
    return {"status": "pass", "reason": None,
            "has_198_18": summary.get("has_198_18"),
            "mihomo_running": summary.get("mihomo_running")}


def probe_activity(socket_path=None):
    """One status read. Missing socket means the daemon is not running.

    A timeout or a garbled reply is ``unknown``: the process might still be
    in a takeover, so the caller must not stop it.
    """
    import nmd_daemon
    path = Path(socket_path or nmd_daemon.SOCKET_PATH)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"state": "inactive", "reason": "socket_absent", "on_boot": None}
    except OSError:
        return {"state": "unknown", "reason": "socket_unreadable", "on_boot": None}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        return {"state": "unknown", "reason": "socket_not_a_socket", "on_boot": None}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    try:
        sock.connect(os.fspath(path))
        sock.sendall(b'{"cmd":"status"}\n')
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_WR)
        data = sock.recv(nmd_daemon.IPC_MAX_BYTES + 1)
    except socket.timeout:
        return {"state": "unknown", "reason": "timeout", "on_boot": None}
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ECONNREFUSED):
            return {"state": "inactive", "reason": "not_listening", "on_boot": None}
        return {"state": "unknown", "reason": "status_unavailable", "on_boot": None}
    finally:
        sock.close()
    if len(data) > nmd_daemon.IPC_MAX_BYTES:
        return {"state": "unknown", "reason": "status_too_large", "on_boot": None}
    try:
        reply = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"state": "unknown", "reason": "invalid_reply", "on_boot": None}
    if not isinstance(reply, dict) or "error" in reply:
        return {"state": "unknown", "reason": "status_unavailable", "on_boot": None}
    active = reply.get("takeover_active")
    if not isinstance(active, bool):
        return {"state": "unknown", "reason": "missing_field", "on_boot": None}
    on_boot = reply.get("on_boot")
    return {"state": "active" if active else "inactive", "reason": None,
            "on_boot": on_boot if isinstance(on_boot, bool) else None}


def probe_geodata(directory, needs_site, needs_ip):
    if directory is None:
        return {"status": "fail", "reason": "geodata_dir_missing", "missing": ["geodata_dir"]}
    directory = Path(directory)
    missing = []
    unreadable = False

    def classify(name):
        """``ok``, ``missing``, or ``unknown``. Does not follow symlinks."""
        file = directory / name
        try:
            info = file.lstat()
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unknown"
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return "missing"
        if info.st_size <= 0 or info.st_size > macos_takeover.GEODATA_MAX_BYTES:
            return "missing"
        try:
            readable = os.access(file, os.R_OK)
        except OSError:
            return "unknown"
        if not readable:
            return "unknown"
        return "ok"

    if needs_site:
        state = classify("geosite.dat")
        if state == "missing":
            missing.append("geosite.dat")
        elif state == "unknown":
            unreadable = True
    if needs_ip:
        states = [classify(name) for name in _GEOIP_NAMES]
        if "ok" not in states:
            if "unknown" in states:
                unreadable = True
            else:
                missing.append("geoip")
    if missing:
        return {"status": "fail", "reason": "geodata_missing", "missing": missing}
    if unreadable:
        return {"status": "unknown", "reason": "geodata_unreadable", "missing": []}
    return {"status": "pass", "reason": "ok" if (needs_site or needs_ip) else "not_required",
            "missing": []}


def inspect_state_dir(path):
    if path is None:
        return {"status": "unknown", "reason": "state_dir_unreadable"}
    if not Path(path).is_absolute():
        return {"status": "fail", "reason": "not_absolute"}
    try:
        macos_takeover.assert_private_ancestors(Path(path))
    except macos_takeover.TakeoverError as exc:
        code = _code(exc, "unsafe_state_dir")
        if code == "path_unusable":
            return {"status": "unknown", "reason": code}
        return {"status": "fail", "reason": code}
    except OSError:
        return {"status": "unknown", "reason": "stat_failed"}
    return {"status": "pass", "reason": "ok"}


def inspect_collector(preferred):
    import nmd_daemon
    preferred = Path(preferred)
    try:
        chosen = nmd_daemon.collector_state_dir(preferred)
    except nmd_daemon.DaemonError:
        return {"status": "fail", "reason": "collector_state_unusable", "path": None}
    if not nmd_daemon._collector_can_lock(chosen):
        return {"status": "fail", "reason": "not_private", "path": str(chosen)}
    if chosen.exists():
        return {"status": "pass", "reason": "ok", "path": str(chosen)}
    parent = chosen.parent
    try:
        info = parent.lstat()
    except OSError:
        return {"status": "unknown", "reason": "parent_unreadable", "path": str(chosen)}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return {"status": "fail", "reason": "parent_not_directory", "path": str(chosen)}
    try:
        writable = os.access(parent, os.W_OK | os.X_OK)
    except OSError:
        return {"status": "unknown", "reason": "parent_unreadable", "path": str(chosen)}
    if not writable:
        return {"status": "fail", "reason": "parent_not_writable", "path": str(chosen)}
    return {"status": "pass", "reason": "can_create", "path": str(chosen)}


def _loopback_port(listen):
    if not isinstance(listen, str) or listen.count(":") != 1:
        return None
    host, port_text = listen.split(":", 1)
    if not port_text.isdigit():
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    port = int(port_text)
    if not address.is_loopback or not 1 <= port <= 65535 or port == 22:
        return None
    return port


def _load_profile(profile):
    if profile is not None:
        return profile
    path = Path(__file__).resolve().parents[1] / "examples/macos-mihomo-coexist.experiment.json"
    return json.loads(path.read_text(encoding="utf-8"))


def inspect_document(profile, inputs):
    blank = {"status": "fail", "reason": "inputs_missing", "dns_mode": None,
             "needs_site": False, "needs_ip": False, "listen_port": None}
    if not isinstance(inputs, dict):
        return blank
    if inputs.get("server") == macos_coexist.PLACEHOLDER_SOCKS_HOST:
        return dict(blank, reason="placeholder_inputs")
    try:
        profile = _load_profile(profile)
        normalized = macos_prepare.validate_inputs(inputs)
        macos_prepare.render_config(profile, normalized, geo_auto_update=False)
        document = macos_prepare.build_mihomo_document(
            profile, normalized, geo_auto_update=False)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return dict(blank, reason=_code(exc, "invalid_config"))
    dns_mode = (document.get("tun") or {}).get("dns-mode")
    if dns_mode not in ("native", "disabled"):
        dns_mode = None
    rules = document.get("rules") or []
    return {"status": "pass", "reason": "ok", "dns_mode": dns_mode,
            "needs_site": any(isinstance(rule, str) and rule.startswith("GEOSITE,")
                              for rule in rules),
            "needs_ip": any(isinstance(rule, str) and rule.startswith("GEOIP,")
                            for rule in rules),
            "listen_port": _loopback_port((document.get("dns") or {}).get("listen"))}


def _load_installed_config(root):
    import nmd_daemon
    path = nmd_daemon.default_daemon_config_path(root)
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return None, "absent"
    except OSError:
        return None, "unreadable"
    if stat.S_ISLNK(info.st_mode):
        return None, "symlink"
    expected = None if os.geteuid() == 0 else os.geteuid()
    try:
        return nmd_daemon.load_daemon_config(path, expected_uid=expected), None
    except nmd_daemon.DaemonError as exc:
        return None, _code(exc, "invalid_config")


def _recorded_state_dir(root):
    if root is None:
        return str(macos_prepare.default_state_dir())
    try:
        import manager
        recorded = manager.setting(Path(root), "stateDir")
    except Exception:
        return None
    if isinstance(recorded, str) and recorded and Path(recorded).is_absolute():
        return recorded
    return str(macos_prepare.default_state_dir())


def _resolve_mihomo(override):
    if override:
        path = Path(override)
        if not path.is_absolute():
            return {"status": "fail", "path": None, "reason": "not_absolute"}
        status = probe_executable(os.fspath(path))
        if status == "pass":
            return {"status": "pass", "path": str(path), "reason": None}
        if status == "unknown":
            return {"status": "unknown", "path": str(path), "reason": "stat_failed"}
        try:
            present = path.is_symlink() or path.exists()
        except OSError:
            return {"status": "unknown", "path": str(path), "reason": "stat_failed"}
        return {"status": "fail", "path": str(path),
                "reason": "not_executable" if present else "missing"}
    unknown = None
    for candidate in macos_takeover.MIHOMO_CANDIDATES:
        status = probe_executable(candidate)
        if status == "pass":
            return {"status": "pass", "path": candidate, "reason": None}
        if status == "unknown" and unknown is None:
            unknown = candidate
    if unknown is not None:
        return {"status": "unknown", "path": unknown, "reason": "stat_failed"}
    return {"status": "fail", "path": None, "reason": "missing"}


def _safe_probe(fn, fallback):
    try:
        value = fn()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return fallback
    return value if isinstance(value, dict) else fallback


def collect(tier, *, root=None, options=None):
    """Gather facts. Every probe is read-only; a probe error becomes unknown."""
    if not host_is_darwin():
        return {"platform": "other", "tier": tier}
    foreground = tier == "takeover" and options is not None
    options = options or {}
    facts = {"platform": "macos", "tier": tier, "config": None, "config_problem": None,
             "document": None, "mihomo": None, "version": None, "tailscale_cli": None,
             "tailscale_status": None, "geodata": None, "state_dir": None,
             "collector": None, "dashboard_port": None, "listen": {},
             "snapshot": None, "activity": None, "on_boot": None,
             "expand_takeover": False, "require_daemon_config": False}
    if tier == "readonly":
        state = _recorded_state_dir(root)
        if state is None:
            facts["collector"] = {"status": "unknown", "reason": "state_dir_unreadable",
                                  "path": None}
        else:
            facts["collector"] = _safe_probe(
                lambda: inspect_collector(state),
                {"status": "unknown", "reason": "probe_error", "path": None})
        config, problem = _load_installed_config(root)
        if problem is None and isinstance(config, dict):
            port = config.get("dashboard", {}).get("port")
            if isinstance(port, int) and not isinstance(port, bool):
                facts["dashboard_port"] = port
                facts["listen"][port] = probe_listen(port)
        return facts

    config = None
    problem = None
    if not foreground:
        facts["require_daemon_config"] = True
        config, problem = _load_installed_config(root)
        facts["config"] = config
        facts["config_problem"] = problem
    if isinstance(config, dict):
        facts["on_boot"] = config["takeover"]["on_boot"]
    if tier == "daemon":
        facts["activity"] = _safe_probe(
            probe_activity,
            {"state": "unknown", "reason": "probe_error", "on_boot": None})
        activity = facts["activity"] or {}
        if isinstance(activity.get("on_boot"), bool) and facts["on_boot"] is None:
            facts["on_boot"] = activity["on_boot"]
        facts["expand_takeover"] = bool(
            facts["on_boot"] is True or activity.get("state") == "unknown")

    override = options.get("mihomo_path") if foreground else None
    if override is None and isinstance(config, dict):
        override = config["takeover"].get("mihomo_path")
    facts["mihomo"] = _safe_probe(
        lambda: _resolve_mihomo(override),
        {"status": "unknown", "path": None, "reason": "probe_error"})
    facts["tailscale_cli"] = _safe_probe(
        probe_tailscale_cli,
        {"status": "unknown", "path": None, "reason": "probe_error"})

    if foreground:
        state = options.get("state_dir") or _recorded_state_dir(root)
    elif isinstance(config, dict) and config["takeover"].get("state_dir"):
        state = config["takeover"]["state_dir"]
    else:
        state = _recorded_state_dir(root)
    facts["state_dir"] = _safe_probe(
        lambda: inspect_state_dir(state),
        {"status": "unknown", "reason": "probe_error"})

    want_takeover = tier == "takeover" or facts["expand_takeover"]
    if not want_takeover:
        return facts

    profile = options.get("profile") if foreground else None
    inputs = options.get("inputs") if foreground else None
    if isinstance(config, dict):
        if profile is None:
            profile = config["takeover"].get("profile")
        if inputs is None:
            inputs = config["takeover"].get("inputs")
    facts["document"] = _safe_probe(
        lambda: inspect_document(profile, inputs),
        {"status": "unknown", "reason": "probe_error", "dns_mode": None,
         "needs_site": False, "needs_ip": False, "listen_port": None})
    document = facts["document"] or {}
    mihomo = facts["mihomo"] or {}
    if mihomo.get("status") == "pass" and mihomo.get("path"):
        facts["version"] = _safe_probe(
            lambda: probe_version(mihomo["path"]),
            {"status": "unknown", "parsed": None, "reason": "probe_error"})
    else:
        facts["version"] = {"status": "skip", "parsed": None, "reason": "not_run"}
    tailscale = facts["tailscale_cli"] or {}
    if tailscale.get("status") == "pass" and tailscale.get("path"):
        facts["tailscale_status"] = _safe_probe(
            lambda: probe_tailscale_status(tailscale["path"]),
            {"status": "unknown", "availability": None, "reason": "probe_error"})
    else:
        facts["tailscale_status"] = {"status": "skip", "availability": None,
                                     "reason": "not_run"}
    geo_override = options.get("geodata_dir") if foreground else None
    try:
        geo_dir = macos_takeover.resolve_geodata_dir(geo_override)
        geo_problem = None
    except macos_takeover.TakeoverError as exc:
        geo_dir = None
        geo_problem = _code(exc, "invalid_geodata_dir")
    if geo_problem:
        facts["geodata"] = {"status": "fail", "reason": geo_problem, "missing": []}
    else:
        facts["geodata"] = _safe_probe(
            lambda: probe_geodata(geo_dir, document.get("needs_site"), document.get("needs_ip")),
            {"status": "unknown", "reason": "probe_error", "missing": []})
    facts["snapshot"] = _safe_probe(
        probe_snapshot,
        {"status": "unknown", "reason": "probe_error",
         "has_198_18": None, "mihomo_running": None})
    listen_port = document.get("listen_port")
    if isinstance(listen_port, int):
        facts["listen"][listen_port] = probe_listen(listen_port)
    return facts


def _mihomo_text(mihomo):
    reason = (mihomo or {}).get("reason")
    path = (mihomo or {}).get("path")
    if reason == "missing":
        return ("没有找到可执行的 mihomo。",
                "把官方 mihomo 装到 /usr/local/bin/mihomo、/opt/homebrew/bin/mihomo "
                "或 /usr/local/sbin/mihomo，或在 daemon.json 的 takeover.mihomo_path "
                "写成绝对路径。不会自动下载。")
    if reason == "not_executable":
        return ("mihomo 文件存在，但当前用户不能执行。",
                "确认它是普通文件并且有执行权限。预检不会改权限，也不会下载。")
    if reason == "not_absolute":
        return ("mihomo 路径不是绝对路径。",
                "takeover.mihomo_path 或 --mihomo 必须是绝对路径。")
    if (mihomo or {}).get("status") == "unknown":
        return ("无法确认 mihomo 是否可执行。",
                "探测没有得到结果，所以这是 unknown，不会当成已安装。没有改动服务。")
    return (f"mihomo 可用：{path}" if path else "mihomo 可用。", None)


def _version_text(version, dns_mode):
    reason = (version or {}).get("reason")
    parsed = _version_label((version or {}).get("parsed"))
    if reason == "timeout":
        return ("mihomo 版本探测超时。",
                "结果是 unknown。请在本机重试 mihomo -v。预检没有启动或停止服务。")
    if reason in ("unparsed", "invalid_text", "command_failed", "probe_error"):
        return ("mihomo -v 没有给出可识别的版本。",
                "无法判断它是否支持当前配置。请在本机确认版本后重试。预检不会猜测兼容性。")
    if dns_mode == "native" and (version or {}).get("status") == "fail":
        return (f"mihomo {parsed or '版本过旧'} 不支持当前的 tun.dns-mode native。",
                f"这份配置需要 mihomo {_VERSION_TEXT} 或更新。这是文档里 native 模式的要求，"
                "不是把曾经观测到的 1.19.34 当成最低版本。请换官方构建。不会自动下载。")
    if dns_mode == "disabled":
        return ("dns-mode 为 disabled，没有额外的版本下限。"
                + (f" 读到的版本是 {parsed}。" if parsed else ""), None)
    if dns_mode is None:
        return ("读不到这份配置的 dns-mode，无法对照版本能力。",
                "结果是 unknown。请修正配置后再接管。")
    if parsed:
        return (f"mihomo {parsed} 满足当前 dns-mode native 的要求。", None)
    return ("无法确认 mihomo 版本。", "结果是 unknown。没有改动服务。")


def assess(tier, facts):
    """Turn collected facts into one report. This function does no I/O."""
    if not isinstance(facts, dict) or facts.get("platform") != "macos":
        return _not_applicable(tier)
    checks = []
    if tier == "readonly":
        collector = facts.get("collector") or {"status": "unknown", "reason": "not_run"}
        status = collector.get("status") or "unknown"
        if status == "pass":
            summary, fix = "当前用户可以使用采集目录。", None
        elif status == "unknown":
            summary, fix = ("读不到采集目录，无法确认当前用户能不能用。",
                            "请确认目录是否存在、属主是不是当前用户。预检没有创建目录。")
        else:
            summary, fix = ("当前用户用不了采集目录。",
                            "请使用该用户自己的 0700 目录。接管目录若属 root，采集会改用旁边的"
                            "同名 -user 目录，父目录也必须可写。打开面板不需要 mihomo。")
        checks.append(_check("collector_directory", status, required=True,
                             reason=collector.get("reason"), summary=summary,
                             remediation=fix, path=collector.get("path")))
        port = facts.get("dashboard_port")
        if not isinstance(port, int):
            checks.append(_check("dashboard_port", "skip", required=False,
                                 reason="not_configured",
                                 summary="没有已安装的面板端口。打开面板不检查接管组件。"))
        else:
            listened = (facts.get("listen") or {}).get(port)
            if listened == "busy":
                checks.append(_check(
                    "dashboard_port", "fail", required=True, reason="busy",
                    summary=f"面板端口 {port} 已有程序在监听。",
                    remediation="换一个端口，或停掉占用它的程序后再开面板。预检不会结束那个进程。"))
            elif listened == "free":
                checks.append(_check("dashboard_port", "pass", required=True,
                                     summary=f"面板端口 {port} 没有监听。"))
            else:
                checks.append(_check(
                    "dashboard_port", "unknown", required=True, reason="probe_unknown",
                    summary=f"无法确认面板端口 {port} 是否空闲。",
                    remediation="探测没有得到结果，所以这是 unknown。没有改动端口上的程序。"))
        return _finish(tier, ["readonly"], checks, facts)

    config_problem = facts.get("config_problem")
    if facts.get("require_daemon_config"):
        if config_problem is None and isinstance(facts.get("config"), dict):
            checks.append(_check("daemon_config", "pass", required=True,
                                 summary="daemon.json 可以通过现有校验。"))
        elif config_problem == "absent":
            checks.append(_check(
                "daemon_config", "fail", required=True, reason="absent",
                summary="没有 daemon.json，常驻守护起不来。",
                remediation="按 examples/macos-daemon.json 写成仅当前用户可读写的配置。"
                            "不会自动填入真实地址。"))
        elif config_problem in ("unreadable",):
            checks.append(_check(
                "daemon_config", "unknown", required=True, reason=config_problem,
                summary="daemon.json 读不出来。",
                remediation="无法确认配置是否有效，所以这是 unknown。没有改这个文件。"))
        else:
            checks.append(_check(
                "daemon_config", "fail", required=True, reason=config_problem or "invalid_config",
                summary="daemon.json 没有通过校验。",
                remediation="请修正配置的权限、所有者和字段。预检不会改写它。"))

    state = facts.get("state_dir") or {"status": "unknown", "reason": "not_run"}
    if state.get("status") == "pass":
        checks.append(_check("state_directory", "pass", required=True,
                             summary="状态目录通过现有的私有路径检查。"))
    elif state.get("status") == "unknown":
        checks.append(_check(
            "state_directory", "unknown", required=True, reason=state.get("reason"),
            summary="读不到状态目录，无法确认权限。",
            remediation="没有修改该目录。请先确认路径可读，再重试。"))
    else:
        checks.append(_check(
            "state_directory", "fail", required=True, reason=state.get("reason") or "unsafe",
            summary="状态目录的权限或路径不安全。",
            remediation="目录需要是运行该进程的用户可用的私有目录，父路径不能是可被替换的符号链接，"
                        "组或其他人不能可写。预检不会改权限。"))

    mihomo = facts.get("mihomo") or {"status": "unknown", "reason": "not_run"}
    summary, fix = _mihomo_text(mihomo)
    checks.append(_check("mihomo_executable", mihomo.get("status") or "unknown",
                         required=True, reason=mihomo.get("reason"),
                         summary=summary, remediation=fix, path=mihomo.get("path")))

    tailscale = facts.get("tailscale_cli") or {"status": "unknown", "reason": "not_run"}
    if tailscale.get("status") == "pass":
        checks.append(_check("tailscale_cli", "pass", required=True,
                             summary="找到官方 Tailscale 命令行。",
                             path=tailscale.get("path")))
    elif tailscale.get("status") == "unknown":
        checks.append(_check(
            "tailscale_cli", "unknown", required=True, reason=tailscale.get("reason"),
            summary="无法确认官方 Tailscale 命令行是否可执行。",
            remediation="探测没有得到结果。不会改用其他客户端，也不会安装。"))
    else:
        checks.append(_check(
            "tailscale_cli", "fail", required=True, reason="missing",
            summary="没有找到官方 Tailscale 命令行。",
            remediation="请安装官方 Tailscale，使命令位于 /usr/bin/tailscale、"
                        "/usr/local/bin/tailscale、/opt/homebrew/bin/tailscale "
                        "或 Tailscale.app 内。不会自动安装，也不会改用其他客户端。"))

    if tier == "daemon":
        activity = facts.get("activity") or {"state": "unknown", "reason": "not_run"}
        if activity.get("state") == "unknown":
            checks.append(_check(
                "daemon_activity", "unknown", required=True, reason=activity.get("reason"),
                summary="看不清常驻守护是否正在接管。",
                remediation="状态套接字没有给出可用结果。为避免误停正在跑的进程，"
                            "这次不会 stop，也不会 sudo。"))
        elif activity.get("state") == "active":
            checks.append(_check("daemon_activity", "pass", required=True,
                                 summary="常驻守护在运行，并且当前有接管。"))
        else:
            checks.append(_check("daemon_activity", "pass", required=True,
                                 reason=activity.get("reason"),
                                 summary="没有看到正在运行的常驻守护。"))
        checks.append(_check("network_effect", "pass", required=False,
                             summary=_network_summary(activity, facts.get("on_boot"))))

    want_takeover = tier == "takeover" or facts.get("expand_takeover") is True
    if not want_takeover:
        required = ["daemon"]
        return _finish(tier, required, checks, facts)

    document = facts.get("document") or {"status": "unknown", "reason": "not_run",
                                         "dns_mode": None}
    if document.get("status") == "pass":
        checks.append(_check("mihomo_config", "pass", required=True,
                             summary="离线配置校验通过。没有运行会联网的 mihomo -t。"))
    elif document.get("status") == "unknown":
        checks.append(_check(
            "mihomo_config", "unknown", required=True, reason=document.get("reason"),
            summary="离线配置校验没有完成。",
            remediation="结果是 unknown。没有写入配置，也没有改网络。"))
    else:
        reason = document.get("reason") or "invalid_config"
        if reason == "placeholder_inputs":
            summary = "配置仍是文档占位地址，不能用来接管。"
            fix = "换成自己的 Tailnet 地址后再试。预检不会写入这份配置。"
        elif reason == "inputs_missing":
            summary = "没有接管输入，无法校验将要加载的配置。"
            fix = "提供 inputs，或先写好 daemon.json。不会自动生成。"
        else:
            summary = "mihomo 配置没有通过离线校验。"
            fix = "请修正 inputs 或 profile。预检不会改写配置，也不会联网下载地理数据。"
        checks.append(_check("mihomo_config", "fail", required=True, reason=reason,
                             summary=summary, remediation=fix))

    dns_mode = document.get("dns_mode")
    version = facts.get("version") or {"status": "unknown", "reason": "not_run"}
    if version.get("status") == "skip":
        checks.append(_check("mihomo_version", "skip", required=False,
                             reason=version.get("reason") or "not_run",
                             summary="mihomo 还不可执行，跳过版本探测。"))
    else:
        capability = version.get("status") or "unknown"
        if capability == "pass" and dns_mode == "native":
            parsed = version.get("parsed")
            if not isinstance(parsed, tuple) or parsed < NATIVE_DNS_MODE_VERSION:
                capability = "fail"
        elif capability == "pass" and dns_mode is None:
            capability = "unknown"
        summary, fix = _version_text(dict(version, status=capability), dns_mode)
        checks.append(_check("mihomo_version", capability, required=True,
                             reason=version.get("reason"), summary=summary,
                             remediation=fix, version=_version_label(version.get("parsed"))))

    geodata = facts.get("geodata") or {"status": "unknown", "reason": "not_run", "missing": []}
    if geodata.get("status") == "pass":
        checks.append(_check("geodata", "pass", required=True,
                             summary="接管规则要用的地理数据可以读到。不会下载缺失文件。"))
    elif geodata.get("status") == "unknown":
        checks.append(_check(
            "geodata", "unknown", required=True, reason=geodata.get("reason"),
            summary="地理数据目录读不完整。",
            remediation="结果是 unknown。没有复制或下载文件。"))
    else:
        missing = geodata.get("missing") if isinstance(geodata.get("missing"), list) else []
        checks.append(_check(
            "geodata", "fail", required=True, reason=geodata.get("reason") or "geodata_missing",
            summary="地理数据不够用或目录不可用。" + (f" 缺：{', '.join(missing)}。" if missing else ""),
            remediation="规则用到 GEOSITE 时需要 geosite.dat；用到 GEOIP 时需要 geoip.metadb、"
                        "Country.mmdb 或 geoip.dat 之一。放到该账户的 ~/.config/mihomo，"
                        "或显式指定目录。不会自动下载。",
            missing=missing or None))

    status_probe = facts.get("tailscale_status") or {"status": "unknown", "reason": "not_run"}
    if status_probe.get("status") == "skip":
        checks.append(_check("tailscale_status", "skip", required=False,
                             reason="not_run", summary="没有官方 Tailscale 命令行，跳过状态探测。"))
    elif status_probe.get("status") == "pass":
        checks.append(_check("tailscale_status", "pass", required=True,
                             summary="官方 Tailscale 正在运行。"))
    elif status_probe.get("status") == "fail":
        checks.append(_check(
            "tailscale_status", "fail", required=True, reason="not_running",
            summary="官方 Tailscale 没有在运行。",
            remediation="先打开官方客户端并连上，再做接管。预检不会执行 tailscale set。"))
    else:
        checks.append(_check(
            "tailscale_status", "unknown", required=True,
            reason=status_probe.get("reason") or "unavailable",
            summary="无法确认官方 Tailscale 是否在运行。",
            remediation="状态探测超时、失败或无法解析。没有把它当成已连接，也没有修改 Tailscale。"))

    snapshot = facts.get("snapshot") or {"status": "unknown", "has_198_18": None,
                                         "mihomo_running": None}
    # Restart stops this daemon's takeover before the new process listens.
    # Its own mihomo and 198.18 are not another instance. A boolean probe
    # cannot see a second mihomo beside that takeover; unknown stays unknown.
    owns = _daemon_owns_takeover(tier, facts)
    for check_id, field, busy_summary, busy_fix, clear_summary in (
            ("tun_dns", "has_198_18",
             "系统 DNS 里已经有 198.18。",
             "先确认没有另一份 mihomo 在接管。预检不会改 DNS。",
             "没有看到 198.18 的系统 DNS。"),
            ("mihomo_process", "mihomo_running",
             "已经有 mihomo 进程。",
             "先确认它不是要保留的实例。预检不会结束它。",
             "进程列表里没有 mihomo。")):
        if snapshot.get("status") != "pass" or snapshot.get(field) is None:
            checks.append(_check(
                check_id, "unknown", required=True,
                reason=snapshot.get("reason") or "not_observed",
                summary="读不到这项冲突检查的结果。",
                remediation="unknown 不会当成没有冲突。没有改网络。"))
        elif snapshot.get(field) is True and owns:
            checks.append(_check(
                check_id, "pass", required=True, reason="owned_by_daemon",
                summary="这是当前常驻守护自己的接管，不是另一份实例。"
                        "重载会先结束它并按快照回退。"))
        elif snapshot.get(field) is True:
            checks.append(_check(check_id, "fail", required=True, reason="conflict",
                                 summary=busy_summary, remediation=busy_fix))
        else:
            checks.append(_check(check_id, "pass", required=True, summary=clear_summary))

    listen_port = (facts.get("document") or {}).get("listen_port")
    if not isinstance(listen_port, int):
        checks.append(_check("dns_listen", "skip", required=False, reason="not_configured",
                             summary="这份配置没有本机回环 DNS 端口需要检查。"))
    else:
        listened = (facts.get("listen") or {}).get(listen_port)
        if listened == "busy" and owns:
            checks.append(_check(
                "dns_listen", "pass", required=True, reason="owned_by_daemon",
                summary=f"127.0.0.1:{listen_port} 正由当前接管使用，不是另一份程序。"
                        "重载会先结束它，再由新进程监听。"))
        elif listened == "busy":
            checks.append(_check(
                "dns_listen", "fail", required=True, reason="busy",
                summary=f"127.0.0.1:{listen_port} 已有程序在监听。",
                remediation="接管配置会使用这个 DNS 端口。先停掉占用它的程序。预检不会结束那个进程。"))
        elif listened == "free":
            checks.append(_check("dns_listen", "pass", required=True,
                                 summary=f"127.0.0.1:{listen_port} 没有监听。"))
        else:
            checks.append(_check(
                "dns_listen", "unknown", required=True, reason="probe_unknown",
                summary=f"无法确认 127.0.0.1:{listen_port} 是否空闲。",
                remediation="探测没有得到结果，所以这是 unknown。没有改动该端口。"))

    required = ["takeover"] if tier == "takeover" else ["daemon", "takeover"]
    return _finish(tier, required, checks, facts)


def _daemon_owns_takeover(tier, facts):
    """True when this daemon reports its own takeover, not a foreign one.

    Only the daemon lifecycle releases that takeover before listening again.
    ``accept`` / ``takeover`` do not, so the takeover tier stays strict.
    """
    return (tier == "daemon"
            and (facts.get("activity") or {}).get("state") == "active")


def _network_summary(activity, on_boot):
    state = (activity or {}).get("state")
    if state == "active":
        return ("当前有接管。之后若执行 restart，stop 会先按快照回退，"
                "路由、DNS 或 Tailscale exit node 会变。")
    if state == "unknown":
        return "看不清是否正在接管，所以不会假定网络保持不变。"
    if on_boot is True:
        return ("当前没有看到正在运行的接管。on_boot 为 true 时，若这次启动被管理器当成"
                "新的一次开机，可能开始接管。会话若停在 active、starting 或 "
                "needs_rollback，启动会先把那次回退做完。")
    return ("当前没有看到正在运行的接管，on_boot 不是 true，不会因为开机策略再开一轮接管。"
            "会话若停在 active、starting 或 needs_rollback，启动仍会先把那次回退做完，"
            "网络可能因此变化。")


def _finish(tier, required_tiers, checks, facts):
    required = [item for item in checks if item["required"]]
    if any(item["status"] == "fail" for item in required):
        result = "fail"
    elif any(item["status"] == "unknown" for item in required):
        result = "unknown"
    else:
        result = "pass"
    remediation = []
    for item in required:
        text = item.get("remediation")
        if text and text not in remediation:
            remediation.append(text)
    activity = facts.get("activity") or {}
    state = activity.get("state")
    if tier == "readonly":
        effects = {"preflight_mutates": False, "blocked_by_takeover_dependencies": False}
    elif tier == "takeover":
        effects = {"preflight_mutates": False, "command_may_change_network": True}
    else:
        rollback = True if state == "active" else None if state == "unknown" else False
        effects = {"preflight_mutates": False,
                   "later_restart_may_roll_back_active_takeover": rollback,
                   "later_start_may_takeover_on_new_boot": facts.get("on_boot") is True,
                   "later_start_may_finish_a_pending_rollback": True}
    return {"schema_version": SCHEMA_VERSION, "kind": "macos_preflight",
            "tier": tier, "result": result, "blocking": result != "pass",
            "required_tiers": list(required_tiers), "checks": checks,
            "remediation": remediation, "effects": effects}


def run(tier):
    if tier not in TIERS:
        raise ValueError("invalid_tier")
    if not host_is_darwin():
        return _not_applicable(tier)
    root = None
    try:
        import manager
        root = manager.ROOT
    except (OSError, ValueError, TypeError):
        root = None
    return assess(tier, collect(tier, root=root))


def for_daemon_lifecycle(root=None):
    if not host_is_darwin():
        return _not_applicable("daemon")
    if root is None:
        import manager
        root = manager.ROOT
    return assess("daemon", collect("daemon", root=root))


def for_foreground(options):
    if not host_is_darwin():
        return _not_applicable("takeover")
    return assess("takeover", collect("takeover", options=options or {}))


def for_installed_takeover(root=None):
    if not host_is_darwin():
        return _not_applicable("takeover")
    if root is None:
        import manager
        root = manager.ROOT
    return assess("takeover", collect("takeover", root=root))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(item in ("-h", "--help") for item in argv) or argv == ["help"]:
        sys.stdout.write(HELP)
        return 0 if argv else 2
    if not argv:
        tier = "readonly"
    elif len(argv) == 2 and argv[0] == "--tier" and argv[1] in TIERS:
        tier = argv[1]
    else:
        sys.stderr.write(HELP)
        return 2
    report = run(tier)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
