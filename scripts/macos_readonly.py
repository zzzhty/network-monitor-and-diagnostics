"""Opt-in, read-only macOS diagnostics for the existing collector.

The collector calls ``collect`` only when ``macos_readonly.enabled`` is true.
``observe`` is the explicit command. Neither path changes routes, DNS, proxy
settings, or Tailscale, and neither uses sudo. Linux and Windows get
``not_applicable`` and do not run the macOS command list.

Tailscale status is buffered up to the parser limit and then whitelist-filtered.
An over-limit or truncated body is discarded, not parsed. A VPS TCP target is
taken only from the monitor config. One successful connect is not tailnet,
route, DNS, or application health.
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import ipaddress
import json
import os
import re
import select
import signal
import socket
import subprocess
import sys
import time

import macos_coexist

SCHEMA_VERSION = 1
TAILSCALE_CANDIDATES = (
    "/usr/bin/tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
)
_FIXED_COMMANDS = (
    ("/usr/sbin/netstat", "-rn", "-f", "inet"),
    ("/usr/sbin/netstat", "-rn", "-f", "inet6"),
    ("/usr/sbin/scutil", "--dns"),
    ("/usr/sbin/scutil", "--proxy"),
)
_COMMAND_LIMITS = {
    _FIXED_COMMANDS[0]: 65536,
    _FIXED_COMMANDS[1]: 65536,
    _FIXED_COMMANDS[2]: 65536,
    _FIXED_COMMANDS[3]: 65536,
}
_PARSE_LIMIT = macos_coexist.TAILSCALE_STATUS_PARSE_LIMIT
_NETSTAT_TIMEOUT = 2
_SCUTIL_TIMEOUT = 2
_TAILSCALE_TIMEOUT = 3
_TCP_TIMEOUT = 2
_LISTENER_TIMEOUT = 1
_TAILNET4 = ipaddress.ip_network(macos_coexist.TAILNET_ROUTE_EXCLUSIONS[0])
_TAILNET6 = ipaddress.ip_network(macos_coexist.TAILNET_ROUTE_EXCLUSIONS[1])
_FAKE_IP = ipaddress.ip_network("198.18.0.0/16")
_NATIVE_TUN_RESOLVER = ipaddress.ip_address(macos_coexist.NATIVE_SYSTEM_DNS)
_MAGIC_DNS = ipaddress.ip_address("100.100.100.100")
_INTERFACE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,15}$")
_PUBLIC_ERRORS = {
    "tool_missing",
    "permission_denied",
    "timeout",
    "launch_error",
    "output_too_large",
    "invalid_text",
    "command_not_run",
    "command_failed",
    "truncated",
}
PHASE_2_NOT_IMPLEMENTED = (
    "config_generation",
    "pre_start_snapshot",
    "independent_watchdog",
    "idempotent_rollback",
    "cutover",
    "boot_autostart",
)

HELP = """\
usage: python3 scripts/macos_readonly.py observe [--config MONITOR.json]

Read-only macOS diagnostics. There is no cutover, restore, or autostart command.
On Linux and Windows the report status is not_applicable.
"""


def validate_settings(value):
    """Return the normalized opt-in block, or raise ValueError.

    ``None`` and a missing block mean disabled, with no VPS target. A hostname
    is rejected so this path never resolves DNS. Port 22 is rejected so the
    TCP check cannot be pointed at SSH.
    """
    if value is None:
        return {"enabled": False, "vps": None}
    if not isinstance(value, dict) or set(value) - {"enabled", "vps"}:
        raise ValueError("invalid_macos_readonly")
    enabled = value.get("enabled", False)
    if type(enabled) is not bool:
        raise ValueError("invalid_macos_readonly")
    vps = value.get("vps", None)
    if vps is None:
        return {"enabled": enabled, "vps": None}
    if not isinstance(vps, dict) or set(vps) - {"host", "port"}:
        raise ValueError("invalid_macos_readonly")
    host = vps.get("host")
    port = vps.get("port")
    if not isinstance(host, str) or _ip(host) is None:
        raise ValueError("invalid_macos_readonly")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid_macos_readonly")
    if port == 22:
        raise ValueError("ssh_port_not_allowed")
    return {"enabled": enabled, "vps": {"host": str(_ip(host)), "port": port}}


def collect(platform, settings, *, runner=None, tcp=None, exists=None, invocation="collector"):
    """Build one read-only report. The default runner is used only on macOS."""
    settings = validate_settings(settings)
    invoked = invocation if invocation in {"cli", "collector"} else "collector"
    if platform != "macos":
        return _report(platform, settings, "not_applicable", "not_applicable", invoked)
    if not settings["enabled"]:
        return _report(platform, settings, "not_enabled", "not_enabled", invoked)
    if runner is None:
        runner = execute
    if tcp is None:
        tcp = tcp_connect
    if exists is None:
        exists = _executable
    return _observe(platform, settings, runner, tcp, exists, invoked)


def execute(argv, timeout):
    """Run one allowlisted argv. Any other argv is rejected before a process starts."""
    key = tuple(argv)
    limit = _limit_for(key)
    if limit is None:
        raise ValueError("command_not_allowlisted")
    code, data, error = bounded_run(list(key), timeout, limit)
    if error:
        return code, "", error if error in _PUBLIC_ERRORS else "command_failed"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return code, "", "invalid_text"
    return code, text, None


def bounded_run(argv, timeout, limit):
    """Read at most ``limit`` bytes. Over-limit and timeout discard the body."""
    _check_bounds(argv, timeout, limit)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    try:
        proc = subprocess.Popen(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError:
        return None, b"", "tool_missing"
    except PermissionError:
        return None, b"", "permission_denied"
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return None, b"", "permission_denied"
        return None, b"", "launch_error"
    chunks = []
    total = 0
    error = None
    deadline = time.monotonic() + float(timeout)
    try:
        while total <= limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = "timeout"
                break
            try:
                ready, _, _ = select.select([proc.stdout], [], [], remaining)
            except (ValueError, OSError):
                error = "launch_error"
                break
            if not ready:
                error = "timeout"
                break
            want = min(65536, limit + 1 - total)
            if want <= 0:
                break
            block = proc.stdout.read(want)
            if not block:
                break
            chunks.append(block)
            total += len(block)
        if error is None and total > limit:
            error = "output_too_large"
    finally:
        if proc.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(OSError):
            if proc.stdout is not None:
                proc.stdout.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)
    if error:
        return None, b"", error
    return proc.returncode, b"".join(chunks), None


def tcp_connect(host, port, timeout):
    """One TCP connect to an IP literal. No DNS, no login, no port 22."""
    addr = _ip(host)
    if addr is None or type(port) is not int or port == 22 or not 1 <= port <= 65535:
        return {"status": "refused_by_policy", "elapsed_ms": None}
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0 or timeout > 30:
        return {"status": "error", "elapsed_ms": None}
    family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    started = time.monotonic()
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(float(timeout))
        sock.connect((str(addr), port))
    except socket.timeout:
        status = "timeout"
    except ConnectionRefusedError:
        status = "refused"
    except OSError as exc:
        if exc.errno in (errno.ETIMEDOUT, getattr(errno, "WSAETIMEDOUT", -1)):
            status = "timeout"
        elif exc.errno in (
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            errno.ECONNRESET,
            errno.EADDRNOTAVAIL,
            getattr(errno, "WSAEHOSTUNREACH", -1),
        ):
            status = "unreachable"
        else:
            status = "error"
    else:
        status = "ok"
    finally:
        if sock is not None:
            sock.close()
    return {"status": status, "elapsed_ms": _elapsed_ms(started)}


def main(argv=None):
    """Print one report. Exit 2 is a usage or config error, not a network fault."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        sys.stdout.write(HELP)
        return 0 if args else 2
    if args[0] != "observe":
        sys.stdout.write(HELP)
        return 2
    config_path = None
    rest = args[1:]
    if rest[:1] == ["--config"] and len(rest) == 2:
        config_path = rest[1]
        rest = []
    if rest:
        sys.stdout.write(HELP)
        return 2
    settings = {"enabled": True, "vps": None}
    if config_path is not None:
        import nmd_monitor

        try:
            loaded = nmd_monitor.load_config(config_path)["macos_readonly"]
        except (OSError, ValueError) as exc:
            sys.stderr.write((str(exc) or "config_error") + "\n")
            return 2
        settings = {"enabled": True, "vps": loaded["vps"]}
    import nmd_platform

    report = collect(nmd_platform.name(), settings, invocation="cli")
    sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return 0


def _observe(platform, settings, runner, tcp, exists, invocation):
    commands = []
    vps = settings["vps"]
    target = _ip(vps["host"]) if vps else None
    inet, inet_error = _command(runner, commands, _FIXED_COMMANDS[0], _NETSTAT_TIMEOUT, 65536)
    inet6, inet6_error = (None, None)
    if target is not None and target.version == 6:
        inet6, inet6_error = _command(runner, commands, _FIXED_COMMANDS[1], _NETSTAT_TIMEOUT, 65536)
    dns_text, dns_error = _command(runner, commands, _FIXED_COMMANDS[2], _SCUTIL_TIMEOUT, 65536)
    proxy_text, proxy_error = _command(runner, commands, _FIXED_COMMANDS[3], _SCUTIL_TIMEOUT, 65536)
    tailscale_path = next((path for path in TAILSCALE_CANDIDATES if exists(path)), None)
    if tailscale_path is None:
        tailscale = _tailscale_result("tool_missing")
    else:
        argv = (tailscale_path, "status", "--json")
        text, error, code = _command(runner, commands, argv, _TAILSCALE_TIMEOUT, _PARSE_LIMIT, with_code=True)
        tailscale = _tailscale_from_command(text, error, code)
    routes = _routes(inet, inet_error, inet6, inet6_error, target)
    dns = _dns(dns_text, dns_error)
    proxy = _proxy(proxy_text, proxy_error, tcp)
    vps_tcp = _vps(vps, tcp)
    sections = (tailscale, routes, dns, proxy, vps_tcp)
    report = _report(platform, settings, _rollup(sections), None, invocation)
    report["commands"] = [list(argv) for argv in commands]
    report["tailscale"] = tailscale
    report["routes"] = routes
    report["dns"] = dns
    report["system_proxy"] = proxy
    report["vps_tcp"] = vps_tcp
    return report


def _command(runner, commands, argv, timeout, limit, with_code=False):
    commands.append(tuple(argv))
    code, text, error = runner(list(argv), timeout)
    if error:
        text = ""
    elif not isinstance(text, str):
        text, error = "", "invalid_text"
    elif len(text.encode("utf-8")) > limit:
        text, error = "", "output_too_large"
    if with_code:
        return text, error, code
    if error:
        return None, _public_error(error)
    if code != 0:
        return None, "command_failed"
    return text, None


def _tailscale_from_command(text, error, code):
    if error == "truncated":
        return macos_coexist.normalize_tailscale_status("", returncode=0, truncated=True)
    if error:
        return _tailscale_result(_public_error(error))
    try:
        return macos_coexist.normalize_tailscale_status(text, returncode=code, truncated=False)
    except ValueError:
        return _tailscale_result("command_failed")


def _tailscale_result(reason, availability=None):
    if availability is None:
        availability = reason if reason in {"not_applicable", "not_enabled"} else "unavailable"
    return {
        "availability": availability,
        "reason": reason,
        "backend_state": None,
        "self_online": None,
        "peer_summary": None,
        "peer_count": None,
        "peers_online": None,
    }


def _routes(inet, inet_error, inet6, inet6_error, target):
    blank = _blank_routes("unavailable", None)
    if inet_error:
        blank["reason"] = inet_error
        blank["tailnet_route_status"] = "unavailable"
        return blank
    parsed = _parse_routes(inet, 4)
    if parsed is None:
        blank["status"] = "unknown"
        blank["reason"] = "invalid_route_output"
        blank["tailnet_route_status"] = "unknown"
        return blank
    defaults = [iface for network, iface in parsed if network.prefixlen == 0]
    ipv6_status = "not_applicable"
    tailnet_status = "not_configured"
    tailnet_interface = None
    reason = None
    status = "observed"
    if target is None:
        family_rows = parsed
    elif target.version == 4:
        family_rows = parsed
    else:
        family_rows = None
        if inet6_error:
            status = "unavailable"
            reason = inet6_error
            tailnet_status = "unavailable"
            ipv6_status = "unavailable"
        else:
            family_rows = _parse_routes(inet6, 6)
            ipv6_status = "observed" if family_rows is not None else "unknown"
            if family_rows is None:
                status = "unknown"
                reason = "invalid_route_output"
                tailnet_status = "unknown"
    if target is not None and family_rows is not None:
        tailnet_interface, match_reason = _select_route(family_rows, target)
        if match_reason:
            tailnet_status = "unknown"
            status = "unknown"
            reason = match_reason
        else:
            tailnet_status = "observed"
    if len(defaults) > 32:
        status = "unknown"
        reason = "too_many_defaults"
        defaults = []
    return {
        "status": status,
        "reason": reason,
        "default_interfaces": sorted(set(defaults)),
        "default_route_count": len(defaults),
        "tailnet_interface": tailnet_interface,
        "tailnet_route_status": tailnet_status,
        "interface_discovery": "dynamic",
        "ipv6_default_status": ipv6_status,
    }


def _parse_routes(text, family):
    if not isinstance(text, str) or not text.strip():
        return None
    lines = [line.split() for line in text.splitlines() if line.strip()]
    header = next((i for i, fields in enumerate(lines)
                   if len(fields) >= 4 and fields[:3] == ["Destination", "Gateway", "Flags"] and "Netif" in fields), None)
    if header is None:
        return None
    index = lines[header].index("Netif")
    rows = []
    for fields in lines[header + 1:]:
        if len(fields) <= index:
            return None
        iface = fields[index]
        if not _INTERFACE_NAME.fullmatch(iface):
            continue
        network = _parse_destination(fields[0], family)
        if network is not None:
            rows.append((network, iface))
    return rows or None


def _parse_destination(token, family):
    if token == "default":
        return ipaddress.ip_network("0.0.0.0/0" if family == 4 else "::/0")
    if family == 6:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return None
        return network if network.version == 6 else None
    if token in {"0.0.0.0", "0.0.0.0/0"}:
        return ipaddress.ip_network("0.0.0.0/0")
    prefix = None
    left = token
    if "/" in token:
        left, prefix_text = token.split("/", 1)
        if not prefix_text.isdigit():
            return None
        prefix = int(prefix_text)
    parts = left.split(".")
    if not 1 <= len(parts) <= 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return None
    if prefix is None:
        prefix = {1: 8, 2: 16, 3: 24, 4: 32}[len(parts)]
    while len(parts) < 4:
        parts.append("0")
    try:
        return ipaddress.ip_network(".".join(parts) + "/" + str(prefix), strict=False)
    except ValueError:
        return None


def _select_route(rows, target):
    best = []
    best_len = -1
    for network, iface in rows:
        if target not in network:
            continue
        if network.prefixlen > best_len:
            best = [iface]
            best_len = network.prefixlen
        elif network.prefixlen == best_len and iface not in best:
            best.append(iface)
    if not best:
        return None, "no_route"
    if len(best) != 1:
        return None, "ambiguous_route"
    return best[0], None


def _dns(text, error):
    if error:
        return _blank_dns("unavailable", error)
    if not isinstance(text, str) or ("resolver #" not in text and "nameserver[" not in text):
        return _blank_dns("unknown", "invalid_dns_output")
    count = 0
    fake = magic = native = False
    non_ip = False
    for line in text.splitlines():
        match = re.match(r"\s*nameserver\[\d+\]\s*:\s*(\S+)\s*$", line)
        if not match:
            continue
        addr = _ip(match.group(1))
        if addr is None:
            non_ip = True
            continue
        count += 1
        fake = fake or addr in _FAKE_IP
        native = native or addr == _NATIVE_TUN_RESOLVER
        magic = magic or addr == _MAGIC_DNS
    return {
        "status": "unknown" if non_ip else "observed",
        "reason": "non_ip_nameserver" if non_ip else None,
        "nameserver_count": count,
        "fake_ip_resolver_present": fake,
        "native_tun_resolver_present": native,
        "magic_dns_present": magic,
    }


def _proxy(text, error, tcp):
    if error:
        return _blank_proxy("unavailable", error)
    parsed = _parse_proxy(text)
    if parsed is None:
        return _blank_proxy("unknown", "invalid_proxy_output")
    view = {}
    listeners = {}
    hidden_disabled = 0
    missing = []
    extra_warnings = []
    for protocol, prefix in (("http", "HTTP"), ("https", "HTTPS"), ("socks", "SOCKS")):
        enable = parsed["values"].get(prefix + "Enable")
        if enable not in {"0", "1"}:
            missing.append(protocol)
            continue
        server = _ip(parsed["values"].get(prefix + "Proxy", ""))
        port = _port(parsed["values"].get(prefix + "Port"))
        enabled = enable == "1"
        loopback = server is not None and server.is_loopback and port is not None and port != 22
        if not enabled:
            if loopback:
                view[protocol] = {"enabled": "No", "server": str(server), "port": port}
            else:
                view[protocol] = {"enabled": "No"}
                if parsed["values"].get(prefix + "Proxy"):
                    hidden_disabled += 1
            continue
        if loopback:
            endpoint = str(server) + ":" + str(port)
            try:
                outcome = tcp(str(server), port, _LISTENER_TIMEOUT)
            except AssertionError:
                raise
            except Exception:
                outcome = {"status": "error"}
            listeners[endpoint] = isinstance(outcome, dict) and outcome.get("status") == "ok"
            view[protocol] = {"enabled": "Yes", "server": str(server), "port": port}
        else:
            code = "proxy_enabled_unchecked" if server is not None else "proxy_target_unparsed"
            extra_warnings.append({
                "code": code, "protocol": protocol, "endpoint": None, "read_only": True,
            })
    if not view and not extra_warnings:
        blank = _blank_proxy("unknown", "missing_field")
        blank["missing_protocols"] = missing or ["http", "https", "socks"]
        return blank
    try:
        classified = macos_coexist.classify_system_proxies({
            **view,
            "bypass": parsed["bypass"],
            "listener_open": listeners,
        })
    except ValueError:
        return _blank_proxy("unknown", "invalid_proxy_output")
    warnings = [_public_warning(item) for item in classified["warnings"]]
    warnings.extend(extra_warnings)
    saved = []
    for item in classified["disabled_saved_addresses"]:
        endpoint = item.get("endpoint")
        if _loopback_endpoint(endpoint):
            saved.append({"protocol": item.get("protocol"), "endpoint": endpoint})
    return {
        "status": "observed",
        "reason": None,
        "warnings": warnings,
        "actions": [],
        "disabled_saved_address_is_fault": False,
        "disabled_saved": saved,
        "disabled_non_loopback_count": hidden_disabled,
        "bypass_count": len(parsed["bypass"]) if parsed["bypass_known"] else None,
        "bypass_known": parsed["bypass_known"],
        "bypass_reset": False,
        "auto_disable": False,
        "mutates_network": False,
        "missing_protocols": missing,
    }


def _parse_proxy(text):
    if not isinstance(text, str) or not text.strip():
        return None
    values = {}
    bypass = []
    in_list = False
    saw_value = False
    bypass_known = False
    for line in text.splitlines():
        if "ExceptionsList" in line and "<array>" in line:
            bypass_known = True
            in_list = not line.strip().endswith("}")
            continue
        if in_list:
            if line.strip() == "}":
                in_list = False
                continue
            match = re.match(r"\s*\d+\s*:\s*(\S+)\s*$", line)
            if match:
                bypass.append(match.group(1))
            continue
        match = re.match(r"\s*([A-Za-z][A-Za-z0-9]*)\s*:\s*(\S+)\s*$", line)
        if match:
            saw_value = True
            values[match.group(1)] = match.group(2)
    if not saw_value:
        return None
    return {"values": values, "bypass": bypass, "bypass_known": bypass_known}


def _vps(vps, tcp):
    if vps is None:
        blank = _blank_vps("not_configured", None)
        return blank
    host = vps["host"]
    port = vps["port"]
    try:
        outcome = tcp(host, port, _TCP_TIMEOUT)
    except Exception:
        outcome = {"status": "error", "elapsed_ms": None}
    status = outcome.get("status") if isinstance(outcome, dict) else None
    if status not in {"ok", "timeout", "refused", "unreachable", "error", "refused_by_policy"}:
        status = "error"
    elapsed = outcome.get("elapsed_ms") if isinstance(outcome, dict) else None
    if type(elapsed) is not int or elapsed < 0 or elapsed > 120000:
        elapsed = None
    addr = _ip(host)
    if addr in _TAILNET4:
        kind = "tailnet_ipv4"
    elif addr in _TAILNET6:
        kind = "tailnet_ipv6"
    else:
        kind = "other"
    return {
        "status": status,
        "reason": None,
        "port": port,
        "address_class": kind,
        "host_fingerprint": hashlib.sha256(str(addr).encode("utf-8")).hexdigest()[:16],
        "elapsed_ms": elapsed,
        "business_stable": False,
        "means_tailnet_online": False,
        "means_route_ok": False,
        "means_dns_ok": False,
        "means_app_ok": False,
    }


def _rollup(sections):
    tailscale, routes, dns, proxy, vps = sections
    states = []
    availability = tailscale["availability"]
    if availability in {"healthy", "offline"}:
        states.append("observed")
    elif availability == "unknown":
        states.append("unknown")
    else:
        states.append("unavailable")
    states.extend(section["status"] for section in (routes, dns, proxy))
    vps_status = vps["status"]
    if vps_status in {"ok", "timeout", "refused", "unreachable", "error", "not_configured"}:
        states.append("observed")
    elif vps_status == "unknown":
        states.append("unknown")
    else:
        states.append("unavailable")
    if all(item == "observed" for item in states):
        return "observed"
    if any(item == "observed" for item in states) or any(item == "unknown" for item in states):
        return "partial"
    return "unavailable"


def _report(platform, settings, status, reason, invocation):
    child = "not_applicable" if status == "not_applicable" else "not_enabled"
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "macos_readonly",
        "platform": platform,
        "invocation": invocation,
        "enabled": settings["enabled"],
        "status": status,
        "reason": reason,
        "mutates_network": False,
        "uses_sudo": False,
        "report_is_health": False,
        "business_stable": False,
        "real_machine_verified": False,
        "overnight_23s_root_cause_fixed": False,
        "phase_2_implemented": False,
        "actions": [],
        "commands": [],
        "tailscale": _tailscale_result(child, child),
        "routes": _blank_routes(child, child),
        "dns": _blank_dns(child, child),
        "system_proxy": _blank_proxy(child, child),
        "vps_tcp": _blank_vps(child, child),
    }


def _blank_routes(status, reason):
    return {
        "status": status,
        "reason": reason,
        "default_interfaces": [],
        "default_route_count": None,
        "tailnet_interface": None,
        "tailnet_route_status": status,
        "interface_discovery": "dynamic",
        "ipv6_default_status": "not_applicable",
    }


def _blank_dns(status, reason):
    return {
        "status": status,
        "reason": reason,
        "nameserver_count": None,
        "fake_ip_resolver_present": None,
        "native_tun_resolver_present": None,
        "magic_dns_present": None,
    }


def _blank_proxy(status, reason):
    return {
        "status": status,
        "reason": reason,
        "warnings": [],
        "actions": [],
        "disabled_saved_address_is_fault": False,
        "disabled_saved": [],
        "disabled_non_loopback_count": None,
        "bypass_count": None,
        "bypass_known": False,
        "bypass_reset": False,
        "auto_disable": False,
        "mutates_network": False,
        "missing_protocols": [],
    }


def _blank_vps(status, reason):
    return {
        "status": status,
        "reason": reason,
        "port": None,
        "address_class": None,
        "host_fingerprint": None,
        "elapsed_ms": None,
        "business_stable": False,
        "means_tailnet_online": False,
        "means_route_ok": False,
        "means_dns_ok": False,
        "means_app_ok": False,
    }


def _public_warning(item):
    endpoint = item.get("endpoint")
    if not _loopback_endpoint(endpoint):
        endpoint = None
    return {
        "code": item.get("code"),
        "protocol": item.get("protocol"),
        "endpoint": endpoint,
        "read_only": True,
    }


def _public_error(error):
    return error if error in _PUBLIC_ERRORS else "command_failed"


def _limit_for(argv):
    if argv in _COMMAND_LIMITS:
        return _COMMAND_LIMITS[argv]
    if (
        len(argv) == 3
        and argv[0] in TAILSCALE_CANDIDATES
        and argv[1:] == ("status", "--json")
        and _executable(argv[0])
    ):
        return _PARSE_LIMIT
    return None


def _executable(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _check_bounds(argv, timeout, limit):
    if (
        not isinstance(argv, (list, tuple))
        or not argv
        or any(not isinstance(item, str) or not item or "\x00" in item for item in argv)
    ):
        raise ValueError("invalid_argv")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        raise ValueError("invalid_timeout")
    if type(limit) is not int or not 1 <= limit <= _PARSE_LIMIT:
        raise ValueError("invalid_limit")


def _ip(value):
    if not isinstance(value, str) or not value or any(ord(char) < 33 or ord(char) > 126 for char in value):
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _port(value):
    if isinstance(value, str) and value.isdigit():
        number = int(value)
        if 1 <= number <= 65535:
            return number
    return None


def _loopback_endpoint(endpoint):
    if not isinstance(endpoint, str):
        return False
    host, separator, port = endpoint.rpartition(":")
    addr = _ip(host)
    return bool(separator) and port.isdigit() and addr is not None and addr.is_loopback


def _elapsed_ms(started):
    return max(0, min(120000, int((time.monotonic() - started) * 1000)))


if __name__ == "__main__":
    raise SystemExit(main())
