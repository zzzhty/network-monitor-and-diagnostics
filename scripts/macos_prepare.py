"""Phase A of the self-managed mihomo macOS route: prepare, do not switch.

Offline, deterministic generation of a mihomo-loadable YAML config from the
experiment profile plus user inputs, and a read-only pre-start system-state
snapshot for a future idempotent rollback. No sudo, no process start (except
the read-only observation commands listed here), no route, DNS, proxy, or
Tailscale mutation, and nothing auto-enabled. mihomo is never run from this
module: config validation is structural plus the offline rule engine, and the
real-machine ``mihomo -t`` check is a later phase's step.

The snapshot file keeps real values (exit node id, resolvers, gateways) and is
private to the NMD state directory, the same trust domain as the egress source
registry. Anything printed to stdout goes through ``summarize_snapshot`` and
keeps the established redaction: counts, booleans, and fingerprints only.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

import macos_coexist
import macos_readonly

SCHEMA_VERSION = 1
PHASE_A_IMPLEMENTED = ("config_generation", "pre_start_snapshot")
# Drift guard: the readonly module keeps the canonical remaining list.
PHASE_2_REMAINING = ()

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROXY_NAME = "VPS"
PLACEHOLDER_INPUTS = {
    "proxy_name": DEFAULT_PROXY_NAME,
    "server": macos_coexist.PLACEHOLDER_SOCKS_HOST,
    "port": macos_coexist.PLACEHOLDER_SOCKS_PORT,
}

_TAILNET4 = ipaddress.ip_network(macos_coexist.TAILNET_ROUTE_EXCLUSIONS[0])
_TAILNET6 = ipaddress.ip_network(macos_coexist.TAILNET_ROUTE_EXCLUSIONS[1])
_FAKE_IP = ipaddress.ip_network("198.18.0.0/16")
_PROXY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_RESERVED_PROXY_NAMES = {"DIRECT", "REJECT"}

# Guardrails first in the generated rule list. macOS omits PROCESS-NAME rules.
GUARDRAIL_RULES = (
    "DOMAIN-SUFFIX,tailscale.com,DIRECT",
    "DOMAIN-SUFFIX,tailscale.io,DIRECT",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve",
)

_HEADER = (
    "# NMD macOS mihomo 实验配置 — Phase A 生成，勿手改\n"
    "# 203.0.113.20 是文档占位，不是实机地址\n"
    "# 本配置未做实机验证；实机启动前先运行 mihomo -t（后续阶段步骤）。\n"
)

# --- snapshot: read-only commands, allowlisted before any spawn -------------

# All users, full `comm` paths. Short names (`ucomm`, `-c`) truncate or are a
# different field; a current-uid filter misses root and still grows past a cap.
_PS_SNAPSHOT_ARGV = ("/bin/ps", "-axo", "pid=,comm=")
_SNAPSHOT_COMMANDS = (
    (("/usr/sbin/netstat", "-rn", "-f", "inet"), 2),
    (("/usr/sbin/netstat", "-rn", "-f", "inet6"), 2),
    (("/usr/sbin/scutil", "--dns"), 2),
    (("/usr/sbin/scutil", "--proxy"), 2),
    (_PS_SNAPSHOT_ARGV, 2),
)
_SETUP = "/usr/sbin/networksetup"
# Read forms only. A write flag is absent here, so it cannot match.
_SETUP_READS = {"-listallnetworkservices": 0, "-getdnsservers": 1}
_MAX_SERVICES = 8
_SETUP_TIMEOUT = 2
_TAILSCALE_TIMEOUT = 3
_TAILSCALE_STATUS_LIMIT = macos_coexist.TAILSCALE_STATUS_PARSE_LIMIT
_PREFS_LIMIT = 65536
_FIXED_LIMIT = 65536
# A busy Darwin 27 host printed 78965 bytes / 853 lines of full paths (median
# comm 84 bytes, max 220) in about 20ms, exit 0, empty stderr, valid UTF-8.
# The 64KiB cap read 65537 bytes, discarded the body, and the snapshot became
# unknown. 1MiB is the shared reader's ceiling and about 13x that table.
# Past it the body is dropped whole: a prefix is not a complete observation.
# Other snapshot commands stay at 64KiB.
_PS_SNAPSHOT_LIMIT = 1024 * 1024
_PREFS_KEYS = ("ExitNodeID", "ExitNodeIP", "CorpDNS", "RouteAll",
               "ExitNodeAllowLANAccess", "WantRunning")

HELP = """\
usage: python3 scripts/macos_prepare.py config --inputs INPUTS.json [--profile PROFILE.json] (--out PATH | --stdout)
       python3 scripts/macos_prepare.py snapshot [--state-dir DIR]

Phase A of the self-managed mihomo macOS route: offline config generation and
a read-only pre-start snapshot. There is no cutover, restore, watchdog, or
autostart command, no sudo, and no network change. On non-macOS platforms the
snapshot status is not_applicable and no command runs.
"""


# --- config generation (pure; no I/O) ----------------------------------------


def _proxy_name(value):
    if not isinstance(value, str) or not _PROXY_NAME.fullmatch(value):
        raise ValueError("invalid_proxy_name")
    if value.upper() in _RESERVED_PROXY_NAMES:
        raise ValueError("invalid_proxy_name")
    return value


def validate_inputs(value):
    """Return normalized inputs, or raise ValueError.

    ``server`` is a tailnet IP literal (the VPS over Tailscale) or exactly the
    documentation placeholder; mixing placeholder and real values is rejected.
    Port 22 is rejected so this path can never aim at SSH.
    """
    if not isinstance(value, dict):
        raise ValueError("invalid_inputs")
    allowed = {"server", "port", "proxy_name"}
    if set(value) - allowed or not {"server", "port"} <= set(value):
        raise ValueError("invalid_inputs")
    server, port = value["server"], value["port"]
    if not isinstance(server, str):
        raise ValueError("invalid_server")
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        address = None
    placeholder_server = server == macos_coexist.PLACEHOLDER_SOCKS_HOST
    if not placeholder_server:
        if address is None or not (address in _TAILNET4 or address in _TAILNET6):
            raise ValueError("invalid_server")
    if type(port) is not int or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    if port == 22:
        raise ValueError("ssh_port_not_allowed")
    if placeholder_server and port != macos_coexist.PLACEHOLDER_SOCKS_PORT:
        # The placeholder anchor is the RFC 5737 server address, which can
        # never be a real tailnet IP; port 1080 is the standard SOCKS port and
        # perfectly valid with a real server. Only the checked-in example pair
        # must stay exactly (203.0.113.20, 1080).
        raise ValueError("placeholder_server_requires_placeholder_port")
    return {"proxy_name": _proxy_name(value.get("proxy_name", DEFAULT_PROXY_NAME)),
            "server": server, "port": port}


def guardrail_rules():
    """Constant guardrail entries: Tailscale control planes and the tailnet."""
    return list(GUARDRAIL_RULES)


def build_rules(profile):
    """Guardrails plus the profile rules, with the domain fix placed correctly."""
    rules = profile["rules"]
    if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
        raise ValueError("invalid_profile_rules")
    return macos_coexist.insert_overseas_domain_rules(
        guardrail_rules() + rules, profile["egress"]["group"])


def build_mihomo_document(profile, inputs, *, geo_auto_update=True):
    """The mihomo document with a fixed key order; deterministic by construction.

    The short acceptance run turns geo auto-update off so a copied geodata
    directory is not refreshed from the network during those two minutes.
    Every other caller keeps the previous default.
    """
    dns_mode = profile["dns_mode"]["selected"]
    return {
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "tcp-concurrent": True,
        "unified-delay": True,
        "geo-auto-update": bool(geo_auto_update),
        "geo-update-interval": 72,
        "tun": {
            "enable": True,
            "stack": "mixed",
            "auto-route": True,
            "auto-detect-interface": True,
            "dns-hijack": ["any:53"],
            "dns-mode": dns_mode,
            "route-exclude-address": list(macos_coexist.TAILNET_ROUTE_EXCLUSIONS),
        },
        "dns": {
            "enable": True,
            "listen": "127.0.0.1:1053",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["+.tailscale.com", "+.tailscale.io", "+.ts.net",
                               "+.lan", "+.local", "+.home.arpa", "localhost.*"],
            "nameserver-policy": {"+.ts.net": "100.100.100.100"},
            "nameserver": ["223.5.5.5", "119.29.29.29"],
        },
        "sniffer": {
            "enable": True,
            "sniff": {"TLS": {"ports": [443, 8443]}, "HTTP": {"ports": [80]}},
        },
        "proxies": [{
            "name": inputs["proxy_name"],
            "type": "socks5",
            "server": inputs["server"],
            "port": inputs["port"],
            "udp": True,
        }],
        "proxy-groups": [{
            "name": profile["egress"]["group"],
            "type": "select",
            "proxies": [inputs["proxy_name"]],
        }],
        "rules": build_rules(profile),
    }


def validate_document(document, exit_group):
    """Empty list means the document is structurally sound for later ``-t``."""
    errors = []
    if not macos_coexist.mihomo_would_load(document):
        errors.append("document is not a bare mihomo shape")
    errors.extend(macos_coexist.validate_rule_order(document.get("rules") or [], exit_group))
    rules = document.get("rules") or []
    if not rules or rules[-1] != f"MATCH,{exit_group}":
        errors.append("rules must end with MATCH to the exit group")
    tun = document.get("tun", {})
    if tun.get("route-exclude-address") != list(macos_coexist.TAILNET_ROUTE_EXCLUSIONS):
        errors.append("tun route exclusions must cover the tailnet")
    for key in ("device", "iproute2-table-index", "iproute2-rule-index"):
        if key in tun:
            errors.append(f"tun must not pin {key}")
    proxies = document.get("proxies") or []
    if not proxies or proxies[0].get("type") != "socks5" or proxies[0].get("udp") is not True:
        errors.append("the single proxy must be socks5 with udp")
    if proxies and "interface-name" in proxies[0]:
        errors.append("the proxy must not pin an interface")
    groups = document.get("proxy-groups") or []
    if not groups or groups[0].get("name") != exit_group:
        errors.append("the first proxy group must be the exit group")
    elif proxies and groups[0].get("proxies") != [proxies[0].get("name")]:
        errors.append("the exit group must select exactly the proxy")
    if tun.get("dns-mode") not in ("native", "disabled"):
        errors.append("tun dns-mode must be native or disabled")
    for value in document.get("dns", {}).get("nameserver-policy", {}).values():
        if isinstance(value, str) and "#" in value:
            errors.append("nameserver policy must not bind an interface")
    errors.extend(macos_coexist.find_hardcoded_utun(document))
    return errors


_SAFE_SCALAR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*$")
_BOOL_LIKE = {"true", "false", "yes", "no", "on", "off", "null", "~"}


def _scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if _SAFE_SCALAR.match(value) and value.lower() not in _BOOL_LIKE:
            return value
        return "'" + value.replace("'", "''") + "'"
    raise ValueError("unsupported yaml scalar")


def _emit_mapping(node, indent, lines):
    pad = " " * indent
    for key, value in node.items():
        if not isinstance(key, str):
            raise ValueError("yaml keys must be strings")
        scalar_key = _scalar(key)
        if isinstance(value, dict):
            if value:
                lines.append(f"{pad}{scalar_key}:")
                _emit_mapping(value, indent + 2, lines)
            else:
                lines.append(f"{pad}{scalar_key}: {{}}")
        elif isinstance(value, list):
            if value:
                lines.append(f"{pad}{scalar_key}:")
                _emit_sequence(value, indent + 2, lines)
            else:
                lines.append(f"{pad}{scalar_key}: []")
        else:
            lines.append(f"{pad}{scalar_key}: {_scalar(value)}")


def _emit_sequence(node, indent, lines):
    pad = " " * indent
    for item in node:
        if isinstance(item, dict):
            if not item:
                lines.append(f"{pad}- {{}}")
                continue
            sub = []
            _emit_mapping(item, indent + 2, sub)
            lines.append(f"{pad}- {sub[0].lstrip()}")
            lines.extend(sub[1:])
        else:
            lines.append(f"{pad}- {_scalar(item)}")


def dump_yaml(document):
    """Deterministic block YAML for the document shapes this module builds."""
    if not isinstance(document, dict):
        raise ValueError("yaml document must be a mapping")
    lines = []
    _emit_mapping(document, 0, lines)
    return "\n".join(lines) + "\n"


def render_config(profile, inputs, *, geo_auto_update=True):
    """Validate the whole chain, then return header + YAML text."""
    errors = macos_coexist.validate_experiment_profile(profile)
    if errors:
        raise ValueError("invalid_experiment_profile: " + "; ".join(errors))
    normalized = validate_inputs(inputs)
    document = build_mihomo_document(profile, normalized, geo_auto_update=geo_auto_update)
    errors = validate_document(document, profile["egress"]["group"])
    if errors:
        raise ValueError("invalid_document: " + "; ".join(errors))
    return _HEADER + dump_yaml(document)


def _inside_repository(path, repo_root):
    return path == repo_root or repo_root in path.parents


def _create_private_parents(path):
    missing, current = [], path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir()
        os.chmod(directory, 0o700)


def _atomic_private_write(directory, name, payload):
    fd, temporary = tempfile.mkstemp(dir=str(directory), prefix="." + name + ".")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, directory / name)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def write_config(text, out_path, *, repo_root=REPO_ROOT):
    """Write the config outside the checkout only; 0700 dirs, 0600 file."""
    path = Path(out_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    if _inside_repository(path, repo_root.resolve()):
        raise ValueError("output_inside_repository")
    _create_private_parents(path.parent)
    _atomic_private_write(path.parent, path.name, text.encode())
    return path


# --- snapshot: read-only observation, private file ---------------------------


def _limit_for(key):
    if key == _PS_SNAPSHOT_ARGV:
        return _PS_SNAPSHOT_LIMIT
    for argv, _ in _SNAPSHOT_COMMANDS:
        if key == argv:
            return _FIXED_LIMIT
    if key[0:1] == (_SETUP,):
        rest = key[1:]
        for flag, arity in _SETUP_READS.items():
            if len(rest) == arity + 1 and rest[0] == flag:
                return _FIXED_LIMIT
    if key[0] in macos_readonly.TAILSCALE_CANDIDATES:
        if key[1:] == ("status", "--json"):
            return _TAILSCALE_STATUS_LIMIT
        if key[1:] == ("debug", "prefs"):
            return _PREFS_LIMIT
    # One process's start time and argv. The pid is a canonical integer, so
    # this cannot become ``ps`` with a free-form selector.
    if (len(key) == 5 and key[0:2] == ("/bin/ps", "-p")
            and key[3:] == ("-o", "lstart=,args=")):
        pid_text = key[2]
        if pid_text.isdigit():
            pid = int(pid_text)
            if 1 < pid <= 2 ** 31 - 1 and str(pid) == pid_text:
                return _FIXED_LIMIT
    return None


def execute(argv, timeout):
    """Run one allowlisted argv via the shared bounded runner. No other spawn."""
    key = tuple(argv)
    limit = _limit_for(key)
    if limit is None:
        raise ValueError("command_not_allowlisted")
    code, data, error = macos_readonly.bounded_run(list(key), timeout, limit)
    if error:
        return code, "", error if error in macos_readonly._PUBLIC_ERRORS else "command_failed"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return code, "", "invalid_text"
    return code, text, None


def _first_tailscale(exists):
    for candidate in macos_readonly.TAILSCALE_CANDIDATES:
        if exists(candidate):
            return candidate
    return None


def _run(runner, argv, timeout, commands):
    commands.append(list(argv))
    return runner(list(argv), timeout)


def _parse_prefs(code, text, error):
    result = {"status": "unavailable", "reason": None}
    if error:
        return dict(result, reason=error)
    if code != 0:
        return dict(result, reason="command_failed")
    try:
        document = json.loads(text)
    except ValueError:
        return dict(result, reason="invalid_json")
    if not isinstance(document, dict):
        return dict(result, reason="invalid_json")
    prefs = {key: document.get(key) for key in _PREFS_KEYS if key in document}
    if "ExitNodeID" not in prefs and "ExitNodeIP" not in prefs:
        return dict(result, reason="missing_exit_node_fields")
    prefs["status"] = "observed"
    prefs["reason"] = None
    return prefs


# Official `tailscale set --exit-node` (CLI 1.104) accepts an IP, a MagicDNS
# base name, or auto:any. auto:any selects whichever exit is available, so it
# cannot restore one pinned node. A StableNodeID matches none of those forms.
_EXIT_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _ip_or_none(value):
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def exit_identity(prefs):
    """Stable id and IP from prefs. Empty strings are absent, not selected."""
    if not isinstance(prefs, dict):
        return None, None
    raw_id = prefs.get("ExitNodeID")
    exit_id = raw_id.strip() if isinstance(raw_id, str) and raw_id.strip() else None
    return exit_id, _ip_or_none(prefs.get("ExitNodeIP"))


def exits_match(want, have):
    """True when both prefs describe the same exit selection, including none."""
    want_id, want_ip = exit_identity(want)
    have_id, have_ip = exit_identity(have)
    if want_id and have_id:
        return want_id == have_id
    if want_ip and have_ip:
        return want_ip == have_ip
    return not want_id and not want_ip and not have_id and not have_ip


def cli_exit_token_allowed(value):
    """Empty clears. Any other token must be an IP or one MagicDNS label."""
    if value == "":
        return True
    if not isinstance(value, str):
        return False
    if _ip_or_none(value) is not None:
        return True
    return _EXIT_HOSTNAME.fullmatch(value) is not None


def _magic_dns_base(dns_name, suffix):
    if not isinstance(dns_name, str) or not dns_name.strip():
        return None
    name = dns_name.strip()
    if name.endswith("."):
        name = name[:-1]
    if isinstance(suffix, str) and suffix.strip():
        trimmed = suffix.strip()
        if trimmed.endswith("."):
            trimmed = trimmed[:-1]
        if name.lower().endswith("." + trimmed.lower()):
            name = name[:-(len(trimmed) + 1)]
    base = name.split(".", 1)[0]
    if _EXIT_HOSTNAME.fullmatch(base):
        return base
    return None


def _peer_tailscale_ip(peer):
    found = []
    for raw in peer.get("TailscaleIPs") or []:
        ip = _ip_or_none(raw)
        if ip is None or ip.is_unspecified or ip.is_loopback or ip.is_multicast:
            continue
        found.append(ip)
    for ip in found:
        if ip.version == 4:
            return ip
    return found[0] if found else None


def _peer_is_exit(peer, exit_id, exit_ip):
    if not isinstance(peer, dict) or peer.get("ExitNodeOption") is not True:
        return False
    if exit_id and peer.get("ID") == exit_id:
        return True
    if exit_ip is None:
        return False
    return any(_ip_or_none(raw) == exit_ip for raw in (peer.get("TailscaleIPs") or []))


def exit_node_cli_value(prefs, status):
    """CLI argument for the pinned exit, or None when it cannot be named.

    ``ExitNodeID`` is a StableNodeID. The official CLI rejects that form.
    The peer's Tailscale IP is preferred; the MagicDNS base name is the
    fallback. ``auto:any`` is never returned.
    """
    exit_id, exit_ip = exit_identity(prefs)
    if exit_id is None and exit_ip is None:
        return None
    peers = []
    suffix = None
    if isinstance(status, dict):
        suffix = status.get("MagicDNSSuffix")
        raw = status.get("Peer")
        if isinstance(raw, dict):
            peers = [peer for peer in raw.values() if _peer_is_exit(peer, exit_id, exit_ip)]
    for peer in peers:
        ip = _peer_tailscale_ip(peer)
        if ip is not None and str(ip) != exit_id:
            return str(ip)
    for peer in peers:
        base = _magic_dns_base(peer.get("DNSName"), suffix)
        if base and base != exit_id:
            return base
    if exit_ip is not None and str(exit_ip) != exit_id:
        return str(exit_ip)
    return None


def _parse_scutil_dns(code, text, error):
    if error or code != 0:
        return {"status": "unavailable", "reason": error or "command_failed",
                "resolvers": [], "has_198_18": None}
    resolvers, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        match = re.fullmatch(r"resolver #(\d+)", stripped)
        if match:
            if current is not None:
                resolvers.append(current)
            current = {"scope": "global", "nameservers": [], "search_domains": [],
                       "if_index": None}
            continue
        if current is None:
            continue
        match = re.fullmatch(r"nameserver\[\d+\]\s*:\s*(\S+)", stripped)
        if match:
            current["nameservers"].append(match.group(1))
            continue
        match = re.fullmatch(r"search domain\[\d+\]\s*:\s*(\S+)", stripped)
        if match:
            current["search_domains"].append(match.group(1))
            continue
        match = re.fullmatch(r"if_index\s*:\s*(\d+)(?:\s+\(.*\))?", stripped)
        if match:
            current["if_index"] = int(match.group(1))
            current["scope"] = "scoped"
    if current is not None:
        resolvers.append(current)
    has_198_18 = None
    seen = [item for row in resolvers for item in row["nameservers"]]
    if seen:
        try:
            has_198_18 = any(ipaddress.ip_address(item) in _FAKE_IP for item in seen)
        except ValueError:
            has_198_18 = None
    return {"status": "observed" if resolvers else "unavailable",
            "reason": None if resolvers else "no_resolvers",
            "resolvers": resolvers, "has_198_18": has_198_18}


def _parse_services(code, text, error):
    if error or code != 0:
        return None, "unavailable"
    active = []
    for line in text.splitlines():
        name = line.rstrip("\n")
        if not name or name.startswith("An asterisk") or name.startswith(" asterisk"):
            continue
        if not macos_readonly._SERVICE_NAME.fullmatch(name):
            continue
        if name.startswith("*"):
            continue
        active.append(name)
    active.sort(key=lambda item: (item != "Wi-Fi",))
    return active[:_MAX_SERVICES], None


def _parse_dnsservers(text):
    """Server list per service. None means unparseable, [] means Automatic."""
    servers = []
    for line in text.splitlines():
        entry = line.strip()
        if not entry:
            continue
        if entry.startswith("There aren't any"):
            return []
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            return None
        servers.append(entry)
    return servers


def _parse_scutil_proxy(code, text, error):
    if error or code != 0:
        return {"status": "unavailable", "reason": error or "command_failed",
                "protocols": {}, "bypass": []}
    # A successful command that is not a scutil dictionary is not "no proxy".
    if not isinstance(text, str) or "<dictionary>" not in text:
        return {"status": "unknown", "reason": "invalid_proxy_output",
                "protocols": {}, "bypass": []}
    protocols, bypass, in_exceptions = {}, [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "}":
            in_exceptions = False
            continue
        match = re.fullmatch(r"(\w+)Enable\s*:\s*(\d+)", stripped)
        if match:
            row = protocols.setdefault(match.group(1), {})
            # Only 0 and 1 are the documented flags. Any other number stays
            # unset so a caller cannot treat it as disabled.
            if match.group(2) in {"0", "1"}:
                row["enabled"] = match.group(2) == "1"
            continue
        match = re.fullmatch(r"(\w+)Proxy\s*:\s*(\S+)", stripped)
        if match:
            protocols.setdefault(match.group(1), {})["server"] = match.group(2)
            continue
        match = re.fullmatch(r"(\w+)Port\s*:\s*(\d+)", stripped)
        if match:
            protocols.setdefault(match.group(1), {})["port"] = int(match.group(2))
            continue
        if stripped.startswith("ExceptionsList"):
            in_exceptions = True
            continue
        if in_exceptions:
            match = re.fullmatch(r"\d+\s*:\s*(\S+)", stripped)
            if match:
                bypass.append(match.group(1))
    return {"status": "observed", "reason": None, "protocols": protocols, "bypass": bypass}


def _ps_failure(error, code):
    """Why this ps read cannot decide absence. None means the listing is complete."""
    if not error and code == 0:
        return None
    if error == "timeout":
        return "timeout"
    if error == "output_too_large":
        return "output_too_large"
    if error == "invalid_text":
        return "invalid_text"
    # Non-zero exit and command_failed are one class. tool_missing,
    # permission_denied, and launch_error stay the generic unknown.
    if error == "command_failed" or (error is None and code not in (0, None)):
        return "command_failed"
    return "unavailable"


_PS_NOTES = {
    "timeout": "ps_timeout",
    "output_too_large": "ps_output_too_large",
    "invalid_text": "ps_invalid_text",
    "command_failed": "ps_command_failed",
}


def _parse_ps(code, text, error):
    result = {"mihomo": [], "sing_tun": [], "tailscale": []}
    reason = _ps_failure(error, code)
    if reason is not None:
        return result, reason
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        base = parts[1].strip().rsplit("/", 1)[-1].strip()
        if base == "mihomo":
            result["mihomo"].append({"pid": pid, "comm": base})
        elif "sing-tun" in base or "sing_tun" in base:
            result["sing_tun"].append({"pid": pid, "comm": base})
        elif base in ("tailscaled", "Tailscale"):
            result["tailscale"].append({"pid": pid, "comm": base})
    return result, None


def _expand_v4(destination):
    """netstat prints compressed CIDRs like 100.64/10; expand for matching."""
    parts = destination.split("/")
    if len(parts) != 2:
        return None
    address, bits = parts
    if bits.isdigit() and 0 <= int(bits) <= 32:
        octets = address.split(".")
        if 1 <= len(octets) <= 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in octets):
            address = ".".join(octets + ["0"] * (4 - len(octets)))
            try:
                return ipaddress.ip_network(f"{address}/{bits}", strict=False)
            except ValueError:
                return None
    try:
        return ipaddress.ip_network(destination, strict=False)
    except ValueError:
        return None


def _parse_routes(code, text, error, family):
    rows = {"status": "unavailable", "reason": error or "command_failed",
            "default": [], "tailnet": {"interface": None, "status": "unknown"}}
    if error or code != 0:
        return rows
    header_seen = False
    for line in text.splitlines():
        fields = line.split()
        if not header_seen:
            if fields[:3] == ["Destination", "Gateway", "Flags"]:
                header_seen = True
            continue
        if len(fields) < 3:
            continue
        destination, gateway = fields[0], fields[1]
        # The interface column position varies (Refs/Use/Expire come and go);
        # take the trailing field that looks like an interface name.
        interface = None
        for candidate in (fields[-1], fields[-2] if len(fields) >= 4 else None):
            if candidate and macos_readonly._INTERFACE_NAME.fullmatch(candidate):
                interface = candidate
                break
        if destination in ("default", "0.0.0.0", "::/0"):
            rows["default"].append({"family": family, "interface": interface,
                                    "gateway": gateway})
            continue
        network = None
        if family == 4:
            network = _expand_v4(destination)
        else:
            with contextlib.suppress(ValueError):
                network = ipaddress.ip_network(destination, strict=False)
        if network is not None and (network.overlaps(_TAILNET4) or network.overlaps(_TAILNET6)):
            if rows["tailnet"]["interface"] is None:
                rows["tailnet"] = {"interface": interface, "status": "observed"}
    rows["status"] = "observed"
    rows["reason"] = None
    return rows


def _timestamp(now):
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)), time.strftime(
        "%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now))


def build_snapshot(platform, *, runner=None, exists=None, now=None):
    """One read-only snapshot. Real values stay in the returned document."""
    if now is None:
        now = time.time()
    base = {"schema_version": SCHEMA_VERSION, "kind": "macos_pre_start_snapshot",
            "phase": "A", "platform": platform,
            "mutates_network": False, "uses_sudo": False, "starts_processes": False}
    if platform != "macos":
        return dict(base, status="not_applicable", reason="not_applicable",
                    created_at=_timestamp(now)[1], created_at_unix=int(now),
                    commands=[], sections={})
    if runner is None:
        runner = execute
    if exists is None:
        def exists(path):  # noqa: E306
            return Path(path).is_file() and os.access(path, os.X_OK)
    commands, notes = [], []
    netstat4 = _run(runner, _SNAPSHOT_COMMANDS[0][0], _SNAPSHOT_COMMANDS[0][1], commands)
    netstat6 = _run(runner, _SNAPSHOT_COMMANDS[1][0], _SNAPSHOT_COMMANDS[1][1], commands)
    scutil_dns = _run(runner, _SNAPSHOT_COMMANDS[2][0], _SNAPSHOT_COMMANDS[2][1], commands)
    scutil_proxy = _run(runner, _SNAPSHOT_COMMANDS[3][0], _SNAPSHOT_COMMANDS[3][1], commands)
    ps = _run(runner, _SNAPSHOT_COMMANDS[4][0], _SNAPSHOT_COMMANDS[4][1], commands)

    dns = _parse_scutil_dns(*scutil_dns)
    proxy = _parse_scutil_proxy(*scutil_proxy)
    processes, ps_reason = _parse_ps(*ps)
    routes = _parse_routes(*netstat4, family=4)
    routes6 = _parse_routes(*netstat6, family=6)

    services, _ = _parse_services(*_run(
        runner, (_SETUP, "-listallnetworkservices"), _SETUP_TIMEOUT, commands))
    service_rows = []
    if services is not None:
        for name in services:
            code, text, error = _run(runner, (_SETUP, "-getdnsservers", name),
                                     _SETUP_TIMEOUT, commands)
            servers = None if error or code != 0 else _parse_dnsservers(text)
            status = "observed" if servers is not None else "unavailable"
            service_rows.append({"service": name, "dnsservers": servers, "status": status})
    else:
        notes.append("networksetup_services_unavailable")

    tailscale_path = _first_tailscale(exists)
    status_view = {"availability": "unavailable", "reason": "binary_missing"}
    prefs = {"status": "unavailable", "reason": "binary_missing"}
    status_document = None
    if tailscale_path is not None:
        code, text, error = _run(runner, (tailscale_path, "status", "--json"),
                                 _TAILSCALE_TIMEOUT, commands)
        if error or code != 0:
            status_view = {"availability": "unavailable", "reason": error or "command_failed"}
        else:
            status_view = macos_coexist.normalize_tailscale_status(text, returncode=code)
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                status_document = parsed
        code, text, error = _run(runner, (tailscale_path, "debug", "prefs"),
                                 _TAILSCALE_TIMEOUT, commands)
        prefs = _parse_prefs(code, text, error)
    else:
        notes.append("tailscale_binary_missing")
    exit_node_cli = exit_node_cli_value(prefs, status_document) if prefs.get("status") == "observed" else None

    if dns["status"] != "observed":
        notes.append("scutil_dns_unavailable")
    if prefs["status"] != "observed":
        notes.append("tailscale_prefs_unavailable")
    if ps_reason is not None:
        # A failed or truncated ps is unknown. null is not "mihomo is absent".
        # The specific token names timeout / non-zero / over-limit / bad text.
        # Neither token carries process text.
        notes.append("ps_unavailable")
        specific = _PS_NOTES.get(ps_reason)
        if specific:
            notes.append(specific)

    has_198_18 = dns["has_198_18"]
    exit_node_selected = bool(prefs.get("ExitNodeID") or prefs.get("ExitNodeIP"))
    takeover_ready = {
        "scutil_has_no_198_18": None if has_198_18 is None else not has_198_18,
        # None means the ps read did not succeed. It must not be used as ready.
        "mihomo_absent": None if ps_reason is not None else not processes["mihomo"],
        "exit_node_selected": exit_node_selected,
        "notes": notes,
    }
    return dict(
        base,
        status="observed",
        reason=None,
        created_at=_timestamp(now)[1],
        created_at_unix=int(now),
        commands=commands,
        tailscale={"status": status_view, "prefs": prefs, "exit_node_cli": exit_node_cli},
        dns=dict(dns, services=service_rows),
        proxy=proxy,
        routes={"inet": routes, "inet6": routes6},
        processes=processes,
        takeover_ready=takeover_ready,
    )


def _summary_mihomo_running(snapshot, processes):
    ready = snapshot.get("takeover_ready")
    if isinstance(ready, dict) and "mihomo_absent" in ready:
        absent = ready.get("mihomo_absent")
        if absent is None:
            return None
        return not bool(absent)
    return bool(processes.get("mihomo"))


def summarize_snapshot(snapshot, path=None):
    """The public, redacted view: statuses, counts, booleans, fingerprints.

    ``mihomo_running`` is null when the ps read failed. That null is not a
    ready signal and is not rewritten to false.
    """
    prefs = (snapshot.get("tailscale") or {}).get("prefs") or {}
    dns = snapshot.get("dns") or {}
    processes = snapshot.get("processes") or {}
    exit_node = prefs.get("ExitNodeID") or prefs.get("ExitNodeIP")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": snapshot.get("kind"),
        "phase": snapshot.get("phase"),
        "platform": snapshot.get("platform"),
        "status": snapshot.get("status"),
        "created_at": snapshot.get("created_at"),
        "path": str(path) if path is not None else None,
        "command_count": len(snapshot.get("commands") or []),
        "exit_node_selected": bool(exit_node),
        "exit_node_id_fingerprint": hashlib.sha256(
            exit_node.encode()).hexdigest()[:16] if isinstance(exit_node, str) and exit_node else None,
        "has_198_18": dns.get("has_198_18"),
        # null when ps was not observed. An empty list is "not running" only
        # after a successful read; a failed read must not look like ready.
        "mihomo_running": _summary_mihomo_running(snapshot, processes),
        "tailscale": {"status": ((snapshot.get("tailscale") or {}).get("status") or {}).get("availability"),
                      "prefs": prefs.get("status")},
        "dns": {"status": dns.get("status"), "service_count": len(dns.get("services") or [])},
        "proxy": {"status": (snapshot.get("proxy") or {}).get("status")},
        "routes": {"inet": (snapshot.get("routes") or {}).get("inet", {}).get("status"),
                   "inet6": (snapshot.get("routes") or {}).get("inet6", {}).get("status")},
        "phase_2_remaining": list(PHASE_2_REMAINING),
        "mutates_network": False,
        "uses_sudo": False,
    }


def default_state_dir():
    base = os.environ.get("XDG_STATE_HOME")
    base = Path(base) if base and Path(base).is_absolute() else Path.home() / ".local/state"
    return base / "nmd-monitor"


def write_snapshot(snapshot, state_dir, *, repo_root=REPO_ROOT, now=None):
    """Write the snapshot privately: 0700 dirs, 0600 file, never in the checkout.

    All checks and the write itself target the fully resolved path, so a
    symlinked state directory cannot redirect the snapshot into the checkout:
    the resolved location is what gets refused or written.
    """
    directory = Path(state_dir).expanduser()
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    directory = directory.resolve()
    if _inside_repository(directory, repo_root.resolve()):
        raise ValueError("state_dir_inside_repository")
    _create_private_parents(directory)
    stamp, _ = _timestamp(now if now is not None else time.time())
    name = f"pre-start-{stamp}.json"
    payload = json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
    _atomic_private_write(directory, name, payload)
    return directory / name


def collect_snapshot(platform, state_dir=None, *, runner=None, exists=None, now=None):
    """Observe, persist (macOS only), and return the redacted summary."""
    if now is None:
        now = time.time()
    snapshot = build_snapshot(platform, runner=runner, exists=exists, now=now)
    path = None
    if snapshot["status"] == "observed":
        path = write_snapshot(snapshot, state_dir if state_dir is not None
                              else default_state_dir(), now=now)
    return snapshot, summarize_snapshot(snapshot, path), path


def _load_json(path):
    try:
        with open(path, "rb") as handle:
            return json.loads(handle.read(65536))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid_json_file: {path}") from exc


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in ([], ["help"], ["-h"], ["--help"]):
        stream = sys.stdout if argv else sys.stderr
        stream.write(HELP)
        return 0 if argv else 2
    if argv[0] == "config":
        inputs_path, profile_path, out_path, stdout = None, None, None, False
        rest = argv[1:]
        index = 0
        while index < len(rest):
            flag = rest[index]
            if flag in ("--inputs", "--profile", "--out") and index + 1 < len(rest):
                value = rest[index + 1]
                if flag == "--inputs":
                    inputs_path = value
                elif flag == "--profile":
                    profile_path = value
                else:
                    out_path = value
                index += 2
            elif flag == "--stdout":
                stdout = True
                index += 1
            else:
                sys.stderr.write(HELP)
                return 2
        if not inputs_path or (stdout == (out_path is not None)):
            sys.stderr.write(HELP)
            return 2
        profile = _load_json(profile_path or REPO_ROOT / "examples/macos-mihomo-coexist.experiment.json")
        inputs = _load_json(inputs_path)
        try:
            text = render_config(profile, inputs)
            path = None if stdout else write_config(text, out_path)
        except ValueError as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 2
        if stdout:
            sys.stdout.write(text)
        else:
            print(json.dumps({"result": "config_written", "path": str(path)}))
        return 0
    if argv[0] == "snapshot":
        state_dir = None
        rest = argv[1:]
        if len(rest) == 2 and rest[0] == "--state-dir":
            state_dir = rest[1]
        elif rest:
            sys.stderr.write(HELP)
            return 2
        import nmd_platform
        _, summary, _ = collect_snapshot(nmd_platform.name(), state_dir)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    sys.stderr.write(HELP)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
