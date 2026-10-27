"""Private source registry and explicit egress operations; no daemon or service control.

Only this module handles subscription URLs. Public views are allowlists, never
redacted copies of arbitrary provider/controller responses. Runtime files contain
node credentials and are private deployment inputs, not diagnostic exports.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time
from urllib.parse import quote, urlencode, urlsplit

GROUP = "NMD-EXIT"
ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 2 * 1024 * 1024
MAX_NODES = 256
TAILNET = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
NODE_TYPES = {"socks5", "http", "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "snell", "anytls"}
# Protocol data only. In particular, no filesystem certificates, dialer chains,
# routing marks, interface overrides, health checks or provider URLs are imported.
NODE_FIELDS = set("name type server port username password udp tls sni servername cipher uuid alterId network alpn client-fingerprint fingerprint skip-cert-verify flow packet-encoding obfs obfs-password protocol protocol-param obfs-param plugin plugin-opts ws-opts grpc-opts h2-opts http-opts reality-opts smux tfo fast-open udp-over-tcp udp-over-tcp-version up down auth auth-str recv-window recv-window-conn disable-mtu-discovery reduce-rtt request-timeout heartbeat-interval disable-sni fast-open version congestion-controller udp-relay-mode zero-rtt-handshake".split())
FORBIDDEN = {"interface-name", "routing-mark", "dialer-proxy", "certificate", "private-key", "ca", "ca-str"}
# Manual single-node latency checks only. The test URL is a fixed constant and
# never client-supplied; no batch testing, no background probing.
DELAY_TEST_URL = "https://www.gstatic.com/generate_204"
DELAY_TEST_TIMEOUT_MS = 5000
DELAY_HTTP_TIMEOUT = 6
# Opt-in automatic failover between exactly two pinned candidates. No batch
# testing, no background refresh; the monitor collector drives one evaluation
# per cycle and every switch goes through the same select() path as the CLI.
AUTO_DEFAULTS = {"fail_after": 3, "recover_after": 2, "cooldown": 2}
LEGACY_AUTO_KEYS = {"enabled", "paused", "primary", "tailnet", "subscription",
                    "fail_after", "recover_after", "cooldown"}
AUTO_KEYS = {"version", "enabled", "paused", "primary", "secondary",
             "fail_after", "recover_after", "cooldown"}


class SourceError(RuntimeError):
    """Messages are fixed error codes: never interpolate untrusted inputs."""


class ControllerProbeError(SourceError):
    """No trustworthy node result; keep the public delay error opaque."""


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False).encode()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value):
        raise SourceError("invalid_source_id")
    return value


def _private_file(path, owner=None, private=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (owner is not None and info.st_uid != owner)
                or (private and stat.S_IMODE(info.st_mode) & 0o077)
                or info.st_size > MAX_BYTES):
            raise SourceError("unsafe_private_file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise SourceError("input_too_large")
        return data
    finally:
        os.close(fd)


def _owner():
    # Explicit network apply may have crossed sudo; no credentials in argv/env.
    return int(os.environ.get("SUDO_UID", "0")) if os.geteuid() == 0 else os.geteuid()


def _directory(path, create=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise SourceError("unsafe_source_directory")
    if path == ROOT or ROOT in path.parents:
        raise SourceError("private_sources_must_be_outside_checkout")
    for part in reversed((path, *path.parents)):
        if part.is_symlink():
            raise SourceError("unsafe_source_directory")
        if part.exists():
            info = part.stat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, _owner()}
                    or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
                raise SourceError("unsafe_source_directory")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and (path.stat().st_uid not in {os.geteuid(), _owner()}
                          or path.stat().st_mode & 0o077):
        raise SourceError("source_directory_must_be_private")
    return path


def atomic_write(path, data):
    """Do not repair or follow an existing unsafe destination."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        _private_file(path, owner=path.parent.stat().st_uid)
    fd, name = tempfile.mkstemp(prefix=".nmd-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)

    @property
    def path(self):
        return self.directory / "sources.json"

    def load(self):
        _directory(self.directory)
        if not self.path.exists() and not self.path.is_symlink():
            return {"schema_version": 1, "sources": {}, "cache": {}, "selected": None}
        value = json.loads(_private_file(self.path, owner=self.directory.stat().st_uid))
        if (not isinstance(value, dict) or value.get("schema_version") != 1
                or not isinstance(value.get("sources"), dict) or not isinstance(value.get("cache"), dict)):
            raise SourceError("invalid_source_registry")
        for key, source in value["sources"].items():
            identifier(key)
            validate_source(source)
        if "auto" in value:
            validate_auto(value)
        return value

    @contextmanager
    def edit(self, migrate_auto=True):
        _directory(self.directory, create=True)
        lock = self.directory / ".lock"
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise SourceError("unsafe_source_lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SourceError("source_operation_busy") from None
            value = self.load()
            if migrate_auto and "auto" in value:
                value["auto"] = _policy(value["auto"])
            if "controller" not in value:
                value["controller"] = {"url": "http://127.0.0.1:9090", "secret": secrets.token_urlsafe(32)}
            yield value
            if "auto" in value:
                validate_auto(value)
            if len(encode(value)) > MAX_BYTES:
                raise SourceError("registry_too_large")
            atomic_write(self.path, encode(value))
        finally:
            os.close(fd)


def channel_name(value):
    if (not isinstance(value, str) or not value.strip() or len(value) > 128
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise SourceError("invalid_channel_name")
    return value


def _source_identity(source):
    # Preserve the exact legacy digest input, excluding new display-only data.
    return {key: item for key, item in source.items() if key != "display_name"}


def validate_source(value):
    if not isinstance(value, dict):
        raise SourceError("invalid_source")
    kind = value.get("kind")
    allowed = {"kind", "expected_egress_ip", "display_name"}
    if "display_name" in value:
        channel_name(value["display_name"])
    if kind in {"tailnet", "proxy"}:
        allowed |= {"server", "port", "username", "password", "udp"}
        try:
            address = ipaddress.ip_address(value["server"])
        except (ValueError, KeyError, TypeError):
            raise SourceError("tailnet_requires_literal_tailnet_ip" if kind == "tailnet"
                              else "proxy_requires_literal_non_tailnet_ip") from None
        is_tailnet = any(address in network for network in TAILNET)
        if kind == "tailnet" and not is_tailnet:
            raise SourceError("tailnet_requires_literal_tailnet_ip")
        ordinary_address = getattr(address, "ipv4_mapped", None) or address
        if kind == "proxy" and (any(ordinary_address in network for network in TAILNET)
                                or getattr(address, "scope_id", None)
                                or ordinary_address.is_loopback or ordinary_address.is_link_local
                                or ordinary_address.is_multicast or ordinary_address.is_unspecified):
            raise SourceError("proxy_requires_literal_non_tailnet_ip")
        if type(value.get("port")) is not int or not 1 <= value["port"] <= 65535:
            raise SourceError("invalid_proxy_port")
        if "udp" in value and type(value["udp"]) is not bool:
            raise SourceError("invalid_proxy_udp")
        for key in ("username", "password"):
            if key in value and (not isinstance(value[key], str) or len(value[key]) > 4096):
                raise SourceError("invalid_proxy_credential")
    elif kind == "subscription":
        allowed.add("url")
        try:
            if not isinstance(value.get("url"), str):
                raise ValueError()
            parsed = urlsplit(value["url"])
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.fragment or parsed.port not in (None, 443)
                    or any(ord(c) <= 32 or ord(c) == 127 for c in value["url"])):
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise SourceError("subscription_requires_https_url") from None
    else:
        raise SourceError("unsupported_source_kind")
    if set(value) - allowed:
        raise SourceError("unsupported_source_field")
    if value.get("expected_egress_ip") is not None:
        try:
            ipaddress.ip_address(value["expected_egress_ip"])
        except (ValueError, TypeError):
            raise SourceError("invalid_expected_egress_ip") from None
    return value


def _policy(auto):
    """An in-memory view; only an explicit Store.edit persists the conversion."""
    if not isinstance(auto, dict) or set(auto) != LEGACY_AUTO_KEYS:
        return auto
    first = auto["primary"]
    second = "tailnet" if first == "subscription" else "subscription"
    return {"version": 2, "enabled": auto["enabled"], "paused": auto["paused"],
            "primary": dict(auto[first]), "secondary": dict(auto[second]),
            **{key: auto[key] for key in AUTO_DEFAULTS}}


def validate_auto(value):
    auto = value["auto"]
    legacy = isinstance(auto, dict) and set(auto) == LEGACY_AUTO_KEYS
    if not isinstance(auto, dict) or (not legacy and set(auto) != AUTO_KEYS):
        raise SourceError("invalid_auto")
    if type(auto["enabled"]) is not bool or type(auto["paused"]) is not bool:
        raise SourceError("invalid_auto")
    if legacy:
        if auto["primary"] not in ("tailnet", "subscription"):
            raise SourceError("invalid_auto")
        roles = ("tailnet", "subscription")
    else:
        if type(auto["version"]) is not int or auto["version"] != 2:
            raise SourceError("invalid_auto")
        roles = ("primary", "secondary")
    for role in roles:
        pin = auto[role]
        if not isinstance(pin, dict) or set(pin) != {"source", "node"}:
            raise SourceError("invalid_auto")
        try:
            identifier(pin["source"])
        except SourceError:
            raise SourceError("invalid_auto") from None
        source = value["sources"].get(pin["source"])
        if source is None or (legacy and source["kind"] != role):
            raise SourceError("invalid_auto")
        if (not isinstance(pin["node"], str)
                or not re.fullmatch(r"nmd-" + re.escape(pin["source"]) + r"-[a-f0-9]{20}", pin["node"])):
            raise SourceError("invalid_auto")
    policy = _policy(auto)
    if policy["primary"]["node"] == policy["secondary"]["node"]:
        raise SourceError("invalid_auto")
    for key in AUTO_DEFAULTS:
        if type(auto[key]) is not int or not 2 <= auto[key] <= 10:
            raise SourceError("invalid_auto")
    return auto


def yaml_load(data):
    try:
        import yaml
    except ImportError:
        raise SourceError("yaml_dependency_missing_PyYAML_6_0_3") from None

    class StrictLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
            if any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
                raise SourceError("invalid_yaml_keys")
            return super().construct_mapping(node, deep=deep)

    try:
        for index, token in enumerate(yaml.scan(data)):
            if index > 100000 or isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                raise SourceError("unsupported_yaml_alias_or_tag")
        return yaml.load(data, Loader=StrictLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError):
        raise SourceError("invalid_provider_yaml") from None


def _protocol_data(value, depth=0):
    if depth > 12:
        raise SourceError("provider_nesting_too_deep")
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise SourceError("invalid_proxy_data")
        return {key: _protocol_data(item, depth + 1) for key, item in value.items() if key not in FORBIDDEN}
    if isinstance(value, list):
        return [_protocol_data(item, depth + 1) for item in value]
    if value is None or type(value) in {str, int, float, bool}:
        encode(value)
        return value
    raise SourceError("invalid_proxy_data")


def normalize_nodes(source_id, source, raw_nodes):
    if not isinstance(raw_nodes, list) or not 1 <= len(raw_nodes) <= MAX_NODES:
        raise SourceError("provider_requires_1_to_256_nodes")
    nodes, names = [], set()
    for raw in raw_nodes:
        if (not isinstance(raw, dict) or raw.get("type") not in NODE_TYPES
                or not isinstance(raw.get("server"), str) or not raw["server"]
                or type(raw.get("port")) is not int or not 1 <= raw["port"] <= 65535
                or not isinstance(raw.get("name"), str) or not raw["name"]):
            raise SourceError("invalid_or_unsupported_proxy_node")
        if raw["name"] in names:
            raise SourceError("duplicate_proxy_name")
        names.add(raw["name"])
        node = _protocol_data({key: item for key, item in raw.items() if key in NODE_FIELDS})
        # Opaque, source-scoped names prevent both collisions and secret-bearing
        # node labels from reaching stdout, controller URLs or core logs.
        # display is attached strictly after the digest: node ids must stay stable
        # across refreshes, or saved selections and auto pins would break.
        digest = hashlib.sha256(encode([_source_identity(source), node])).hexdigest()[:20]
        node["name"] = f"nmd-{source_id}-{digest}"
        node["display"] = raw["name"][:512]
        if source["kind"] == "tailnet":
            node["interface-name"] = "tailscale0"
        nodes.append(node)
    return nodes


def tailnet_nodes(source_id, source):
    raw = {key: value for key, value in source.items() if key in {"server", "port", "username", "password", "udp"}}
    return normalize_nodes(source_id, source, [dict(raw, name=source_id, type="socks5")])


def fetch_subscription(url):
    """HTTPS only, no redirects, ambient proxies, headers or URL diagnostics."""
    parsed = urlsplit(url)
    conn = http.client.HTTPSConnection(parsed.hostname, timeout=10)
    deadline = time.monotonic() + 20
    try:
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        conn.request("GET", target, headers={"User-Agent": "NMD-source/1", "Accept": "application/yaml, application/json"})
        response = conn.getresponse()
        if response.status != 200:
            raise SourceError("subscription_http_error_no_redirects")
        data = bytearray()
        while len(data) <= MAX_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SourceError("subscription_timeout")
            if conn.sock:
                conn.sock.settimeout(min(10, remaining))
            chunk = response.read1(min(65536, MAX_BYTES + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise SourceError("subscription_too_large")
    except (OSError, http.client.HTTPException, ValueError):
        raise SourceError("subscription_fetch_failed") from None
    finally:
        conn.close()


def _clear_auto_reference(value, source_id):
    """Deleting/changing a pinned source atomically stands automation down."""
    auto = _policy(value.get("auto"))
    if isinstance(auto, dict) and any(auto[role]["source"] == source_id
                                      for role in ("primary", "secondary")):
        value.pop("auto")


def put_source(store, source_id, definition, replace=False):
    identifier(source_id)
    validate_source(definition)
    with store.edit() as value:
        exists = source_id in value["sources"]
        if exists != replace:
            raise SourceError("source_not_found" if replace else "source_already_exists")
        if not exists and len(value["sources"]) >= 32:
            raise SourceError("too_many_sources")
        definition = dict(definition)
        previous = value["sources"].get(source_id)
        if previous and "display_name" not in definition and "display_name" in previous:
            definition["display_name"] = previous["display_name"]
        if previous and previous["kind"] != definition["kind"]:
            _clear_auto_reference(value, source_id)
        value["sources"][source_id] = definition
        if previous is not None and _source_identity(previous) == _source_identity(definition):
            return  # Display-only edits retain cache, selection and policy pins.
        value["cache"].pop(source_id, None)
        if definition["kind"] in {"tailnet", "proxy"}:
            value["cache"][source_id] = {"nodes": tailnet_nodes(source_id, definition), "refreshed_at": time.time()}


def rename_source(store, source_id, display_name):
    identifier(source_id)
    channel_name(display_name)
    with store.edit() as value:
        if source_id not in value["sources"]:
            raise SourceError("source_not_found")
        value["sources"][source_id]["display_name"] = display_name


def refresh(store, source_id, fixture=None):
    identifier(source_id)
    with store.edit() as value:
        source = value["sources"].get(source_id)
        if source is None or source["kind"] != "subscription":
            raise SourceError("subscription_source_not_found")
        data = _private_file(fixture, private=False) if fixture else fetch_subscription(source["url"])
        document = yaml_load(data)
        if not isinstance(document, dict):
            raise SourceError("provider_requires_proxies_mapping")
        # All top-level rules, DNS, TUN, groups, listeners and providers discarded.
        nodes = normalize_nodes(source_id, source, document.get("proxies"))
        previous = value.get("selected")
        if (previous and previous in {node["name"] for node in value["cache"].get(source_id, {}).get("nodes", [])}
                and previous not in {node["name"] for node in nodes}):
            raise SourceError("selected_node_would_disappear_choose_another_first")
        value["cache"][source_id] = {"nodes": nodes, "refreshed_at": time.time()}


def inventory(value):
    result = {}
    for source_id, source in value["sources"].items():
        for node in value["cache"].get(source_id, {}).get("nodes", []):
            # Validate persisted cache again, including source fingerprint and bind.
            name = node.get("name", "")
            if not isinstance(name, str) or not re.fullmatch(r"nmd-" + re.escape(source_id) + r"-[a-f0-9]{20}", name):
                raise SourceError("invalid_cached_node")
            # display is the private readable label; caches written before it
            # existed remain valid and fall back to the anonymous id in views.
            if "display" in node and (not isinstance(node["display"], str) or len(node["display"]) > 512):
                raise SourceError("invalid_cached_node")
            result[name] = (source_id, source, node)
    return result


class Controller:
    def __init__(self, value):
        settings = value.get("controller", {})
        parsed = urlsplit(settings.get("url", ""))
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise SourceError("controller_requires_literal_loopback")
        self.host, self.port = parsed.hostname, parsed.port or 9090
        self.secret = settings.get("secret")
        if not isinstance(self.secret, str) or len(self.secret) < 32 or re.search(r"[\r\n]", self.secret):
            raise SourceError("controller_secret_required")

    def request(self, method, body=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=2)
        try:
            conn.request(method, "/proxies/" + GROUP, body=encode(body) if body else None,
                         headers={"Authorization": "Bearer " + self.secret, "Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read(MAX_BYTES + 1)
            if response.status != (200 if method == "GET" else 204) or len(data) > MAX_BYTES:
                raise SourceError("controller_request_failed")
            return json.loads(data) if method == "GET" else None
        except (OSError, ValueError, http.client.HTTPException):
            raise SourceError("controller_unavailable") from None
        finally:
            conn.close()

    def current(self):
        value = self.request("GET")
        if not isinstance(value, dict) or value.get("type") != "Selector" or not isinstance(value.get("all"), list):
            raise SourceError("manual_selector_required")
        return value

    def delay(self, provider, name, timeout_ms=DELAY_TEST_TIMEOUT_MS):
        """One fixed-URL latency probe of a provider-backed proxy; errors stay opaque."""
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30000:
            raise SourceError("invalid_delay_timeout")
        # Provider members are not in the global proxy map on current cores;
        # the per-proxy healthcheck route is the single-node delay test.
        target = ("/providers/proxies/" + quote(str(provider), safe="") + "/"
                  + quote(str(name), safe="") + "/healthcheck?"
                  + urlencode({"url": DELAY_TEST_URL, "timeout": str(timeout_ms)}))
        conn = http.client.HTTPConnection(self.host, self.port, timeout=DELAY_HTTP_TIMEOUT)
        try:
            conn.request("GET", target, headers={"Authorization": "Bearer " + self.secret})
            response = conn.getresponse()
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ControllerProbeError("delay_test_failed")
            # Pinned mihomo v1.19.30 getProxyDelay reports node failure/timeout
            # as 503/504. Authentication, missing routes and malformed replies
            # are controller faults, not evidence against a candidate node.
            if response.status in (503, 504):
                raise SourceError("delay_test_failed")
            if response.status != 200:
                raise ControllerProbeError("delay_test_failed")
            value = json.loads(data)
            if (not isinstance(value, dict) or type(value.get("delay")) not in (int, float)
                    or not math.isfinite(value["delay"]) or value["delay"] < 0):
                raise ControllerProbeError("delay_test_failed")
            return int(round(value["delay"]))
        except (OSError, ValueError, http.client.HTTPException):
            raise ControllerProbeError("delay_test_failed") from None
        finally:
            conn.close()


def current_node(value):
    current = Controller(value).current()
    name = current.get("now")
    if name not in inventory(value) or name not in current["all"]:
        raise SourceError("active_node_unknown_or_pending_apply")
    return name


def delay_test(directory, name):
    """Manual latency check of one cached node; never accepts a test URL."""
    value = Store(directory).load()
    nodes = inventory(value)
    if name not in nodes:
        raise SourceError("node_not_found")
    return {"node": name, "delay_ms": Controller(value).delay("nmd-" + nodes[name][0], name)}


def select(store, name, deferred=False, origin="manual", auto_decision=None):
    uncertain = False
    with store.edit(migrate_auto=origin != "auto") as value:
        if origin == "auto":
            _check_auto_decision(value, auto_decision)
        nodes = inventory(value)
        if name not in nodes:
            raise SourceError("node_not_found")
        if not deferred:
            client = Controller(value)
            if name not in client.current()["all"]:
                raise SourceError("node_not_deployed_apply_first")
            try:
                client.request("PUT", {"name": name})
                if current_node(value) != name:
                    raise SourceError("selection_not_confirmed")
            except (SourceError, OSError, ValueError):
                auto = value.get("auto")
                if origin == "manual" and isinstance(auto, dict) and auto.get("enabled"):
                    # Keep the old desired node, but commit the pause before
                    # reporting an unknown manual outcome to the caller.
                    uncertain = True
                else:
                    raise SourceError("selection_outcome_unknown_read_status_before_retry") from None
        if not uncertain:
            value["selected"] = name
        # A manual choice never enrolls or replaces policy candidates. Pausing
        # also covers deferred intent, before any later explicit apply/resume.
        auto = value.get("auto")
        if origin == "manual" and isinstance(auto, dict) and auto.get("enabled"):
            auto["paused"] = True
    if uncertain:
        raise SourceError("selection_outcome_unknown_read_status_before_retry")


def _auto_decision(value):
    # Compare the existing policy/desired values directly; no new digest or
    # generation system. Store.load() returns a private, independent snapshot.
    return _policy(value.get("auto")), value.get("selected")


def _check_auto_decision(value, expected):
    auto = _policy(value.get("auto"))
    if (not isinstance(auto, dict) or not auto.get("enabled") or auto.get("paused")
            or expected is None or _auto_decision(value) != expected):
        raise SourceError("auto_decision_stale")
    nodes = inventory(value)
    if any(auto[role]["node"] not in nodes
           or nodes[auto[role]["node"]][0] != auto[role]["source"]
           for role in ("primary", "secondary")):
        raise SourceError("auto_decision_stale")


def _auto_pin(name, nodes, kind=None):
    if not isinstance(name, str) or name not in nodes or (kind is not None and nodes[name][1]["kind"] != kind):
        raise SourceError("auto_node_not_in_inventory")
    return {"source": nodes[name][0], "node": name}


def _single_tailnet_node(nodes):
    candidates = [name for name, (_, source, _) in nodes.items() if source["kind"] == "tailnet"]
    if len(candidates) != 1:
        raise SourceError("auto_requires_single_tailnet_node")
    return candidates[0]


def _auto_subscription_default(value, nodes):
    selected = value.get("selected")
    if selected in nodes and nodes[selected][1]["kind"] == "subscription":
        return selected
    raise SourceError("auto_requires_subscription_node")


def auto_configure(store, payload):
    """CLI and GUI share one policy writer; candidates are never inferred in v2."""
    action = payload.get("action")
    allowed = {"action"}
    if action == "enable":
        allowed |= {"primary_node", "secondary_node", "primary", "tailnet_node", "subscription_node", *AUTO_DEFAULTS}
    elif action == "set-primary":
        allowed.add("primary")
    elif action not in {"disable", "resume", "swap"}:
        raise SourceError("auto_invalid_action")
    if set(payload) - allowed:
        raise SourceError("auto_invalid_parameters")
    with store.edit() as value:
        nodes = inventory(value)
        if action == "enable":
            explicit = "primary_node" in payload or "secondary_node" in payload
            if explicit:
                if set(payload) & {"primary", "tailnet_node", "subscription_node"}:
                    raise SourceError("auto_invalid_parameters")
                first = _auto_pin(payload.get("primary_node"), nodes)
                second = _auto_pin(payload.get("secondary_node"), nodes)
            else:
                # Keep the existing CLI flags, defaults and ordering working.
                primary = payload.get("primary")
                if primary not in ("tailnet", "subscription"):
                    raise SourceError("auto_primary_required")
                tailnet = payload.get("tailnet_node") or _single_tailnet_node(nodes)
                subscription = payload.get("subscription_node") or _auto_subscription_default(value, nodes)
                pins = {"tailnet": _auto_pin(tailnet, nodes, "tailnet"),
                        "subscription": _auto_pin(subscription, nodes, "subscription")}
                first, second = pins[primary], pins["tailnet" if primary == "subscription" else "subscription"]
            if first["node"] == second["node"]:
                raise SourceError("auto_candidates_must_differ")
            auto = {"version": 2, "enabled": True, "paused": False,
                    "primary": first, "secondary": second}
            for key, default in AUTO_DEFAULTS.items():
                parameter = payload.get(key, default)
                if type(parameter) is not int or not 2 <= parameter <= 10:
                    raise SourceError("auto_invalid_parameters")
                auto[key] = parameter
            value["auto"] = auto
            result = "auto_enabled"
        else:
            auto = value.get("auto")
            if not isinstance(auto, dict):
                raise SourceError("auto_not_configured")
            if action == "disable":
                auto["enabled"] = False
                result = "auto_disabled"
            elif action in {"set-primary", "swap"}:
                if action == "set-primary":
                    kind = payload.get("primary")
                    if kind not in ("tailnet", "subscription"):
                        raise SourceError("auto_primary_required")
                    matching = [role for role in ("primary", "secondary")
                                if value["sources"][auto[role]["source"]]["kind"] == kind]
                    if len(matching) != 1:
                        raise SourceError("auto_legacy_primary_ambiguous_use_explicit_nodes")
                    swap = matching[0] == "secondary"
                else:
                    swap = True
                if swap:
                    auto["primary"], auto["secondary"] = auto["secondary"], auto["primary"]
                result = "auto_primary_updated"
            else:
                auto["paused"] = False
                result = "auto_resumed"
    return {"result": result}


def auto_signature(auto):
    auto = _policy(auto)
    fields = ("primary", "secondary", "fail_after", "recover_after", "cooldown")
    return hashlib.sha256(encode({key: auto[key] for key in fields})).hexdigest()[:20]


def _legacy_runtime_signature(auto, sources):
    """Recognize an unchanged legacy episode without losing pending readback."""
    kinds = {role: sources[auto[role]["source"]]["kind"] for role in ("primary", "secondary")}
    if set(kinds.values()) != {"tailnet", "subscription"}:
        return None
    previous = {"primary": kinds["primary"], **{kinds[role]: auto[role] for role in kinds},
                **{key: auto[key] for key in AUTO_DEFAULTS}}
    return hashlib.sha256(encode(previous)).hexdigest()[:20]


def _fresh_runtime(auto):
    return {"signature": auto_signature(auto), "target": None, "primary_fail": 0,
            "primary_recover": 0, "secondary_fail": 0, "cycles_since_switch": 0,
            "pending_verify": None, "suspended": False, "both_unhealthy": False}


def _runtime_view(runtime, auto):
    """Derive display-only fields onto the runtime itself; never a parallel export."""
    if not runtime:
        return
    if auto.get("paused"):
        state = "paused"
    elif runtime.get("suspended"):
        state = "suspended"
    elif runtime.get("pending_verify"):
        state = "pending_verify"
    elif runtime.get("both_unhealthy"):
        state = "both_unhealthy"
    elif runtime.get("target") is None:
        state = "primary_failing" if runtime.get("primary_fail") else "engaging"
    elif runtime["target"] == "secondary":
        state = ("secondary_failing" if runtime.get("secondary_fail")
                 else "recovering" if runtime.get("primary_recover")
                 else "secondary_active")
    else:
        state = "primary_failing" if runtime.get("primary_fail") else "primary_active"
    runtime["state"] = state
    runtime["cooldown_remaining"] = max(0, auto["cooldown"] - runtime.get("cycles_since_switch", 0))


def auto_evaluate(directory, runtime, emit):
    """One failover evaluation; operational faults never raise or count as node failures."""
    value = Store(directory).load()
    auto = _policy(value.get("auto"))
    if not isinstance(auto, dict) or not auto.get("enabled"):
        return {}
    runtime = _auto_evaluate(directory, runtime, emit, value, auto)
    _runtime_view(runtime, auto)
    return runtime


def _auto_evaluate(directory, runtime, emit, value, auto):
    value["auto"] = auto
    signature = auto_signature(auto)
    if (isinstance(runtime, dict) and runtime.get("signature") is not None
            and runtime.get("signature") != signature
            and runtime.get("signature") == _legacy_runtime_signature(auto, value["sources"])):
        runtime["signature"] = signature
    if not isinstance(runtime, dict) or runtime.get("signature") != signature:
        if isinstance(runtime, dict) and runtime:
            emit("candidate_changed", {})
        runtime = _fresh_runtime(auto)
    if auto.get("paused"):
        return runtime
    decision = _auto_decision(value)
    nodes = inventory(value)
    roles = {role: auto[role] for role in ("primary", "secondary")}
    missing = next((role for role in roles if auto[role]["node"] not in nodes), None)
    if missing:
        if not runtime.get("suspended"):
            emit("auto_suspended", {"reason": missing + "_node_missing"})
        runtime["suspended"] = True
        runtime["target"] = None
        return runtime
    if runtime.get("suspended"):
        runtime["suspended"] = False
        runtime["target"] = None
        emit("auto_resumed", {})
    if runtime.get("pending_verify"):
        expected = runtime["pending_verify"]
        try:
            # Reconcile under the same writer lock as manual selection/config.
            # An observation must not replace a completed manual operation.
            with Store(directory).edit(migrate_auto=False) as confirmed:
                _check_auto_decision(confirmed, decision)
                actual = current_node(confirmed)
                if actual == expected:
                    confirmed["selected"] = expected
        except SourceError as exc:
            if str(exc) == "auto_decision_stale":
                return {}
            if str(exc) != "source_operation_busy":
                emit("controller_unreachable", {})
            return runtime
        runtime["pending_verify"] = None
        if actual == expected:
            value = confirmed
            auto = _policy(value["auto"])
            decision = _auto_decision(value)
            runtime["target"] = next(role for role, pin in roles.items() if pin["node"] == expected)
            runtime["cycles_since_switch"] = 0
            runtime["primary_fail"] = runtime["primary_recover"] = runtime["secondary_fail"] = 0
            emit("auto_verify_adopted", {"node": expected})
    # Align the standing target with any desired/live selection on a candidate.
    selected = value.get("selected")
    for role, pin in roles.items():
        if selected == pin["node"] and runtime.get("target") != role:
            if runtime.get("target") is not None:
                emit("manual_engage_" + role, {"node": selected})
            runtime["target"] = role
            runtime["primary_fail"] = runtime["primary_recover"] = runtime["secondary_fail"] = 0
            break
    client = Controller(value)
    try:
        client.current()
    except SourceError:
        emit("controller_unreachable", {})
        return runtime
    def healthy(pin):
        try:
            client.delay("nmd-" + pin["source"], pin["node"])
            return True
        except ControllerProbeError:
            return None
        except SourceError as exc:
            return False if str(exc) == "delay_test_failed" else None
    primary_ok = healthy(roles["primary"])
    secondary_ok = healthy(roles["secondary"])
    if primary_ok is None or secondary_ok is None:
        emit("controller_unreachable", {})
        return runtime
    if not primary_ok and not secondary_ok:
        if not runtime.get("both_unhealthy"):
            emit("both_unhealthy", {})
        runtime["both_unhealthy"] = True
        runtime["cycles_since_switch"] = runtime.get("cycles_since_switch", 0) + 1
        return runtime
    runtime["both_unhealthy"] = False
    target = runtime.get("target")
    cooldown_ok = runtime.get("cycles_since_switch", 0) >= auto["cooldown"]
    switch_to, reason = None, None
    if target == "secondary":
        if primary_ok and not secondary_ok:
            runtime["primary_recover"] = 0
            runtime["secondary_fail"] += 1
            if runtime["secondary_fail"] >= auto["fail_after"] and cooldown_ok:
                switch_to, reason = "primary", "secondary_unhealthy"
        elif primary_ok:
            runtime["secondary_fail"] = 0
            runtime["primary_recover"] += 1
            if runtime["primary_recover"] >= auto["recover_after"] and cooldown_ok:
                switch_to, reason = "primary", "primary_recovered"
        else:
            runtime["primary_recover"] = 0
            if secondary_ok:
                runtime["secondary_fail"] = 0
    else:
        if primary_ok:
            runtime["primary_fail"] = 0
            if target is None:
                switch_to, reason = "primary", "auto_engaged"
        elif secondary_ok:
            runtime["primary_fail"] += 1
            if runtime["primary_fail"] >= auto["fail_after"] and cooldown_ok:
                switch_to, reason = "secondary", "primary_unhealthy"
    if switch_to:
        node = roles[switch_to]["node"]
        try:
            select(Store(directory), node, origin="auto", auto_decision=decision)
        except SourceError as exc:
            code = str(exc)
            if code == "auto_decision_stale":
                return {}
            if code == "source_operation_busy":
                runtime["cycles_since_switch"] = runtime.get("cycles_since_switch", 0) + 1
                return runtime
            if code == "selection_outcome_unknown_read_status_before_retry":
                runtime["pending_verify"] = node
            emit("auto_switch_failed", {"reason": code})
        else:
            emit("auto_switch", {"from": target, "to": switch_to, "node": node, "reason": reason})
            runtime["target"] = switch_to
            runtime["primary_fail"] = runtime["primary_recover"] = runtime["secondary_fail"] = 0
            runtime["cycles_since_switch"] = 0
            runtime["cycles_since_switch"] += 1
            return runtime
    runtime["cycles_since_switch"] = runtime.get("cycles_since_switch", 0) + 1
    return runtime


def public_status(directory, online=True, include_display=False):
    value = Store(directory).load()
    nodes = inventory(value)
    result = {"schema_version": 1, "mode": "sources" if Store(directory).path.exists() else "legacy",
              "group": GROUP, "selection_mode": "manual", "sources": [], "nodes": [],
              "desired": value.get("selected") if value.get("selected") in nodes else None,
              "active": None, "controller": "not_queried", "ai_business": "not_tested",
              "health_check": "disabled", "observed_at": time.time()}
    for source_id, source in value["sources"].items():
        result["sources"].append({"id": source_id, "kind": source["kind"],
            "url": "[redacted]" if source["kind"] == "subscription" else None,
            "expected_ip_configured": bool(source.get("expected_egress_ip")),
            "refreshed_at": value["cache"].get(source_id, {}).get("refreshed_at"),
            "node_count": sum(item[0] == source_id for item in nodes.values()),
            "fallback": ("manual_tailnet_selection_exit_node_not_assumed" if source["kind"] == "tailnet"
                         else "manual_source_selection_no_tailnet_exit_node_rollback")})
        result["sources"][-1]["connection"] = "tailnet" if source["kind"] == "tailnet" else "ordinary"
        if include_display:
            result["sources"][-1]["display_name"] = source.get("display_name", source_id)
    for name, (source_id, _, node) in nodes.items():
        # Readable labels are owner-local: only loopback GUI and local nodes/status
        # request them; list/export stay shareable without provider names.
        protocol = node.get("type")
        row = {"id": name, "source": source_id, "channel": source_id,
               "protocol": protocol if isinstance(protocol, str) and protocol in NODE_TYPES else None}
        if include_display:
            row["display"] = node.get("display")
        result["nodes"].append(row)
    auto = value.get("auto")
    if isinstance(auto, dict):
        result["auto"] = _policy(auto)
        result["selection_mode"] = ("auto" if auto.get("enabled") and not auto.get("paused")
                                    else "manual")
    if online and value["sources"]:
        try:
            result["active"] = current_node(value)
            result["controller"] = "observed"
        except (SourceError, OSError, ValueError):
            result["controller"] = "unavailable_or_pending_apply"
    return result


def render_runtime(directory, template, destination):
    """Private staging only. The shell deployment owns activation and services."""
    value = Store(directory).load()
    nodes = inventory(value)
    selected = value.get("selected")
    if not nodes or selected not in nodes:
        raise SourceError("choose_cached_node_explicitly_before_apply")
    Controller(value)  # Validate loopback authentication before writing anything.
    config = yaml_load(Path(template).read_bytes())
    providers = {}
    destination = Path(destination)
    _directory(destination.parent)
    provider_dir = destination.parent / "providers"
    _directory(provider_dir, create=True)
    ordered = sorted(value["sources"], key=lambda key: (key != nodes[selected][0], key))
    for source_id in ordered:
        cached = value["cache"].get(source_id, {}).get("nodes", [])
        if not cached:
            raise SourceError("refresh_all_configured_sources_before_apply")
        # The core rejects unknown proxy fields, and readable labels never belong
        # in deployed artifacts; hash the stripped list so filenames stay stable.
        stripped = sorted(({key: item for key, item in node.items() if key != "display"}
                           for node in cached), key=lambda node: node["name"] != selected)
        filename = source_id + "-" + hashlib.sha256(encode(stripped)).hexdigest()[:20] + ".json"
        atomic_write(provider_dir / filename, encode({"proxies": stripped}))
        providers["nmd-" + source_id] = {"type": "file", "path": "./providers/" + filename,
                                        "health-check": {"enable": False}}
    config["proxies"] = []
    config["proxy-providers"] = providers
    config["proxy-groups"] = [{"name": GROUP, "type": "select", "use": list(providers)}]
    config["rules"] = [rule if not rule.startswith("MATCH,") else "MATCH," + GROUP for rule in config["rules"]]
    config["external-controller"] = value["controller"]["url"].removeprefix("http://").rstrip("/")
    config["secret"] = value["controller"]["secret"]
    config["allow-lan"] = False
    config["profile"] = {"store-selected": False}
    atomic_write(destination, encode(config))  # JSON is a YAML subset.


def verify_observed(directory, before, observed):
    value = Store(directory).load()
    if current_node(value) != before:
        raise SourceError("selection_changed_during_verification")
    try:
        ip = ipaddress.ip_address(observed.strip())
    except ValueError:
        raise SourceError("egress_probe_failed") from None
    source_id, source, _ = inventory(value)[before]
    expected = source.get("expected_egress_ip")
    if expected and ip != ipaddress.ip_address(expected):
        raise SourceError("selected_source_egress_ip_mismatch")
    return {"source": source_id, "result": "verified_expected_ip" if expected else "https_observed_identity_unpinned",
            "ai_business": "not_tested"}


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        # argparse normally echoes rejected values, which may be secret URLs.
        raise SourceError("invalid_arguments_use_source_help")


def main(argv=None, directory=None, allow_directory_override=True):
    parser = Parser(prog="nmd source", description="Private sources; explicit refresh/select, no background tasks")
    if allow_directory_override:
        parser.add_argument("--sources-dir", type=Path, default=directory, required=directory is None)
    else:
        if directory is None:
            raise SourceError("installed_sources_require_recorded_directory")
        # Installed mode has no directory option at all. argparse rejects every
        # spelling, including equals syntax, before reads or mutations occur.
        parser.set_defaults(sources_dir=directory)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    for action in ("list", "nodes", "export", "status"):
        sub = commands.add_parser(action, help="redacted JSON only")
        if action == "status":
            sub.add_argument("--offline", action="store_true")
    for action in ("add", "update"):
        sub = commands.add_parser(action)
        sub.add_argument("id")
        sub.add_argument("--file", type=Path, required=True, help="owner-private JSON definition; never put URLs in argv")
    sub = commands.add_parser("rename", help="change only the Channel display name")
    sub.add_argument("id")
    sub.add_argument("--name", required=True)
    sub = commands.add_parser("remove")
    sub.add_argument("id")
    sub = commands.add_parser("refresh")
    sub.add_argument("id")
    group = sub.add_mutually_exclusive_group(required=True)
    group.add_argument("--fixture", type=Path, help="offline Clash YAML/JSON fixture")
    group.add_argument("--confirm", action="store_true", help="explicitly fetch the one private HTTPS URL")
    sub = commands.add_parser("select")
    sub.add_argument("node")
    group = sub.add_mutually_exclusive_group(required=True)
    group.add_argument("--defer", action="store_true", help="save desired selection only; next explicit apply")
    group.add_argument("--confirm", action="store_true", help="change running loopback selector and read back")
    sub = commands.add_parser("delay")
    sub.add_argument("node", help="manual single-node latency check via loopback controller")
    sub = commands.add_parser("auto")
    actions = sub.add_subparsers(dest="auto_action", required=True, parser_class=Parser)
    enable = actions.add_parser("enable", help="opt in to automatic failover between two pinned nodes")
    enable.add_argument("--primary", choices=["tailnet", "subscription"], help="legacy candidate order")
    enable.add_argument("--primary-node", help="explicit primary cached node")
    enable.add_argument("--secondary-node", help="explicit secondary cached node")
    enable.add_argument("--tailnet-node")
    enable.add_argument("--subscription-node")
    enable.add_argument("--fail-after", type=int)
    enable.add_argument("--recover-after", type=int)
    enable.add_argument("--cooldown", type=int)
    actions.add_parser("disable")
    actions.add_parser("swap", help="exchange the two existing candidates")
    primary_action = actions.add_parser("set-primary")
    primary_action.add_argument("--primary", required=True, choices=["tailnet", "subscription"])
    actions.add_parser("resume", help="clear the pause a manual tailnet selection caused")
    actions.add_parser("status")
    args = parser.parse_args(argv)
    store = Store(args.sources_dir)
    if args.command in {"list", "nodes", "status", "export"}:
        result = public_status(args.sources_dir, online=args.command == "status" and not args.offline,
                               include_display=args.command in {"nodes", "status"})
    elif args.command in {"add", "update"}:
        definition = json.loads(_private_file(args.file, owner=os.geteuid()))
        put_source(store, args.id, definition, replace=args.command == "update")
        result = {"result": "saved_pending_apply"}
    elif args.command == "rename":
        rename_source(store, args.id, args.name)
        result = {"result": "channel_renamed"}
    elif args.command == "refresh":
        refresh(store, args.id, args.fixture)
        result = {"result": "refreshed_pending_apply"}
    elif args.command == "select":
        select(store, args.node, deferred=args.defer)
        result = {"result": "saved_pending_apply" if args.defer else "selected_and_observed"}
    elif args.command == "delay":
        result = delay_test(args.sources_dir, args.node)
    elif args.command == "auto":
        if args.auto_action == "status":
            view = public_status(args.sources_dir, online=False)
            result = {"selection_mode": view["selection_mode"], "auto": view.get("auto"),
                      "desired": view["desired"]}
        else:
            payload = {"action": args.auto_action}
            if args.auto_action in {"enable", "set-primary"} and args.primary is not None:
                payload["primary"] = args.primary
            if args.auto_action == "enable":
                for key, argument in (("primary_node", "primary_node"),
                                      ("secondary_node", "secondary_node"),
                                      ("tailnet_node", "tailnet_node"),
                                      ("subscription_node", "subscription_node"),
                                      ("fail_after", "fail_after"),
                                      ("recover_after", "recover_after"),
                                      ("cooldown", "cooldown")):
                    if getattr(args, argument) is not None:
                        payload[key] = getattr(args, argument)
            result = auto_configure(store, payload)
    else:
        identifier(args.id)
        with store.edit() as value:
            if args.id not in value["sources"]:
                raise SourceError("source_not_found")
            if value.get("selected") in {node["name"] for node in value["cache"].get(args.id, {}).get("nodes", [])}:
                raise SourceError("selected_source_choose_another_first")
            _clear_auto_reference(value, args.id)
            del value["sources"][args.id]
            value["cache"].pop(args.id, None)
        result = {"result": "removed_pending_apply"}
    print(encode(result).decode())


def internal(argv):
    """Only local-setup uses this interface; all outputs/errors remain sanitized."""
    parser = Parser()
    parser.add_argument("action", choices=["render", "current", "verify"])
    parser.add_argument("--sources-dir", type=Path, required=True)
    parser.add_argument("--template", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--before")
    parser.add_argument("--observed")
    args = parser.parse_args(argv)
    if args.action == "render":
        render_runtime(args.sources_dir, args.template, args.output)
    elif args.action == "current":
        print(current_node(Store(args.sources_dir).load()))
    else:
        print(encode(verify_observed(args.sources_dir, args.before, args.observed)).decode())


if __name__ == "__main__":
    import sys
    try:
        internal(sys.argv[1:])
    except (SourceError, OSError, ValueError, TypeError, KeyError):
        print('{"error":"source_operation_failed_check_private_config_and_controller"}', file=sys.stderr)
        sys.exit(1)
