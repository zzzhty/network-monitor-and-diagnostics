#!/usr/bin/env python3
"""Optional local diagnostic CLI and dashboard with local egress control, independent of deployment."""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import threading
import tempfile
import time
from urllib.parse import urlsplit

import nmd_monitor
import nmd_platform

ROOT = Path(__file__).resolve().parents[1]
# Fixed local controls and save-only Channel metadata share the source backend.
# GUI subscription refresh reuses the CLI --confirm path; deployment stays CLI-only.
NODE_ID = re.compile(r"nmd-[a-z][a-z0-9-]{0,31}-[a-f0-9]{20}")
POST_ROUTES = {"/api/egress/select", "/api/egress/delay", "/api/auto",
               "/api/channels", "/api/channels/rename", "/api/channels/refresh"}
MAX_BODY_BYTES = 4096


def default_state_dir():
    base = os.environ.get("XDG_STATE_HOME")
    if base and Path(base).is_absolute():
        return Path(base) / "nmd-monitor"
    return Path.home() / ".local/state/nmd-monitor"


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port, state_dir, sources_dir=None):
        self.state_dir = Path(state_dir)
        self.sources_dir = (Path(sources_dir) if sources_dir is not None
                            and nmd_platform.name() == "linux" else None)
        # Never offer a wildcard or user-supplied bind address in this MVP.
        super().__init__(("127.0.0.1", port), DashboardHandler)

    def capabilities(self):
        value = nmd_platform.capabilities()
        enabled = nmd_platform.name() == 'linux' and self.sources_dir is not None
        value.update(local_egress_control=enabled, channel_management=enabled, read_only_gui=not enabled)
        return value


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "NMDLocalDashboard"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        # URLs and diagnostic paths do not belong in access logs by default.
        pass

    def send_body(self, code, body, content_type="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, code, value):
        self.send_body(code, json.dumps(value, ensure_ascii=False, allow_nan=False).encode())

    def _guard(self):
        """Host and origin defense shared by every method; responds itself."""
        port = self.server.server_address[1]
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        host = self.headers.get("Host", "")
        if host not in allowed_hosts:
            self.json_response(403, {"error": "host_not_allowed"})
            return None
        # The static shell may open as a top-level document from a link. It
        # contains no state; private APIs still reject every cross-site request.
        # Fetch metadata cannot be set by website JS; CSP also forbids framing.
        origin = self.headers.get("Origin")
        shell_navigation = (self.command == "GET" and self.path == "/" and origin is None
                            and self.headers.get("Sec-Fetch-Mode") == "navigate"
                            and self.headers.get("Sec-Fetch-Dest") == "document")
        if ((origin is not None and origin != "http://" + host)
                or (self.headers.get("Sec-Fetch-Site") == "cross-site" and not shell_navigation)):
            self.json_response(403, {"error": "origin_not_allowed"})
            return None
        return host

    def _clean_path(self):
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self.json_response(400, {"error": "invalid_path"})
            return None
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            self.json_response(400, {"error": "invalid_path"})
            return None
        return parsed.path

    def do_GET(self):
        if self._guard() is None:
            return
        path = self._clean_path()
        if path is None:
            return
        if path == "/api/capabilities":
            self.json_response(200, self.server.capabilities())
        elif path == "/api/snapshot":
            try:
                value = nmd_monitor.read_snapshot(self.server.state_dir, limit=100)
                self.json_response(200, value)
            except Exception:
                # A corrupt/unreadable database is not an empty healthy history.
                self.json_response(503, {"schema_version": 1, "error": "snapshot_unavailable"})
        elif path == "/api/sources":
            try:
                import egress_sources
                value = (egress_sources.public_status(self.server.sources_dir, include_display=True)
                         if self.server.sources_dir is not None else
                         {"schema_version": 1, "sources": [], "active": None, "controller": "not_configured"})
                self.json_response(200, value)
            except Exception:
                # System GUI's service UID cannot read root-private sources.
                self.json_response(503, {"schema_version": 1, "error": "sources_unavailable", "active": None})
        elif path in {"/", "/app.js", "/style.css"}:
            name, mime = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                "/style.css": ("style.css", "text/css; charset=utf-8"),
            }[path]
            try:
                self.send_body(200, (ROOT / "web" / name).read_bytes(), mime)
            except OSError:
                self.json_response(503, {"error": "dashboard_assets_unavailable"})
        else:
            self.json_response(404, {"error": "not_found"})

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = 0
        if not 1 <= length <= MAX_BODY_BYTES or not self.headers.get("Content-Type", "").startswith("application/json"):
            self.json_response(400, {"error": "invalid_body"})
            return None
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self.json_response(400, {"error": "invalid_body"})
            return None
        if not isinstance(body, dict):
            self.json_response(400, {"error": "invalid_body"})
            return None
        return body

    def _egress_post(self, path, body):
        """Strict fixed-key bodies; the delay URL is a server constant, never input."""
        import egress_sources
        if path in {"/api/egress/select", "/api/egress/delay"}:
            node = body.get("node")
            if set(body) != {"node"} or not isinstance(node, str) or not NODE_ID.fullmatch(node):
                self.json_response(400, {"error": "invalid_body"})
                return
        if path in {"/api/channels", "/api/channels/rename"}:
            required = {"id", "definition"} if path == "/api/channels" else {"id", "display_name"}
            if (set(body) != required or not isinstance(body.get("id"), str)
                    or (path == "/api/channels" and not isinstance(body.get("definition"), dict))):
                self.json_response(400, {"error": "invalid_body"})
                return
        if path == "/api/channels/refresh" and (set(body) != {"id"} or not isinstance(body.get("id"), str)):
            self.json_response(400, {"error": "invalid_body"})
            return
        try:
            if path == "/api/channels":
                egress_sources.put_source(egress_sources.Store(self.server.sources_dir), body["id"], body["definition"])
                self.json_response(200, {"result": "saved_pending_apply"})
            elif path == "/api/channels/rename":
                egress_sources.rename_source(egress_sources.Store(self.server.sources_dir), body["id"], body["display_name"])
                self.json_response(200, {"result": "channel_renamed"})
            elif path == "/api/channels/refresh":
                # Same semantics as "nmd channel refresh --confirm": one real HTTPS
                # fetch of the stored private URL; no fixture/force/apply parameters.
                egress_sources.refresh(egress_sources.Store(self.server.sources_dir), body["id"])
                self.json_response(200, {"result": "refreshed_pending_apply"})
            elif path == "/api/egress/select":
                egress_sources.select(egress_sources.Store(self.server.sources_dir), node)
                self.json_response(200, {"result": "selected_and_observed", "active": node})
            elif path == "/api/egress/delay":
                self.json_response(200, egress_sources.delay_test(self.server.sources_dir, node))
            else:
                self.json_response(200, egress_sources.auto_configure(
                    egress_sources.Store(self.server.sources_dir), body))
        except egress_sources.SourceError as exc:
            self.json_response(409, {"schema_version": 1, "error": str(exc)})
        except Exception:
            self.json_response(503, {"schema_version": 1, "error": "sources_unavailable"})

    def do_POST(self):
        if self._guard() is None:
            return
        path = self._clean_path()
        if path is None:
            return
        if path not in POST_ROUTES:
            self.json_response(405, {"error": "method_not_allowed"})
            return
        if nmd_platform.name() != "linux":
            self.json_response(405, {"error": "read_only"})
            return
        if self.server.sources_dir is None:
            self.json_response(503, {"schema_version": 1, "error": "sources_unavailable"})
            return
        body = self._read_json_body()
        if body is not None:
            self._egress_post(path, body)

    def do_PUT(self):
        self.json_response(405, {"error": "method_not_allowed"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT
    do_OPTIONS = do_PUT


def print_json(value):
    print(json.dumps(value, ensure_ascii=False, allow_nan=False))


@contextmanager
def demo_state():
    """Disposable, explicitly synthetic evidence. Never read host or tool state."""
    with tempfile.TemporaryDirectory(prefix='nmd-demo-') as temporary:
        state = Path(temporary)
        store = nmd_monitor.Store(state, {})
        try:
            store.setmeta('data_origin', 'demo')
            now = time.time()
            for offset in (60, 30, 0):
                at = now - offset
                store.record([dict(id='demo-http', type='http', path='system',
                                   status='failure', error='synthetic_timeout',
                                   timings={}, observed_at=at, synthetic=True)], now=at)
            store.record([dict(id='local', type='passive', path='local', platform=nmd_platform.name(),
                               status='unknown', error='synthetic_demo', interfaces=['demo0'],
                               interface_states={'demo0': 'unknown'}, services={},
                               service_observation_error='synthetic_demo', timings={},
                               observed_at=now, synthetic=True)], now=now)
        finally:
            store.close()
        yield state


def serve_dashboard(port, state_dir, sources_dir=None):
    if not 0 <= port <= 65535:
        raise ValueError('invalid_port')
    with DashboardServer(port, state_dir, sources_dir) as server:
        mode = "read-only" if server.capabilities()["read_only_gui"] else "local egress control"
        print(f"Dashboard: http://127.0.0.1:{server.server_address[1]}/ ({mode}; collector runs separately)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


def main(argv=None, state_dir=None, config_file=None, sources_dir=None):
    parser = argparse.ArgumentParser(prog="nmd", description="Network Monitor & Diagnostics: independent diagnostics (no network configuration changes)")
    commands = parser.add_subparsers(dest="command", required=True)
    mon = commands.add_parser("monitor", help="continuous diagnostics and recorded history")
    actions = mon.add_subparsers(dest="action", required=True)
    run = actions.add_parser("run", help="foreground collector; stop with Ctrl-C")
    run.add_argument("--config", type=Path, required=config_file is None, default=config_file)
    run.add_argument("--state-dir", type=Path, default=state_dir or default_state_dir())
    run.add_argument("--sources-dir", type=Path, default=sources_dir,
                     help="private egress registry; enables automatic failover evaluation")
    run.add_argument("--once", action="store_true")
    status = actions.add_parser("status", help="read recorded state without starting probes")
    status.add_argument("--state-dir", type=Path, default=state_dir or default_state_dir())
    check = actions.add_parser("config-check", help="validate configuration without sending probes")
    check.add_argument("--config", type=Path, required=config_file is None, default=config_file)
    gui = commands.add_parser("gui", help="local browser dashboard with node switching; collector is separate")
    gui.add_argument("--state-dir", type=Path, default=state_dir or default_state_dir())
    gui.add_argument("--port", type=int, default=8765)
    machine = commands.add_parser("machine", help="versioned machine-readable interface")
    machine.add_argument("action", choices=["capabilities", "status"])
    machine.add_argument("--state-dir", type=Path, default=state_dir or default_state_dir())
    demo = commands.add_parser("demo", help="temporary synthetic dashboard; no host collection or private sources")
    demo.add_argument("--once", action="store_true", help="print a synthetic snapshot and exit without a server")
    demo.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if (args.command == "monitor" and args.action == "run"
            and args.sources_dir is not None and nmd_platform.name() != "linux"):
        parser.error("automatic egress source control is unsupported on this platform")
    if args.command == "demo":
        if not 0 <= args.port <= 65535:
            parser.error("port must be between 0 and 65535")
        with demo_state() as state:
            if args.once:
                print_json(nmd_monitor.read_snapshot(state))
            else:
                print("模拟演示：所有样本均为合成数据，不代表本机网络状态。", flush=True)
                serve_dashboard(args.port, state, sources_dir=None)
        return
    if args.command == "machine" and args.action == "capabilities":
        print_json(nmd_platform.capabilities())
    elif args.command == "machine" or (args.command == "monitor" and args.action == "status"):
        print_json(nmd_monitor.read_snapshot(args.state_dir, limit=100))
    elif args.command == "monitor" and args.action == "config-check":
        config = nmd_monitor.load_config(args.config)
        print_json({"schema_version": 1, "valid": True, "probe_count": len(config["probes"])})
    elif args.command == "monitor":
        config = nmd_monitor.load_config(args.config)
        stopped = threading.Event()
        previous = {}
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, lambda *_: stopped.set())
            nmd_monitor.collect(config, args.state_dir, once=args.once, stop_event=stopped,
                                sources_dir=args.sources_dir)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    else:
        if not 0 <= args.port <= 65535:
            parser.error("port must be between 0 and 65535")
        serve_dashboard(args.port, args.state_dir, sources_dir)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        # CLI diagnostics should not leak target credentials or command output.
        print_json({"schema_version": 1, "error": type(exc).__name__, "message": "diagnostics operation failed; check config, state permissions, or collector lock"})
        raise SystemExit(1)
