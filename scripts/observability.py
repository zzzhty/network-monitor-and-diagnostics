#!/usr/bin/env python3
"""Optional local diagnostic CLI and dashboard with local egress control, independent of deployment."""
import argparse
import contextlib
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
POST_ROUTES = {"/api/egress/select", "/api/egress/delay", "/api/egress/diagnose", "/api/auto",
               "/api/channels", "/api/channels/rename", "/api/channels/refresh", "/api/config",
               "/api/daemon/takeover/stop"}
MAX_BODY_BYTES = 4096
# A full 16-probe config stays well under this; load_config caps the file at 64 KiB.
MAX_CONFIG_BODY_BYTES = 16384


def default_state_dir():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        base = Path(base) if base else Path.home() / "AppData" / "Local"
        return base / "nmd-monitor"
    base = os.environ.get("XDG_STATE_HOME")
    if base and Path(base).is_absolute():
        return Path(base) / "nmd-monitor"
    return Path.home() / ".local/state/nmd-monitor"


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port, state_dir, sources_dir=None, config_path=None,
                 daemon_client=None):
        self.state_dir = Path(state_dir)
        self.sources_dir = (Path(sources_dir) if sources_dir is not None
                            and nmd_platform.name() == "linux" else None)
        # Monitor-config editing is the one non-Linux write: the user's own file.
        # Nothing is spawned, probed or deployed on save. Linux keeps CLI/systemd.
        self.config_path = (Path(config_path) if config_path is not None
                            and nmd_platform.name() in ("macos", "windows") else None)
        # Daemon mode (Phase C): the dashboard lives inside the user daemon and
        # relays exactly one privileged action over the bridge — stopping the
        # takeover. Starting one stays on the sudo CLI.
        self.daemon_client = daemon_client
        self.on_config_saved = None
        # Never offer a wildcard or user-supplied bind address in this MVP.
        super().__init__(("127.0.0.1", port), DashboardHandler)

    def capabilities(self):
        value = nmd_platform.capabilities()
        enabled = nmd_platform.name() == 'linux' and self.sources_dir is not None
        config_enabled = self.config_path is not None
        value.update(local_egress_control=enabled, channel_management=enabled,
                     config_management=config_enabled, read_only_gui=not (enabled or config_enabled))
        if self.daemon_client is not None:
            daemon_view = self.daemon_client.status_cached()
            value.update(daemon=True, daemon_available="error" not in daemon_view,
                         takeover_active=bool(daemon_view.get("takeover_active")),
                         daemon_boot_policy=daemon_view.get("on_boot"))
        return value

    def read_config_status(self):
        """Current config plus existence; a missing file still edits defaults."""
        if not self.config_path.is_file():
            return {"config": nmd_monitor.validate_config({}), "exists": False}
        try:
            return {"config": nmd_monitor.load_config(self.config_path), "exists": True}
        except (OSError, ValueError):
            raise ValueError('config_invalid') from None


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
        elif path == "/api/config":
            if self.server.config_path is None:
                self.json_response(405, {"error": "read_only"})
                return
            try:
                status = self.server.read_config_status()
            except ValueError:
                self.json_response(409, {"schema_version": 1, "error": "config_invalid"})
            else:
                self.json_response(200, {"schema_version": 1, "config_path": str(self.server.config_path),
                                         "exists": status["exists"], "config": status["config"]})
        elif path == "/api/daemon/status":
            if self.server.daemon_client is None:
                self.json_response(404, {"error": "not_found"})
                return
            view = self.server.daemon_client.status_cached()
            if "error" in view:
                self.json_response(503, {"schema_version": 1, "error": "daemon_unavailable"})
            else:
                self.json_response(200, view)
        elif path in {"/", "/app.js", "/style.css", "/logo.png"}:
            name, mime = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                "/style.css": ("style.css", "text/css; charset=utf-8"),
                "/logo.png": ("logo.png", "image/png"),
            }[path]
            try:
                self.send_body(200, (ROOT / "web" / name).read_bytes(), mime)
            except OSError:
                self.json_response(503, {"error": "dashboard_assets_unavailable"})
        else:
            self.json_response(404, {"error": "not_found"})

    def _read_json_body(self, max_bytes=MAX_BODY_BYTES):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = 0
        if not 1 <= length <= max_bytes or not self.headers.get("Content-Type", "").startswith("application/json"):
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
        # The diagnosis battery is entirely server-fixed; the body must be empty.
        if path == "/api/egress/diagnose" and body != {}:
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
            elif path == "/api/egress/diagnose":
                # Read-only layered battery against fixed public targets; the
                # same trust level as the manual delay button, no store writes.
                import egress_diagnose
                self.json_response(200, egress_diagnose.build_report(self.server.sources_dir))
            else:
                self.json_response(200, egress_sources.auto_configure(
                    egress_sources.Store(self.server.sources_dir), body))
        except egress_sources.SourceError as exc:
            self.json_response(409, {"schema_version": 1, "error": str(exc)})
        except Exception:
            self.json_response(503, {"schema_version": 1, "error": "sources_unavailable"})

    def _config_post(self, body):
        """The only non-Linux config write: strictly the user's own monitor file."""
        if set(body) != {"config"} or not isinstance(body["config"], dict):
            self.json_response(400, {"error": "invalid_body"})
            return
        try:
            saved = nmd_monitor.save_config(self.server.config_path, body["config"])
        except ValueError as exc:
            self.json_response(409, {"schema_version": 1, "error": str(exc)})
            return
        except OSError:
            self.json_response(503, {"schema_version": 1, "error": "config_unavailable"})
            return
        # Saving never starts, restarts or probes anything by itself; in daemon
        # mode the supervisor reloads the collector via the save hook, and a
        # standalone `nmd monitor run` picks the new file up on its next start.
        if self.server.on_config_saved is not None:
            with contextlib.suppress(Exception):
                self.server.on_config_saved()
        self.json_response(200, {"result": "config_saved", "config_path": str(self.server.config_path),
                                 "config": saved})

    def _daemon_stop_post(self, body):
        """The panel's only privileged action: stop the takeover, never start."""
        if body != {}:
            self.json_response(400, {"error": "invalid_body"})
            return
        reply = self.server.daemon_client.stop_takeover()
        if "error" in reply:
            self.json_response(503, {"schema_version": 1, "error": "daemon_unavailable"})
            return
        import nmd_daemon
        if not nmd_daemon.stop_result_finished(reply):
            self.json_response(409, {"schema_version": 1, "error": "rollback_incomplete",
                                     "daemon": reply})
            return
        self.json_response(200, {"result": "stop_requested", "daemon": reply})

    def do_POST(self):
        if self._guard() is None:
            return
        path = self._clean_path()
        if path is None:
            return
        if path not in POST_ROUTES:
            self.json_response(405, {"error": "method_not_allowed"})
            return
        if path == "/api/config":
            if self.server.config_path is None:
                self.json_response(405, {"error": "read_only"})
                return
        elif path == "/api/daemon/takeover/stop":
            if self.server.daemon_client is None:
                self.json_response(405, {"error": "read_only"})
                return
        else:
            if nmd_platform.name() != "linux":
                self.json_response(405, {"error": "read_only"})
                return
            if self.server.sources_dir is None:
                self.json_response(503, {"schema_version": 1, "error": "sources_unavailable"})
                return
        body = self._read_json_body(MAX_CONFIG_BODY_BYTES if path == "/api/config" else MAX_BODY_BYTES)
        if body is not None:
            if path == "/api/config":
                self._config_post(body)
            elif path == "/api/daemon/takeover/stop":
                self._daemon_stop_post(body)
            else:
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


def serve_dashboard(port, state_dir, sources_dir=None, config_path=None,
                    daemon_client=None, collector_note="collector runs separately"):
    if not 0 <= port <= 65535:
        raise ValueError('invalid_port')
    with DashboardServer(port, state_dir, sources_dir, config_path=config_path,
                         daemon_client=daemon_client) as server:
        capabilities = server.capabilities()
        mode = ("daemon" if capabilities.get("daemon")
                else "local egress control" if capabilities["local_egress_control"]
                else "monitor configuration" if capabilities["config_management"] else "read-only")
        print(f"Dashboard: http://127.0.0.1:{server.server_address[1]}/ ({mode}; {collector_note})", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return server


def cli_parser(state_dir=None, config_file=None, sources_dir=None):
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
    status.add_argument("--dry-run", action="store_true",
                        help="print a synthetic snapshot and exit; do not read the host or a state directory")
    check = actions.add_parser("config-check", help="validate configuration without sending probes")
    check.add_argument("--config", type=Path, required=config_file is None, default=config_file)
    gui = commands.add_parser("gui", help="local browser dashboard with node switching; collector is separate")
    gui.add_argument("--state-dir", type=Path, default=state_dir or default_state_dir())
    gui.add_argument("--config", type=Path, default=config_file,
                     help="monitor config file editable on the dashboard (macOS and Windows)")
    gui.add_argument("--port", type=int, default=8765)
    gui.add_argument("--dry-run", action="store_true",
                     help="serve a synthetic dashboard; no host collection or private sources")
    machine = commands.add_parser("machine", help="versioned machine-readable interface")
    machine.add_argument("action", choices=["capabilities", "status"])
    machine.add_argument("--state-dir", type=Path, default=state_dir or default_state_dir())
    return parser


def run_synthetic(parser, args):
    if not getattr(args, "dry_run", False):
        return False
    if args.command == "monitor" and args.action == "status":
        with demo_state() as state:
            print_json(nmd_monitor.read_snapshot(state))
        return True
    if args.command == "gui":
        if not 0 <= args.port <= 65535:
            parser.error("port must be between 0 and 65535")
        with demo_state() as state:
            print("模拟演示：所有样本均为合成数据，不代表本机网络状态。", flush=True)
            serve_dashboard(args.port, state, sources_dir=None, config_path=None)
        return True
    return False


def run_synthetic_if_requested(argv):
    # Only these two forms support synthetic data and have no required
    # arguments that depend on installed defaults. Parse them normally before
    # resolving the installation, preserving argparse's flags and validation.
    if not (argv[:1] == ["gui"] or argv[:2] == ["monitor", "status"]):
        return False
    parser = cli_parser()
    return run_synthetic(parser, parser.parse_args(argv))


def main(argv=None, state_dir=None, config_file=None, sources_dir=None):
    parser = cli_parser(state_dir, config_file, sources_dir)
    args = parser.parse_args(argv)
    if run_synthetic(parser, args):
        return
    if (args.command == "monitor" and args.action == "run"
            and args.sources_dir is not None and nmd_platform.name() != "linux"):
        parser.error("automatic egress source control is unsupported on this platform")
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
        # Linux owns monitor config via the CLI and the systemd install.
        # macOS and Windows edit that same file from the dashboard; a missing
        # file starts from validated defaults and does not start collection.
        config_path = args.config
        if config_path is None and nmd_platform.name() in ("macos", "windows"):
            config_path = nmd_monitor.default_config_path()
        serve_dashboard(args.port, args.state_dir, sources_dir, config_path=config_path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        # CLI diagnostics should not leak target credentials or command output.
        print_json({"schema_version": 1, "error": type(exc).__name__, "message": "diagnostics operation failed; check config, state permissions, or collector lock"})
        raise SystemExit(1)
