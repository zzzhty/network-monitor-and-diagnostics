"""Offline tests for the macOS geodata ensure step.

No test contacts the network. A fake transport stands in for the MetaCubeX
release. These fixtures are not a real-Mac download, and they do not cover
sleep, wake, or watchdog restore.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))

import macos_geodata as geodata
import macos_preflight as pf
import macos_takeover
import manager
import nmd_daemon
import nmd_platform

SITE = (b"\x0a" + b"\x1d" + b"geosite-fixture-bytes-ok!!").ljust(32, b"\x00")
MMDB = b"\x00" * 128 + b"\xab\xcd\xefMaxMind.com"
TOKEN = "NMDGEODATATOKEN"
TAILNET = "fd7a:115c:a1e0::abcd"
PLACEHOLDER = "203.0.113.20"


def _payloads(**overrides):
    bodies = {"geosite.dat": SITE, "geoip.metadb": MMDB}
    bodies.update(overrides)
    return bodies


def _transport(bodies, calls=None):
    def transport(url, *, max_bytes):
        if calls is not None:
            calls.append(url)
        name = url.rsplit("/", 1)[-1]
        if name.endswith(".sha256sum"):
            asset = name[: -len(".sha256sum")]
            data = bodies[asset]
            text = hashlib.sha256(data).hexdigest() + "  " + asset + "\n"
            raw = text.encode("ascii")
        else:
            raw = bodies[name]
        if len(raw) > max_bytes:
            raise geodata.GeodataError("too_large")
        return raw
    return transport


def _private(path):
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


class FormatTests(unittest.TestCase):
    def test_format_rejects_html_and_accepts_the_real_shapes(self):
        self.assertTrue(geodata.valid_geosite(SITE))
        self.assertTrue(geodata.valid_mmdb(MMDB))
        self.assertFalse(geodata.valid_geosite(b"<html>nope</html>" + b"\x00" * 32))
        self.assertFalse(geodata.valid_geosite(b"\x0a" + b"short"))
        self.assertFalse(geodata.valid_mmdb(b"\x00" * 200))
        self.assertFalse(geodata.valid_mmdb(b"<html>" + b"\x00" * 200))
        html = b"<html>checksum</html>"
        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.parse_sha256sum(html, "geosite.dat")
        self.assertEqual(caught.exception.reason, "checksum_rejected")
        digest = hashlib.sha256(SITE).hexdigest()
        self.assertEqual(geodata.parse_sha256sum(
            f"{digest}  geosite.dat\n".encode(), "geosite.dat"), digest)
        with self.assertRaises(geodata.GeodataError):
            geodata.parse_sha256sum(f"{digest}  geoip.dat\n".encode(), "geosite.dat")

    def test_urls_are_the_fetch_assets_release(self):
        script = (ROOT / "fetch-assets.sh").read_text(encoding="utf-8")
        self.assertIn(geodata.GEOSITE_URL, script)
        self.assertIn(geodata.GEOIP_URL, script)
        self.assertEqual(geodata.SOURCES["geosite.dat"]["checksum_url"],
                         geodata.GEOSITE_URL + ".sha256sum")
        self.assertEqual(geodata.SOURCES["geoip.metadb"]["checksum_url"],
                         geodata.GEOIP_URL + ".sha256sum")
        self.assertNotIn("geoip.dat", geodata.SOURCES)


class FetchPolicyTests(unittest.TestCase):
    def test_redirects_stay_on_the_release_hosts_and_reads_are_bounded(self):
        class Response:
            def __init__(self, status, body=b"", headers=None):
                self.status = status
                self.headers = headers or {}
                self._body = body
                self._off = 0

            def read(self, n=-1):
                if self._off >= len(self._body):
                    return b""
                if n is None or n < 0:
                    n = len(self._body) - self._off
                chunk = self._body[self._off:self._off + n]
                self._off += len(chunk)
                return chunk

            def getcode(self):
                return self.status

            def close(self):
                pass

        class Opener:
            def __init__(self, responses):
                self.responses = list(responses)
                self.urls = []

            def open(self, request, timeout=None):
                self.urls.append(request.full_url)
                item = self.responses.pop(0)
                if isinstance(item, Exception):
                    raise item
                return item

        evil = Opener([Response(302, headers={"Location": "https://example.com/evil"})])
        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.fetch_https(geodata.GEOSITE_URL, max_bytes=100, opener=evil)
        self.assertEqual(caught.exception.reason, "redirect_rejected")
        self.assertNotIn("example.com", str(caught.exception))

        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.fetch_https("http://github.com/MetaCubeX/geosite.dat",
                                max_bytes=100, opener=Opener([]))
        self.assertEqual(caught.exception.reason, "redirect_rejected")

        hops = [Response(302, headers={"Location": f"https://github.com/hop/{i}"})
                for i in range(8)]
        hopped = Opener(hops)
        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.fetch_https(geodata.GEOSITE_URL, max_bytes=100, opener=hopped)
        self.assertEqual(caught.exception.reason, "redirect_rejected")
        self.assertLessEqual(len(hopped.urls), geodata._MAX_REDIRECTS + 1)

        good = Opener([
            Response(302, headers={
                "Location": "https://release-assets.githubusercontent.com/geosite.dat"}),
            Response(200, SITE, headers={
                "Content-Length": str(len(SITE)),
                "Content-Type": "application/octet-stream"}),
        ])
        self.assertEqual(geodata.fetch_https(geodata.GEOSITE_URL, max_bytes=1000, opener=good),
                         SITE)

        html = Opener([Response(200, b"<html>no</html>", headers={
            "Content-Type": "text/html", "Content-Length": "14"})])
        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.fetch_https(geodata.GEOSITE_URL, max_bytes=100, opener=html)
        self.assertEqual(caught.exception.reason, "html_body")

        short = Opener([Response(200, b"abcd", headers={"Content-Length": "10"})])
        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.fetch_https(geodata.GEOSITE_URL, max_bytes=100, opener=short)
        self.assertEqual(caught.exception.reason, "truncated")

        huge = Opener([Response(200, b"x" * 50, headers={"Content-Length": "50"})])
        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.fetch_https(geodata.GEOSITE_URL, max_bytes=10, opener=huge)
        self.assertEqual(caught.exception.reason, "too_large")

        class Slow(Response):
            def read(self, n=-1):
                time.sleep(0.2)
                return super().read(n)

        slow = Opener([Slow(200, b"abcdef", headers={"Content-Length": "6"})])
        with self.assertRaises(geodata.GeodataError) as caught:
            geodata.fetch_https(geodata.GEOSITE_URL, max_bytes=100, read_timeout=0.01,
                                opener=slow)
        self.assertEqual(caught.exception.reason, "timeout")


class EnsureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.geo = _private(self.base / "geo")
        env = patch.dict(os.environ, {"HOME": str(self.base / "home")}, clear=False)
        env.start()
        self.addCleanup(env.stop)

    def test_missing_files_are_installed_and_then_preflight_passes(self):
        calls = []
        result = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=True,
            transport=_transport(_payloads(), calls))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["downloaded"], ["geosite.dat", "geoip.metadb"])
        self.assertEqual((self.geo / "geosite.dat").read_bytes(), SITE)
        self.assertEqual((self.geo / "geoip.metadb").read_bytes(), MMDB)
        self.assertEqual(stat.S_IMODE((self.geo / "geosite.dat").stat().st_mode), 0o600)
        self.assertEqual(pf.probe_geodata(self.geo, True, True)["status"], "pass")
        self.assertTrue(any(url.endswith("/geosite.dat") for url in calls))
        self.assertTrue(any(url.endswith("/geoip.metadb") for url in calls))

    def test_present_files_do_not_use_the_network_or_change_mode(self):
        site = self.geo / "geosite.dat"
        ip = self.geo / "geoip.metadb"
        site.write_bytes(SITE)
        ip.write_bytes(MMDB)
        os.chmod(site, 0o644)
        os.chmod(self.geo, 0o755)
        calls = []
        result = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=True,
            transport=_transport(_payloads(), calls))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["downloaded"], [])
        self.assertEqual(calls, [])
        self.assertEqual(stat.S_IMODE(site.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.geo.stat().st_mode), 0o755)

    def test_only_the_rule_that_is_used_is_downloaded(self):
        calls = []
        site_only = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=False,
            transport=_transport(_payloads(), calls))
        self.assertEqual(site_only["downloaded"], ["geosite.dat"])
        self.assertFalse((self.geo / "geoip.metadb").exists())
        self.assertFalse(any(url.endswith("/geoip.metadb") for url in calls))
        other = _private(self.base / "ip-only")
        ip_calls = []
        ip_only = geodata.ensure_into(
            other, needs_site=False, needs_ip=True,
            transport=_transport(_payloads(), ip_calls))
        self.assertEqual(ip_only["downloaded"], ["geoip.metadb"])
        self.assertFalse((other / "geosite.dat").exists())
        self.assertFalse(any("geosite.dat" in url for url in ip_calls))
        neither = geodata.ensure_into(
            self.geo, needs_site=False, needs_ip=False,
            transport=_transport(_payloads(), []))
        self.assertTrue(neither["ok"])
        self.assertEqual(neither["needed"], [])

    def test_country_mmdb_and_folded_geosite_skip_the_download(self):
        (self.geo / "GeoSite.dat").write_bytes(SITE)
        (self.geo / "Country.mmdb").write_bytes(MMDB)
        calls = []
        result = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=True,
            transport=_transport(_payloads(), calls))
        self.assertTrue(result["ok"], result)
        self.assertEqual(calls, [])
        self.assertFalse((self.geo / "geosite.dat").exists())
        self.assertFalse((self.geo / "geoip.metadb").exists())

    def test_geoip_dat_alone_does_not_count_and_is_left_in_place(self):
        dat = self.geo / "geoip.dat"
        dat.write_bytes(b"classic-dat-not-mmdb")
        calls = []
        result = geodata.ensure_into(
            self.geo, needs_site=False, needs_ip=True,
            transport=_transport(_payloads(), calls))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["downloaded"], ["geoip.metadb"])
        self.assertEqual(dat.read_bytes(), b"classic-dat-not-mmdb")
        self.assertTrue(any(url.endswith("/geoip.metadb") for url in calls))
        self.assertFalse(any(url.endswith("/geoip.dat") for url in calls))

    def test_failed_download_keeps_the_previous_file_and_writes_no_partial(self):
        existing = self.geo / "geosite.dat"
        existing.write_bytes(SITE)
        os.chmod(existing, 0o640)

        def transport(url, *, max_bytes):
            raise geodata.GeodataError("timeout")

        result = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=True, transport=transport)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "timeout")
        self.assertEqual(existing.read_bytes(), SITE)
        self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o640)
        self.assertFalse((self.geo / "geoip.metadb").exists())
        self.assertFalse(any(path.name.startswith(".geosite") or path.name.startswith(".geoip")
                             for path in self.geo.iterdir()))

    def test_html_and_checksum_mismatch_are_not_installed(self):
        html = b"<html>not a database</html>" + b"\x00" * 16
        calls = []
        result = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=False,
            transport=_transport(_payloads(**{"geosite.dat": html}), calls))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "format_rejected")
        self.assertFalse((self.geo / "geosite.dat").exists())
        self.assertEqual(sum(url.endswith("/geosite.dat") for url in calls), 1)

        def mismatch(url, *, max_bytes):
            calls.append(url)
            if url.endswith(".sha256sum"):
                return (hashlib.sha256(b"other").hexdigest() + "  geosite.dat\n").encode()
            return SITE

        calls.clear()
        result = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=False, transport=mismatch)
        self.assertEqual(result["reason"], "checksum_mismatch")
        self.assertFalse((self.geo / "geosite.dat").exists())
        self.assertGreaterEqual(sum(url.endswith("/geosite.dat") for url in calls), 1)
        self.assertLessEqual(sum(url.endswith("/geosite.dat") for url in calls), 3)

    def test_corrupt_owned_file_is_replaced_only_after_a_valid_download(self):
        html = self.geo / "geosite.dat"
        html.write_bytes(b"<html>old</html>" + b"\x00" * 32)
        real_replace = os.replace

        def boom(src, dst):
            raise OSError("disk")

        with patch.object(geodata.os, "replace", side_effect=boom):
            failed = geodata.ensure_into(
                self.geo, needs_site=True, needs_ip=False,
                transport=_transport(_payloads()))
        self.assertFalse(failed["ok"])
        self.assertEqual(html.read_bytes()[:6], b"<html>")
        self.assertFalse(any(path.name.startswith(".geosite") for path in self.geo.iterdir()))

        replaced = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=False,
            transport=_transport(_payloads()))
        self.assertTrue(replaced["ok"], replaced)
        self.assertEqual(html.read_bytes(), SITE)
        self.assertIs(os.replace, real_replace)

    def test_symlink_and_foreign_owner_are_not_overwritten(self):
        secret = self.base / "secret"
        secret.write_bytes(b"secret-bytes")
        link = self.geo / "geosite.dat"
        link.symlink_to(secret)
        calls = []
        result = geodata.ensure_into(
            self.geo, needs_site=True, needs_ip=False,
            transport=_transport(_payloads(), calls))
        self.assertEqual(result["reason"], "symlink")
        self.assertTrue(link.is_symlink())
        self.assertEqual(secret.read_bytes(), b"secret-bytes")
        self.assertEqual(calls, [])

        foreign = _private(self.base / "foreign")
        kept = foreign / "geosite.dat"
        kept.write_bytes(b"keep-me")
        mode = stat.S_IFREG | 0o600
        uid = 0 if os.geteuid() != 0 else 1
        info = os.stat_result((mode, 1, 1, 1, uid, os.getgid(), 0, 0, 0, 0))

        class Entry:
            name = "geosite.dat"
            path = str(kept)

            def stat(self, follow_symlinks=True):
                return info

        with patch.object(geodata.os, "scandir", return_value=[Entry()]):
            blocked = geodata.ensure_into(
                foreign, needs_site=True, needs_ip=False,
                transport=_transport(_payloads(), calls))
        self.assertEqual(blocked["reason"], "foreign_owner")
        self.assertEqual(kept.read_bytes(), b"keep-me")
        self.assertEqual(calls, [])

    def test_concurrent_ensure_downloads_once(self):
        calls = []
        gate = threading.Event()

        def transport(url, *, max_bytes):
            calls.append(url)
            if url.endswith("/geosite.dat") and not gate.is_set():
                gate.set()
                time.sleep(0.15)
            return _transport(_payloads())(url, max_bytes=max_bytes)

        errors = []

        def worker():
            try:
                result = geodata.ensure_into(
                    self.geo, needs_site=True, needs_ip=False, transport=transport)
                if not result["ok"]:
                    errors.append(result)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(errors, [])
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual((self.geo / "geosite.dat").read_bytes(), SITE)
        self.assertEqual(sum(url.endswith("/geosite.dat") for url in calls), 1)

    def test_explicit_directory_is_the_only_destination(self):
        explicit = _private(self.base / "explicit")
        result = geodata.ensure_into(
            explicit, needs_site=True, needs_ip=True, transport=_transport(_payloads()))
        self.assertEqual(Path(result["directory"]), explicit)
        self.assertTrue((explicit / "geosite.dat").is_file())
        self.assertFalse((self.base / "home" / ".config" / "mihomo").exists())

    def test_root_refuses_before_creating_a_directory(self):
        missing = self.base / "not-created"
        with patch.object(geodata.os, "geteuid", return_value=0):
            result = geodata.ensure_into(
                missing, needs_site=True, needs_ip=True, create=True,
                transport=_transport(_payloads()))
        self.assertEqual(result["reason"], "root_refused")
        self.assertFalse(missing.exists())

    def test_user_files_are_the_ones_root_and_the_config_owner_would_copy(self):
        home = _private(self.base / "alice")
        with patch.dict(os.environ, {"HOME": str(home)}), \
                patch.object(pf, "host_is_darwin", return_value=True):
            result = geodata.prepare_for_foreground(
                {"inputs": {"server": TAILNET, "port": 1081, "proxy_name": TOKEN},
                 "profile": None, "geodata_dir": None},
                transport=_transport(_payloads()))
        directory = home / ".config" / "mihomo"
        self.assertTrue(result["ok"], result)
        self.assertEqual(Path(result["directory"]), directory)
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(TAILNET, json.dumps(result))
        account = type("Account", (), {"pw_uid": os.getuid(), "pw_dir": str(home),
                                       "pw_name": "alice"})()
        with patch.object(macos_takeover.os, "geteuid", return_value=0), \
                patch.dict(os.environ, {"SUDO_USER": "alice", "HOME": str(self.base / "var-root")}), \
                patch("pwd.getpwnam", return_value=account):
            self.assertEqual(macos_takeover.default_geodata_dir(), directory)
        with patch("pwd.getpwuid", return_value=account):
            self.assertEqual(macos_takeover.geodata_dir_for_uid(os.getuid()), directory)
        work = _private(self.base / "work")
        staged, _missing = macos_takeover.stage_geodata(work, directory)
        self.assertEqual((work / "geosite.dat").read_bytes(), SITE)
        self.assertIn("geosite.dat", staged)

    def test_placeholder_inputs_do_not_download_or_echo_the_address(self):
        calls = []
        with patch.object(pf, "host_is_darwin", return_value=True):
            result = geodata.prepare_for_foreground(
                {"inputs": {"server": PLACEHOLDER, "port": 1080, "proxy_name": TOKEN},
                 "profile": None},
                transport=_transport(_payloads(), calls))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "placeholder_inputs")
        self.assertEqual(calls, [])
        text = json.dumps(result)
        self.assertNotIn(PLACEHOLDER, text)
        self.assertNotIn(TOKEN, text)


class CommandTests(unittest.TestCase):
    def test_help_and_non_darwin_do_not_download(self):
        output = io.StringIO()
        with patch.object(geodata, "fetch_verified", side_effect=AssertionError("network")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(geodata.main(["--help"]), 0)
        self.assertIn("nmd macos geodata ensure", output.getvalue())
        with patch.object(pf, "host_is_darwin", return_value=False), \
                patch.object(geodata, "fetch_verified", side_effect=AssertionError("network")), \
                contextlib.redirect_stdout(io.StringIO()) as quiet:
            self.assertEqual(geodata.main(["ensure"]), 0)
        body = json.loads(quiet.getvalue())
        self.assertEqual(body["result"], "not_applicable")

    def test_preflight_names_the_command_and_does_not_fetch(self):
        with patch.object(geodata, "fetch_verified", side_effect=AssertionError("network")):
            report = pf.assess("takeover", {
                "platform": "macos", "tier": "takeover", "config": None,
                "document": {"status": "pass", "reason": "ok", "dns_mode": "disabled",
                             "needs_site": True, "needs_ip": True, "listen_port": 1053},
                "mihomo": {"status": "pass", "path": "/usr/local/bin/mihomo", "reason": None},
                "version": {"status": "pass", "parsed": (1, 19, 33), "reason": None},
                "tailscale_cli": {"status": "pass", "path": "/usr/bin/tailscale", "reason": None},
                "tailscale_status": {"status": "pass", "availability": "healthy", "reason": None},
                "geodata": {"status": "fail", "reason": "geodata_missing",
                            "missing": ["geosite.dat", "geoip"]},
                "state_dir": {"status": "pass", "reason": "ok"},
                "listen": {1053: "free"},
                "snapshot": {"status": "pass", "reason": None,
                             "has_198_18": False, "mihomo_running": False},
                "geodata_override": "/tmp/custom geo",
            })
        text = next(item["remediation"] for item in report["checks"] if item["id"] == "geodata")
        self.assertIn("nmd macos geodata ensure --geodata-dir '/tmp/custom geo'", text)
        self.assertIn("只读预检", text)
        self.assertFalse(report["effects"]["preflight_mutates"])

    def test_cli_ensure_uses_the_explicit_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            explicit = _private(base / "explicit")
            inputs = base / "inputs.json"
            inputs.write_text(json.dumps(
                {"server": TAILNET, "port": 1081, "proxy_name": TOKEN}), encoding="utf-8")
            os.chmod(inputs, 0o600)
            output = io.StringIO()

            def fake(name, *, transport=None):
                return {"geosite.dat": SITE, "geoip.metadb": MMDB}[name]

            with patch.object(pf, "host_is_darwin", return_value=True), \
                    patch.object(geodata, "fetch_verified", side_effect=fake), \
                    contextlib.redirect_stdout(output):
                code = geodata.main(["ensure", "--inputs", str(inputs),
                                     "--geodata-dir", str(explicit)])
            body = json.loads(output.getvalue())
            self.assertEqual(code, 0, output.getvalue())
            self.assertEqual(body["preflight_geodata"], "pass")
            self.assertEqual((explicit / "geosite.dat").read_bytes(), SITE)
            self.assertNotIn(TOKEN, output.getvalue())
            self.assertNotIn(TAILNET, output.getvalue())


class _Checkout(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.checkout = self.base / "repo"
        self.config_dir = _private(self.base / "config")
        self.state_dir = _private(self.base / "state")
        self.checkout.mkdir()
        env = patch.dict(os.environ, {
            "HOME": str(self.base / "home"),
            "XDG_CONFIG_HOME": str(self.base / "xdg-config"),
            "XDG_STATE_HOME": str(self.base / "xdg-state"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }, clear=False)
        env.start()
        self.addCleanup(env.stop)
        subprocess.run(["git", "init", "-q", str(self.checkout)], check=True, capture_output=True)
        (self.checkout / "marker").write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.checkout), "add", "marker"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(self.checkout), "-c", "user.email=t@example.com",
                        "-c", "user.name=test", "commit", "-q", "-m", "init"],
                       check=True, capture_output=True)
        manager.setting(self.checkout, "home", str(self.checkout))
        manager.setting(self.checkout, "scope", "user")
        manager.setting(self.checkout, "configDir", str(self.config_dir))
        manager.setting(self.checkout, "stateDir", str(self.state_dir))
        self.program = self.base / "mihomo"
        self.program.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.program.chmod(0o755)

    def write_config(self, *, on_boot):
        nmd_daemon.write_daemon_config(self.config_dir / "daemon.json", {
            "schema_version": 1,
            "dashboard": {"port": 8765},
            "takeover": {
                "inputs": {"proxy_name": TOKEN, "server": TAILNET, "port": 1081},
                "profile": None, "on_boot": on_boot, "check_interval_seconds": 20,
                "critical_failures": 3, "mihomo_path": str(self.program),
                "state_dir": str(self.state_dir),
            },
        })

    def context(self):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(pf, "host_is_darwin", return_value=True))
        stack.enter_context(patch.object(manager, "ROOT", self.checkout))
        stack.enter_context(patch.object(nmd_platform, "name", return_value="macos"))
        return stack


class LifecycleTests(_Checkout):
    def test_download_then_preflight_then_stop_and_failure_stops_nothing(self):
        self.write_config(on_boot=True)
        calls = []

        def fake(name, *, transport=None):
            calls.append(name)
            return {"geosite.dat": SITE, "geoip.metadb": MMDB}[name]

        def stop():
            calls.append("stop")
            return {"result": "stop"}

        def start():
            calls.append("start")
            return {"result": "start"}

        with self.context(), \
                patch.object(pf, "probe_activity",
                             return_value={"state": "inactive", "reason": None, "on_boot": True}), \
                patch.object(pf, "probe_tailscale_cli",
                             return_value={"status": "pass", "path": "/usr/bin/tailscale",
                                           "reason": None}), \
                patch.object(pf, "probe_tailscale_status",
                             return_value={"status": "pass", "availability": "healthy",
                                           "reason": None}), \
                patch.object(pf, "probe_version",
                             return_value={"status": "pass", "parsed": (1, 19, 33), "reason": None}), \
                patch.object(pf, "probe_snapshot",
                             return_value={"status": "pass", "reason": None,
                                           "has_198_18": False, "mihomo_running": False}), \
                patch.object(pf, "probe_listen", return_value="free"), \
                patch.object(geodata, "fetch_verified", side_effect=fake), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=stop), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=start), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = nmd_daemon.cli_daemon(["restart"])
        directory = Path(os.environ["HOME"]) / ".config" / "mihomo"
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["geosite.dat", "geoip.metadb", "stop", "start"])
        self.assertEqual((directory / "geosite.dat").read_bytes(), SITE)
        self.assertEqual(pf.probe_geodata(directory, True, True)["status"], "pass")

        failed = _private(self.base / "failed-home")
        self.write_config(on_boot=True)
        with patch.dict(os.environ, {"HOME": str(failed)}), self.context(), \
                patch.object(pf, "probe_activity",
                             return_value={"state": "inactive", "reason": None, "on_boot": True}), \
                patch.object(pf, "probe_tailscale_cli",
                             return_value={"status": "pass", "path": "/usr/bin/tailscale",
                                           "reason": None}), \
                patch.object(pf, "probe_tailscale_status",
                             return_value={"status": "pass", "availability": "healthy",
                                           "reason": None}), \
                patch.object(pf, "probe_version",
                             return_value={"status": "pass", "parsed": (1, 19, 33), "reason": None}), \
                patch.object(pf, "probe_snapshot",
                             return_value={"status": "pass", "reason": None,
                                           "has_198_18": False, "mihomo_running": False}), \
                patch.object(pf, "probe_listen", return_value="free"), \
                patch.object(geodata, "fetch_verified",
                             side_effect=geodata.GeodataError("timeout")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=AssertionError("stop")), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=AssertionError("start")), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                patch.object(nmd_daemon, "daemon_receipt", return_value={"version": 1}), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(manager.ManagerError, "待应用状态保留"):
                manager.apply(self.checkout)
        self.assertEqual(manager.setting(self.checkout, "pendingApply"), "true")
        self.assertEqual(manager.setting(self.checkout, "appliedRevision"), "")
        self.assertFalse((failed / ".config" / "mihomo" / "geosite.dat").exists())

    def test_inactive_restart_does_not_download(self):
        self.write_config(on_boot=False)
        calls = []

        def stop():
            calls.append("stop")
            return {"result": "stop"}

        def start():
            calls.append("start")
            return {"result": "start"}

        with self.context(), \
                patch.object(pf, "probe_activity",
                             return_value={"state": "inactive", "reason": None, "on_boot": False}), \
                patch.object(pf, "probe_tailscale_cli",
                             return_value={"status": "pass", "path": "/usr/bin/tailscale",
                                           "reason": None}), \
                patch.object(geodata, "fetch_verified", side_effect=AssertionError("network")), \
                patch.object(pf, "probe_geodata", side_effect=AssertionError("geodata")), \
                patch.object(nmd_daemon, "_daemon_stop", side_effect=stop), \
                patch.object(nmd_daemon, "_daemon_start", side_effect=start), \
                patch.object(nmd_daemon, "_run_helper", side_effect=AssertionError("sudo")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = nmd_daemon.cli_daemon(["restart"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["stop", "start"])

    def test_dispatch_help_does_not_download(self):
        output = io.StringIO()
        with self.context(), \
                patch.object(geodata, "fetch_verified", side_effect=AssertionError("network")), \
                contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as caught:
                manager.main(["macos", "geodata", "--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("nmd macos geodata ensure", output.getvalue())


if __name__ == "__main__":
    unittest.main()
