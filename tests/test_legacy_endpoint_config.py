"""Synthetic legacy endpoint configuration; no DNS, services or real host files."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LegacyEndpointConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = dict(os.environ, NMD_LOCAL_ENV=str(self.base / "missing.env"),
                        NMD_SOURCES_DIR=str(self.base / "sources"))
        self.env.pop("NMD_VPS_TS_IP", None)
        self.env.pop("NMD_VPS_PUB", None)

    def shell(self, body, **overrides):
        prelude = "\n".join(
            f"{name}() {{ echo UNEXPECTED_SIDE_EFFECT >&2; return 99; }}"
            for name in ("sudo", "systemctl", "tailscale", "curl", "ping", "ip", "resolvectl"))
        return subprocess.run(["bash", "-c", prelude + "\nsource " +
                               shlex.quote(str(ROOT / "local-setup.sh")) + "\n" + body],
                              env=dict(self.env, **overrides), capture_output=True, text=True,
                              timeout=5)

    def test_unconfigured_commands_stop_before_privilege_probe_or_write(self):
        for command in ("verify", "setup", "apply", "deploy", "cutover", "rollback", "test-stop"):
            with self.subTest(command=command):
                result = self.shell("main " + command)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("NMD_VPS_TS_IP", result.stderr)
                self.assertNotIn("UNEXPECTED_SIDE_EFFECT", result.stderr)

    def test_help_and_source_mode_do_not_require_a_legacy_endpoint(self):
        self.assertEqual(self.shell("main help").returncode, 0)
        directory = self.base / "sources"
        directory.mkdir()
        (directory / "sources.json").write_text("{}")
        self.assertEqual(self.shell("require_legacy_endpoint").returncode, 0)

    def test_private_data_file_injects_both_synthetic_endpoints(self):
        local = self.base / "local.env"
        local.write_text("NMD_VPS_TS_IP=100.64.0.2\nNMD_VPS_PUB=198.18.0.2\n")
        output = self.base / "rendered.yaml"
        result = self.shell("render_config " + shlex.quote(str(output)), NMD_LOCAL_ENV=str(local))
        self.assertEqual(result.returncode, 0, result.stderr)
        text = output.read_text()
        self.assertIn("server: 100.64.0.2", text)
        self.assertIn("198.18.0.2/32", text)
        self.assertNotIn("203.0.113.20", text)
        self.assertNotIn("203.0.113.10", text)

    def test_missing_server_placeholder_cannot_publish_partial_render(self):
        template = self.base / "template"
        template.mkdir()
        (template / "config.yaml").write_text("# 203.0.113.20\nrules:\n  - IP-CIDR,203.0.113.10/32,DIRECT\n")
        output = self.base / "invalid.yaml"
        result = self.shell("SETUP_DIR=" + shlex.quote(str(template)) + "\nrender_config " +
                            shlex.quote(str(output)), NMD_VPS_TS_IP="100.64.0.2")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), "")


if __name__ == "__main__":
    unittest.main()
