"""The privileged helper treats local overrides as data, never shell code."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class LocalEnvDataTests(unittest.TestCase):
    def test_shell_payload_is_never_executed_even_for_help(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for payload in ('touch "{marker}"', 'NMD_VPS_PUB=$(touch "{marker}")',
                            'NMD_VPS_TS_IP=$(touch "{marker}")',
                            'NMD_VPS_PUB=1.2.3.4; touch "{marker}"'):
                marker, env = base / "executed", base / "local.env"
                env.write_text(payload.format(marker=marker) + "\n")
                result = subprocess.run(["bash", str(ROOT / "local-setup.sh"), "help"],
                                        env=dict(os.environ, NMD_LOCAL_ENV=str(env)),
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(marker.exists())

    def test_literal_quoted_ipv4_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / "local.env"
            for value in ('1.2.3.4', "'1.2.3.4'", '"1.2.3.4"'):
                env.write_text("# only data\nNMD_VPS_PUB=" + value + "\n")
                result = subprocess.run(["bash", str(ROOT / "local-setup.sh"), "help"],
                                        env=dict(os.environ, NMD_LOCAL_ENV=str(env)),
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
