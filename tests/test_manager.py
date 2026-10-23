"""Behavioral guardrails; all system changes are replaced by recorded commands."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ManagerTests(unittest.TestCase):
    def run_manager(self, command, overrides="", active=True):
        with tempfile.TemporaryDirectory() as tmp:
            events = Path(tmp) / "events"
            script = f"""
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
VPS_TS_IP=100.64.0.2 # TEST_ONLY; service and network commands are recorded below.
events={shlex.quote(str(events))}
record() {{ echo "$*" >> "$events"; }}
require_root() {{ :; }}
check_source() {{ record validate-source; }}
check_installed() {{ record validate-installed; }}
deploy_files() {{ record deploy; }}
wait_running() {{ record ready; }}
tailscale() {{
  record "tailscale $*"
  if [[ $1 == debug ]]; then echo '{{"ExitNodeID":"","ExitNodeIP":""}}'; fi
}}
systemctl() {{
  record "systemctl $*"
  if [[ $1 == is-active ]]; then return {0 if active else 3}; fi
}}
resolvectl() {{ record "resolvectl $*"; }}
ip() {{ record "ip $*"; return 1; }}
tailscale_checks() {{ record probes; }}
{overrides}
main {shlex.quote(command)}
"""
            result = subprocess.run(["bash", "-c", script], text=True,
                                    capture_output=True, timeout=10)
            return result, events.read_text().splitlines() if events.exists() else []

    def test_start_and_stop_preserve_tailscale_and_autostart(self):
        for cmd in ("start", "stop", "restart"):
            with self.subTest(cmd=cmd):
                result, events = self.run_manager(cmd, active=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"systemctl {cmd} mihomo", events)
                self.assertFalse(any("tailscale set" in e or "tailscaled" in e
                                     or "systemctl enable" in e or "systemctl disable" in e
                                     for e in events))
                if cmd == "stop":
                    self.assertIn("resolvectl flush-caches", events)

    def test_failed_validation_prevents_deploy_restart_and_dns_changes(self):
        result, events = self.run_manager(
            "apply", "check_source() { record invalid; return 42; }")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(events, ["invalid"])

    def test_apply_preserves_stopped_state_and_checks_before_writes(self):
        for active in (False, True):
            result, events = self.run_manager("apply", active=active)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(events[0], "validate-source")
            self.assertIn("deploy", events)
            self.assertIn("tailscale set --accept-dns=true", events)
            self.assertEqual("systemctl restart mihomo" in events, active)
            self.assertNotIn("systemctl start mihomo", events)

    def test_exit_node_blocks_start_and_apply_before_writes(self):
        for command in ("start", "apply"):
            result, events = self.run_manager(command, '''
tailscale() { record "tailscale $*"; echo '{"ExitNodeID":"selected"}'; }
''')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("deploy", events)
            self.assertFalse(any(e.startswith("systemctl start") for e in events))

    def test_failed_stop_does_not_flush_dns_or_change_tailscale(self):
        result, events = self.run_manager("stop", '''
systemctl() { record "systemctl $*"; return 42; }
''')
        self.assertEqual(result.returncode, 42)
        self.assertEqual(events, ["systemctl stop mihomo"])

    def test_dns_activation_failure_stops_apply_before_restart(self):
        result, events = self.run_manager("apply", '''
resolvectl() { record failed-dns; return 42; }
''')
        self.assertEqual(result.returncode, 42)
        self.assertNotIn("systemctl restart mihomo", events)

    def test_stop_test_restores_service_after_probe_failure(self):
        for active in (True, False):
            result, events = self.run_manager("test-stop", f'''
count=0
systemctl() {{
  record "systemctl $*"
  if [[ $1 == is-active ]]; then
    count=$((count + 1))
    if (( count == 1 )); then return {0 if active else 3}; fi
    return 3
  fi
}}
tailscale_checks() {{ record probes-failed; return 42; }}
''', active=active)
            self.assertEqual(result.returncode, 42, result.stderr)
            self.assertEqual("systemctl start mihomo" in events, active)

    def test_unknown_command_and_sudo_failure_propagate(self):
        result = subprocess.run([str(ROOT / "nmd"), "typo"], capture_output=True)
        self.assertEqual(result.returncode, 2)
        if os.geteuid() != 0:
            with tempfile.TemporaryDirectory() as tmp:
                # Never invoke real sudo/service mutations from the test suite.
                sudo = Path(tmp) / "sudo"
                sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >&2\nexit 42\n')
                sudo.chmod(0o755)
                env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"])
                result = subprocess.run(["bash", str(ROOT / "local-setup.sh"), "stop"], capture_output=True,
                                        text=True, env=env)
                self.assertEqual(result.returncode, 42)
                self.assertEqual(result.stderr.splitlines(),
                                 ["--", "bash", str(ROOT / "local-setup.sh"), "stop"])



if __name__ == "__main__":
    unittest.main()
