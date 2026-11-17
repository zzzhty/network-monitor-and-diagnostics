"""Behavioral guardrails; all system changes are replaced by recorded commands."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ManagerTests(unittest.TestCase):
    def run_manager(self, command, overrides="", active=True):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            events = root / "events"
            # Own executable and config dir: do not use /bin/true or /etc/mihomo.
            # Darwin has failed `[[ -x /bin/true ]]`, and a host pending file would
            # fall into the real dpkg/install path.
            mihomo = root / "mihomo"
            mihomo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            mihomo.chmod(0o755)
            script = f"""
unset MIHOMO || true
NMD_LOCAL_ENV={shlex.quote(str(root / 'absent.env'))}
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
VPS_TS_IP=100.64.0.2 # TEST_ONLY; service and network commands are recorded below.
CONFIG_DIR={shlex.quote(str(root / 'config'))}
MIHOMO={shlex.quote(str(mihomo))}
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
            result = _bash(script)
            text = events.read_bytes().decode("utf-8", errors="backslashreplace") if events.exists() else ""
            return result, text.splitlines()

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
        stderr = result.stderr.decode("utf-8", errors="backslashreplace")
        if sys.platform == "linux":
            self.assertEqual(result.returncode, 2, stderr)
            self.assertIn("未知命令", stderr)
        else:
            # The manager rejects this before local-setup.sh. Exit 1 is the
            # platform error, not the Linux "unknown command" exit 2.
            self.assertEqual(result.returncode, 1, stderr)
            self.assertIn("仅支持 Linux", stderr)
            self.assertNotIn("未知命令", stderr)
        if os.name == "nt" or os.geteuid() == 0:
            return
        with tempfile.TemporaryDirectory() as tmp:
            # Never invoke real sudo/service mutations from the test suite.
            sudo = Path(tmp) / "sudo"
            sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >&2\nexit 42\n', encoding="utf-8")
            sudo.chmod(0o755)
            env = _bash_env()
            env["PATH"] = tmp + os.pathsep + env.get("PATH", "")
            env["NMD_LOCAL_ENV"] = str(Path(tmp) / "absent.env")
            result = subprocess.run(["bash", str(ROOT / "local-setup.sh"), "stop"],
                                    capture_output=True, env=env)
            err = result.stderr.decode("utf-8", errors="backslashreplace")
            self.assertEqual(result.returncode, 42, err)
            self.assertEqual(err.splitlines(),
                             ["--", "bash", str(ROOT / "local-setup.sh"), "stop"])



def _bash_env():
    """Drop host shell startup files so bash -c sees only the test script."""
    env = os.environ.copy()
    for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "POSIXLY_CORRECT", "MIHOMO"):
        env.pop(key, None)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def _bash(text, env=None):
    completed = subprocess.run(["bash", "-c", text], capture_output=True, timeout=10,
                               env=env or _bash_env())
    return subprocess.CompletedProcess(
        completed.args, completed.returncode,
        completed.stdout.decode("utf-8", errors="backslashreplace"),
        completed.stderr.decode("utf-8", errors="backslashreplace"))


if __name__ == "__main__":
    unittest.main()
