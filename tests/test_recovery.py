"""Isolated shell fault injection: temporary paths, mocked system/network tools only."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.events = self.base / 'events'

    def shell(self, text):
        return subprocess.run(['bash', '-c', text], capture_output=True, text=True, timeout=15)

    def local(self, command='deploy', failure='', active=False, package_failure=False):
        return self.shell(f'''
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
VPS_TS_IP=100.64.0.2 # TEST_ONLY; all network/service operations below are mocked.
CONFIG_DIR={shlex.quote(str(self.base / 'config'))}
MIHOMO={shlex.quote(str(self.base / 'missing-mihomo')) if package_failure else '/bin/true'}
dpkg() {{
 mkdir -p "$CONFIG_DIR"
 echo package-config > "$CONFIG_DIR/config.yaml"
 return 48
}}
record() {{ echo "$*" >> {shlex.quote(str(self.events))}; }}
require_root() {{ :; }}
ensure_no_exit_node() {{ :; }}
check_source() {{ record validate; }}
check_installed() {{ :; }}
deploy_files() {{ record deploy; echo config > "$CONFIG_DIR/config.yaml"; }}
activate_dns() {{ record dns; {'return 42' if failure == 'dns' else ':'}; }}
wait_running() {{ record ready; {'return 43' if failure == 'ready' else ':'}; }}
verify() {{ record "verify $*"; {'return 45' if failure == 'verify' else ':'}; }}
systemctl() {{
 record "systemctl $*"
 if [[ $1 == is-active ]]; then return {0 if active else 3}; fi
 if [[ $1 == enable && {shlex.quote(failure or 'none')} == enable ]]; then return 44; fi
}}
main {command}
''')

    def test_initial_failure_retries_start_enable_and_full_verify(self):
        for point in ('dns', 'ready', 'enable', 'verify'):
            with self.subTest(point=point):
                result = self.local(failure=point)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue((self.base / 'config/.initial-deploy-pending').exists())
                self.events.write_text('')
                result = self.local('apply')
                self.assertEqual(result.returncode, 0, result.stderr)
                events = self.events.read_text()
                self.assertIn('systemctl start mihomo', events)
                self.assertIn('systemctl enable mihomo', events)
                self.assertIn('verify running', events)
                self.assertFalse((self.base / 'config/.initial-deploy-pending').exists())
                (self.base / 'config/config.yaml').unlink()

    def test_package_failure_before_validation_keeps_initial_intent(self):
        result = self.local(package_failure=True)
        self.assertEqual(result.returncode, 48)
        self.assertTrue((self.base / 'config/config.yaml').exists())
        self.assertTrue((self.base / 'config/.initial-deploy-pending').exists())
        result = self.local('deploy')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('systemctl start mihomo', self.events.read_text())
        self.assertIn('systemctl enable mihomo', self.events.read_text())
        self.assertIn('verify running', self.events.read_text())

    def test_existing_stopped_deploy_stays_stopped(self):
        (self.base / 'config').mkdir()
        (self.base / 'config/config.yaml').write_text('previous')
        result = self.local()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('systemctl start', self.events.read_text())
        self.assertNotIn('systemctl enable', self.events.read_text())

    def test_verify_running_cannot_skip_inactive_service(self):
        result = self.shell(f'''source {ROOT / 'local-setup.sh'}
systemctl() {{ return 3; }}
tailscale_checks() {{ echo SHOULD-NOT-PROBE; }}
verify running''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('SHOULD-NOT-PROBE', result.stdout)

    def test_service_stopping_during_verify_fails(self):
        result = self.shell(f'''source {ROOT / 'local-setup.sh'}
count=0
systemctl() {{ count=$((count + 1)); (( count == 1 )); }}
tailscale_checks() {{ :; }}
curl() {{ echo 200; }}
verify running''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('SKIP', result.stdout)

    def test_optional_diagnostics_are_explicit(self):
        result = self.shell(f'''source {ROOT / 'local-setup.sh'}
ping() {{ echo mocked-ping; return 1; }}
timeout() {{ echo mocked-dns; return 1; }}
diagnostics''')
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('mocked-', result.stdout)
        result = self.shell(f'''source {ROOT / 'local-setup.sh'}
ping() {{ echo mocked-ping; return 1; }}
timeout() {{ echo mocked-dns; return 1; }}
NMD_LAN_HOST=192.0.2.1 diagnostics''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('mocked-ping', result.stdout)

    def vps(self, failure='', existing=False, active=True, enabled=None, restore_failure=False):
        binary = self.base / 'bin/mihomo'
        config = self.base / 'config/config.yaml'
        unit = self.base / 'systemd/mihomo.service'
        if existing:
            for path in (binary, config, unit):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('old-' + path.name)
        if enabled is None:
            enabled = existing and active
        script = f'''
source {ROOT / 'vps-setup.sh'}
BINARY={binary}
CONFIG_DIR={config.parent}
UNIT={unit}
record() {{ echo "$*" >> {self.events}; }}
mktemp() {{ command mktemp -d {self.base}/stage.XXXXXX; }}
cp() {{
 if [[ {int(restore_failure)} == 1 && $* == *old-binary* && $* == *.restore* ]]; then return 49; fi
 command cp "$@"
}}
curl() {{
 record "curl $*"
 if [[ $* == *mihomo.gz* ]]; then
   while (( $# )); do
     if [[ $1 == -o ]]; then
       printf '#!/bin/sh\\nexit {46 if failure == 'validate' else 0}\\n' | gzip > "$2"
       return
     fi
     shift
   done
 fi
 {'return 47' if failure == 'probe' else "echo ip=203.0.113.1"}
}}
tailscale() {{ echo 100.100.1.2; }}
sleep() {{ :; }}
service_active={1 if existing and active else 0}
service_enabled={int(enabled)}
systemctl() {{
 record "systemctl $*"
 case $1 in
   is-active) (( service_active )); return $?;;
   is-enabled) (( service_enabled )); return $?;;
   restart|start) service_active=1;;
   stop) service_active=0;;
   enable) service_enabled=1;;
   disable) service_enabled=0;;
 esac
 return 0
}}
main
'''
        return self.shell(script), (binary, config, unit)

    def test_vps_rejects_symlink_artifacts_before_activation(self):
        target = self.base / 'operator-owned'
        target.write_text('keep operator configuration')
        unit = self.base / 'systemd/mihomo.service'
        unit.parent.mkdir()
        unit.symlink_to(target)
        result, _ = self.vps()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(unit.is_symlink())
        self.assertEqual(target.read_text(), 'keep operator configuration')
        self.assertFalse(self.events.exists())

    def test_vps_validation_failure_does_not_activate(self):
        result, paths = self.vps('validate', existing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('systemctl', self.events.read_text())
        self.assertTrue(all(p.read_text().startswith('old-') for p in paths))

    def test_vps_probe_failure_rolls_back_and_fails(self):
        result, paths = self.vps('probe', existing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('完成 ✓', result.stdout)
        self.assertTrue(all(p.read_text().startswith('old-') for p in paths))
        events = self.events.read_text()
        self.assertEqual(events.count('systemctl restart mihomo'), 2)
        self.assertEqual(events.count('--max-time 5'), 10)

    def test_vps_failure_restores_fresh_and_stopped_states(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                self.events.write_text('')
                result, paths = self.vps('probe', existing=existing, active=False)
                self.assertNotEqual(result.returncode, 0)
                events = self.events.read_text()
                self.assertIn('systemctl stop mihomo', events)
                self.assertIn('systemctl disable mihomo', events)
                if existing:
                    self.assertTrue(all(p.read_text().startswith('old-') for p in paths))
                else:
                    self.assertTrue(all(not p.exists() for p in paths))

    def test_vps_rollback_failure_preserves_private_backups(self):
        result, paths = self.vps('probe', existing=True, restore_failure=True)
        self.assertNotEqual(result.returncode, 0)
        stages = list(self.base.glob('stage.*'))
        self.assertEqual(len(stages), 1)
        self.assertEqual((stages[0] / 'old-binary').read_text(), 'old-mihomo')
        self.assertEqual(stages[0].stat().st_mode & 0o777, 0o700)
        self.assertIn(str(stages[0]), result.stderr)
        self.assertIn('systemctl restart mihomo', self.events.read_text())

    def test_vps_failure_restores_independent_enabled_state(self):
        for active, enabled in ((True, False), (False, True)):
            with self.subTest(active=active, enabled=enabled):
                self.events.write_text('')
                result, paths = self.vps('probe', existing=True, active=active, enabled=enabled)
                self.assertNotEqual(result.returncode, 0)
                events = self.events.read_text().splitlines()
                self.assertEqual(events[-2:], [
                    'systemctl ' + ('enable' if enabled else 'disable') + ' mihomo',
                    'systemctl ' + ('restart' if active else 'stop') + ' mihomo'])
                self.assertFalse(list(self.base.glob('stage.*')))

    def test_vps_repeat_deploy_restarts_running_service(self):
        result, paths = self.vps(existing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text()
        self.assertIn('systemctl restart mihomo', events)
        self.assertNotIn('enable --now', events)
        self.assertIn('--max-time 120', events)
        self.assertIn('--max-time 5', events)
        self.assertIn('完成 ✓', result.stdout)


class LocalOverrideTests(unittest.TestCase):
    """NMD_VPS_PUB 本地覆盖：占位端点注入与 verify 期望值来源。"""

    PLACEHOLDER = '203.0.113.10'
    FAKE_PUB = '198.51.100.77'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def shell(self, text):
        return subprocess.run(['bash', '-c', text], capture_output=True, text=True, timeout=15)

    def env_file(self, body=None):
        path = self.base / 'nmd-local.env'
        path.write_text(body if body is not None
                        else f'NMD_VPS_PUB={self.FAKE_PUB}\n')
        return path

    def render_with(self, env_path, dest, setup_dir=None):
        setup = f'SETUP_DIR={shlex.quote(str(setup_dir))}\n' if setup_dir else ''
        return self.shell(f'''
NMD_LOCAL_ENV={shlex.quote(str(env_path))}
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
{setup}render_config {shlex.quote(str(dest))}
printf 'VPS_PUB=%s\\n' "$VPS_PUB"''')

    def test_override_replaces_placeholder_and_sets_expectation(self):
        dest = self.base / 'rendered.yaml'
        result = self.render_with(self.env_file(), dest)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (ROOT / 'config.yaml').read_text().replace(
            self.PLACEHOLDER, self.FAKE_PUB)
        self.assertEqual(dest.read_text(), expected)
        self.assertNotIn(self.PLACEHOLDER, dest.read_text())
        self.assertIn(f'VPS_PUB={self.FAKE_PUB}', result.stdout)

    def test_default_without_override_keeps_placeholder(self):
        dest = self.base / 'rendered.yaml'
        result = self.render_with(self.base / 'absent.env', dest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(dest.read_text(), (ROOT / 'config.yaml').read_text())
        self.assertIn(f'VPS_PUB={self.PLACEHOLDER}', result.stdout)

    def test_invalid_override_refuses_to_load(self):
        result = self.render_with(self.env_file('NMD_VPS_PUB=not-an-ip\n'),
                                  self.base / 'unused.yaml')
        self.assertEqual(result.returncode, 2)
        self.assertIn('字面赋值', result.stderr)

    def test_missing_placeholder_token_blocks_render(self):
        stage = self.base / 'stage'
        stage.mkdir()
        (stage / 'config.yaml').write_text('rules:\n  - MATCH,DIRECT\n')
        result = self.render_with(self.env_file(), self.base / 'rendered.yaml',
                                  setup_dir=stage)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('缺少公网出口占位字段', result.stderr)

    def verify_with(self, env_path, egress):
        return self.shell(f'''
NMD_LOCAL_ENV={shlex.quote(str(env_path))}
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
VPS_TS_IP=100.64.0.2 # TEST_ONLY; all probes below are shell functions.
systemctl() {{ if [[ $1 == is-active ]]; then return 0; fi; return 3; }}
tailscale_checks() {{ :; }}
curl() {{
  case "$*" in
    *baidu*) echo 200;;
    *cloudflare*) printf 'ip=%s\\n' {shlex.quote(egress)};;
  esac
}}
timeout() {{ shift; "$@"; }}
getent() {{ echo '198.18.0.5'; }}
verify''')

    def test_verify_passes_with_matching_override(self):
        result = self.verify_with(self.env_file(), self.FAKE_PUB)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'PASS VPS 出口 {self.FAKE_PUB}', result.stdout)
        self.assertNotIn('提示', result.stderr)

    def test_verify_failure_hints_when_expectation_is_placeholder(self):
        result = self.verify_with(self.base / 'absent.env', self.FAKE_PUB)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'FAIL VPS 出口: {self.FAKE_PUB}，期望 {self.PLACEHOLDER}',
                      result.stderr)
        self.assertIn('NMD_VPS_PUB', result.stderr)


class VerifyRetryTests(unittest.TestCase):
    """verify 的 VPS 出口探测容忍重启预热瞬态：有界重试，不改接受标准。"""

    FAKE_PUB = '198.51.100.77'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = self.base / 'nmd-local.env'
        self.env.write_text(f'NMD_VPS_PUB={self.FAKE_PUB}\n')

    def shell(self, text):
        return subprocess.run(['bash', '-c', text], capture_output=True, text=True, timeout=15)

    def verify(self, cloudflare_body):
        calls = self.base / 'calls'
        return self.shell(f'''
NMD_LOCAL_ENV={shlex.quote(str(self.env))}
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
VPS_TS_IP=100.64.0.2 # TEST_ONLY; all probes below are shell functions.
systemctl() {{ if [[ $1 == is-active ]]; then return 0; fi; return 3; }}
tailscale_checks() {{ :; }}
sleep() {{ echo sleep >> {shlex.quote(str(calls))}; }}
timeout() {{ shift; "$@"; }}
getent() {{ echo '198.18.0.5'; }}
# curl 在命令替换的子 shell 中执行：跨调用状态必须走文件，不能用 shell 变量。
count_cloudflare() {{ grep -c cloudflare {shlex.quote(str(calls))} || true; }}
curl() {{
  case "$*" in
    *baidu*) echo 200;;
    *cloudflare*)
      echo cloudflare >> {shlex.quote(str(calls))}
      {cloudflare_body}
      ;;
  esac
}}
verify'''), calls

    def test_transient_egress_failure_passes_after_retry(self):
        result, calls = self.verify(
            f"if (( $(count_cloudflare) < 3 )); then return 28; fi\n"
            f"      printf 'ip=%s\\n' {self.FAKE_PUB}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'PASS VPS 出口 {self.FAKE_PUB}', result.stdout)
        self.assertEqual(calls.read_text().splitlines().count('cloudflare'), 3)
        self.assertEqual(calls.read_text().splitlines().count('sleep'), 2)

    def test_wrong_exit_ip_fails_without_retry(self):
        result, calls = self.verify("printf 'ip=%s\\n' 203.0.113.99")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'FAIL VPS 出口: 203.0.113.99，期望 {self.FAKE_PUB}', result.stderr)
        self.assertEqual(calls.read_text().splitlines().count('cloudflare'), 1)
        self.assertNotIn('sleep', calls.read_text())

    def test_persistent_unreachable_fails_after_bounded_retries(self):
        result, calls = self.verify('return 28')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f'FAIL VPS 出口: 不可达，期望 {self.FAKE_PUB}', result.stderr)
        self.assertEqual(calls.read_text().splitlines().count('cloudflare'), 3)
        self.assertEqual(calls.read_text().splitlines().count('sleep'), 2)


class PeerProbeTests(unittest.TestCase):
    """尾网对端以 pong 可达为验收；DERP 为显式降级通过（按实际路径报告）。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = self.base / 'nmd-local.env'
        self.env.write_text('NMD_VPS_PUB=198.51.100.77\n')

    def shell(self, text):
        return subprocess.run(['bash', '-c', text], capture_output=True, text=True, timeout=15)

    def probe(self, ping_output, ping_status):
        out = self.base / 'ping.out'
        out.write_text(ping_output)
        return self.shell(f'''
NMD_LOCAL_ENV={shlex.quote(str(self.env))}
source {shlex.quote(str(ROOT / 'local-setup.sh'))}
timeout() {{ shift; "$@"; }}
tailscale() {{ cat {shlex.quote(str(out))}; return {ping_status}; }}
peer_probe 100.64.0.2''')

    def test_derp_pong_passes_as_degraded(self):
        result = self.probe(
            'pong from vm (100.64.0.2) via DERP(tok) in 286ms\n'
            'direct connection not established\n', 1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS 尾网对端（经 DERP 中继，无直连——已知降级）', result.stdout)

    def test_direct_pong_passes_without_degraded_marker(self):
        result = self.probe(
            'pong from vm (100.64.0.2) via 154.36.156.59:41641 in 32ms\n', 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS 尾网对端（直连）', result.stdout)
        self.assertNotIn('DERP', result.stdout)

    def test_missing_pong_fails(self):
        result = self.probe('no route to host\n', 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAIL 尾网对端', result.stderr)


if __name__ == '__main__':
    unittest.main()
