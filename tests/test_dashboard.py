"""Dependency-free UI guardrails, plus optional actual Chromium fixture tests.

Browser CI: npm install --no-save --prefix web playwright@1.57.0
           web/node_modules/.bin/playwright install --with-deps chromium
           node web/tests/dashboard.spec.cjs
Local overrides: PLAYWRIGHT_MODULE and CHROMIUM_PATH.
No real network probes or changes: the fixture server binds loopback only.
"""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DashboardTests(unittest.TestCase):
    def test_static_safety(self):
        js = (ROOT / 'web/app.js').read_text()
        html = (ROOT / 'web/index.html').read_text()
        self.assertNotIn('innerHTML', js)
        self.assertNotIn('eval(', js)
        self.assertNotIn('https://', html)
        self.assertNotIn('onclick=', html)
        self.assertIn("fetch('/api/snapshot'", js)
        self.assertIn("postJSON('/api/egress/select'", js)
        self.assertIn("postJSON('/api/egress/delay'", js)
        self.assertIn("postJSON('/api/auto'", js)
        self.assertIn('AbortController', js)
        self.assertIn('document.hidden', js)
        self.assertIn('if (busy) return', js)
        self.assertIn('5000', js)
        self.assertIn('aria-label=', html)
        self.assertIn('data-page="egress"', html)

    def test_platform_and_synthetic_data_are_visible(self):
        html = (ROOT / 'web/index.html').read_text()
        js = (ROOT / 'web/app.js').read_text()
        self.assertIn('id="demo-notice"', html)
        self.assertIn('id="platform-capabilities"', html)
        self.assertIn('data_origin', js)
        self.assertIn('模拟演示', html)
        self.assertIn("fetch('/api/capabilities'", js)

    def test_product_identity(self):
        html = (ROOT / 'web/index.html').read_text()
        js = (ROOT / 'web/app.js').read_text()
        self.assertIn('<title>NMD · Network Monitor &amp; Diagnostics · 网络观察台</title>', html)
        self.assertIn('<strong>NMD</strong>', html)
        self.assertIn('<small>网络观察台</small>', html)
        self.assertIn('>Network Monitor &amp; Diagnostics</p>', html)
        self.assertIn('NMD / 本地面板', html)
        self.assertIn('nmd CLI', html)
        self.assertIn('nmd CLI', js)
        self.assertNotIn('<strong>mh</strong>', html)

    @unittest.skipUnless(shutil.which('node'), 'Node needed for JS syntax check')
    def test_javascript_syntax(self):
        subprocess.run(['node', '--check', str(ROOT / 'web/app.js')], check=True, capture_output=True)

    @unittest.skipUnless(os.environ.get('RUN_BROWSER_TESTS') == '1', 'Set RUN_BROWSER_TESTS=1 for Chromium fixtures')
    @unittest.skipUnless(shutil.which('node'), 'Node needed for browser test')
    def test_browser_fixtures(self):
        env = dict(os.environ)
        local = ROOT / 'web/node_modules/playwright'
        preinstalled = Path('/opt/codex/cua_node/lib/node_modules/playwright')
        if not env.get('PLAYWRIGHT_MODULE'):
            if local.is_dir():
                env['PLAYWRIGHT_MODULE'] = str(local)
            elif preinstalled.is_dir():
                env['PLAYWRIGHT_MODULE'] = str(preinstalled)
                if shutil.which('chromium'):
                    env.setdefault('CHROMIUM_PATH', shutil.which('chromium'))
            else:
                self.skipTest('Install pinned Playwright 1.57.0 and Chromium for browser fixtures')
        proc = subprocess.run(['node', str(ROOT / 'web/tests/dashboard.spec.cjs')], env=env,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == '__main__':
    unittest.main()
