'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '..');
// WCAG contrast ratios of de-emphasized text pairs, computed from live
// computed styles so the accessibility contract is checked per scheme.
const textContrasts = (page) => page.evaluate(() => {
  const channel = (value) => {
    const part = Number(value) / 255;
    return part <= 0.04045 ? part / 12.92 : Math.pow((part + 0.055) / 1.055, 2.4);
  };
  const luminance = (color) => {
    const [r, g, b] = color.match(/\d+(\.\d+)?/g).slice(0, 3).map(channel);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const pair = (element, background) => {
    const fg = luminance(getComputedStyle(element).color);
    const bg = luminance(getComputedStyle(background).backgroundColor);
    return (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05);
  };
  return {
    footer: pair(document.querySelector('footer'), document.documentElement),
    // main paints no background of its own: de-emphasized text sits on the
    // page background (cards are always at least as strict in light mode).
    muted: pair(document.querySelector('.muted'), document.documentElement),
    navIdle: pair(document.querySelector('.nav:not(.active)'), document.querySelector('.sidebar'))
  };
});
const assertTextContrast = async (page) => {
  const ratios = await textContrasts(page);
  for (const [name, value] of Object.entries(ratios)) assert.ok(value >= 4.5, `${name} contrast ${value} < 4.5`);
};
const assertChannelFields = async (page, kind) => {
  assert.equal(await page.locator('#channel-kind').inputValue(), kind);
  const subscription = kind === 'subscription';
  assert.equal(await page.locator('#channel-subscription-fields').isVisible(), subscription);
  assert.equal(await page.locator('#channel-proxy-fields').isVisible(), !subscription);
  assert.equal(await page.locator('#channel-url').isEnabled(), subscription);
  for (const field of ['server', 'port', 'username', 'password']) {
    assert.equal(await page.locator(`#channel-${field}`).isEnabled(), !subscription);
  }
};
let mode = 'empty', requests = [], posts = [], snapshot, refreshHold = 0;
let diagnoseView = null;
let capabilityView = { schema_version: 1, platform: 'linux', network_mutations: false, native_desktop: false, local_egress_control: true, channel_management: true, config_management: false, read_only_gui: false };
let sourceView = { schema_version: 1, sources: [], nodes: [], active: null, controller: 'not_queried', selection_mode: 'manual' };
let configView = { schema_version: 1, config_path: '/tmp/nmd-fixture/monitor.json', exists: false,
  config: { schema_version: 1, interval_seconds: 30, timeout_seconds: 5, retention_hours: 168, max_samples: 100000, probes: [] } };
const failingNodes = [];
const autoConfig = { version: 3, enabled: true, paused: false,
  fail_after: 3, recover_after: 2, cooldown: 2 };
const server = http.createServer((req, res) => {
  requests.push([req.method, req.url]);
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'");
  if (req.method === 'POST') {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', async () => {
      posts.push([req.url, raw]);
      let body = null; try { body = JSON.parse(raw || '{}'); } catch { body = null; }
      if (req.url === '/api/channels' && body?.id && body?.definition) {
        if (sourceView.sources.some(channel => channel.id === body.id)) {
          res.writeHead(409); return res.end('{"error":"source_already_exists"}');
        }
        const { kind, display_name } = body.definition;
        sourceView.sources.push({ id: body.id, kind, display_name, node_count: kind === 'subscription' ? 0 : 1,
          url: kind === 'subscription' ? '[redacted]' : null });
        if (kind !== 'subscription') sourceView.nodes.push({ id: `nmd-${body.id}-${'b'.repeat(20)}`, source: body.id, display: body.id, protocol: 'socks5' });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{"result":"saved_pending_apply"}');
      }
      if (req.url === '/api/channels/rename' && body?.id && typeof body.display_name === 'string') {
        sourceView.sources.find(channel => channel.id === body.id).display_name = body.display_name;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{"result":"channel_renamed"}');
      }
      if (req.url === '/api/channels/refresh' && body && typeof body.id === 'string') {
        const channel = sourceView.sources.find(row => row.id === body.id);
        if (!channel || channel.kind !== 'subscription') {
          res.writeHead(409); return res.end('{"schema_version":1,"error":"subscription_source_not_found"}');
        }
        if (refreshHold) await new Promise(resolve => setTimeout(resolve, refreshHold));
        channel.node_count = 3;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{"result":"refreshed_pending_apply"}');
      }
      if (req.url === '/api/egress/select' && body && typeof body.node === 'string') {
        sourceView.active = body.node; if (sourceView.auto?.enabled) { sourceView.auto.paused = true; sourceView.selection_mode = 'manual'; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ result: 'selected_and_observed', active: body.node }));
      }
      if (req.url === '/api/egress/delay' && body && typeof body.node === 'string') {
        if (failingNodes.includes(body.node)) { res.writeHead(409); return res.end('{"error":"delay_test_failed"}'); }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ node: body.node, delay_ms: 87 }));
      }
      if (req.url === '/api/egress/diagnose') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(diagnoseView));
      }
      if (req.url === '/api/config') {
        if (!capabilityView.config_management || !body || Object.keys(body).length !== 1 || typeof body.config !== 'object') {
          res.writeHead(body && 'config' in body ? 409 : 400);
          return res.end('{"schema_version":1,"error":"invalid_body"}');
        }
        configView = { ...configView, exists: true, config: body.config };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ result: 'config_saved', config_path: configView.config_path, config: configView.config }));
      }
      if (req.url === '/api/auto' && body && typeof body.action === 'string') {
        if (body.action === 'enable') {
          const pin = node => ({ source: sourceView.nodes.find(row => row.id === node).source, node });
          sourceView.auto = { ...autoConfig, candidates: body.nodes.map(pin) }; sourceView.selection_mode = 'auto';
        }
        if (body.action === 'set-candidates' && Array.isArray(body.nodes)) {
          const pin = node => ({ source: sourceView.nodes.find(row => row.id === node).source, node });
          sourceView.auto.candidates = body.nodes.map(pin);
        }
        if (body.action === 'resume') { sourceView.auto.paused = false; sourceView.selection_mode = 'auto'; }
        if (body.action === 'disable') { sourceView.auto.enabled = false; sourceView.selection_mode = 'manual'; }
        const results = { enable: 'auto_enabled', 'set-candidates': 'auto_candidates_updated', resume: 'auto_resumed', disable: 'auto_disabled' };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ result: results[body.action] || 'auto_invalid_action' }));
      }
      res.writeHead(400); res.end('{"error":"invalid_body"}');
    });
    return;
  }
  if (req.url === '/api/config') {
    if (!capabilityView.config_management) { res.writeHead(405); return res.end('{"error":"read_only"}'); }
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify(configView));
  }
  if (req.url === '/api/capabilities') {
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify(capabilityView));
  }
  if (req.url === '/api/sources') {
    if (!sourceView) { res.writeHead(503); return res.end('unavailable'); }
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify(sourceView));
  }
  if (req.url === '/api/snapshot') {
    if (mode === 'error') { res.writeHead(503); return res.end('unavailable'); }
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify(mode === 'invalid' ? { schema_version: 2 } : snapshot));
  }
  const name = ({ '/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css', '/logo.png': 'logo.png' })[req.url];
  if (!name) { res.writeHead(404); return res.end(); }
  res.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : name.endsWith('.png') ? 'image/png' : 'text/html');
  res.end(fs.readFileSync(path.join(root, name)));
});
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}), args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    const now = Date.now() / 1000;
    snapshot = { schema_version: 1, generated_at: now, collector: { state: 'no_data', last_sample_at: null }, samples: [], incidents: [], gaps: [] };
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.waitForFunction(() => document.querySelector('#connection').textContent.includes('尚无监控数据'));
    assert.equal(await page.title(), 'NMD · Network Monitor & Diagnostics · 网络观察台');
    assert.equal(await page.locator('.brand strong').textContent(), 'NMD');
    assert.equal(await page.locator('.brand small').textContent(), '网络观察台');
    assert.equal(await page.locator('header .eyebrow').textContent(), 'Network Monitor & Diagnostics');
    assert.match(await page.locator('#connection').textContent(), /nmd CLI/);
    assert.equal(await page.locator('#collector-state').textContent(), '未知');
    assert.equal(await page.locator('#incident-count').textContent(), '未知');
    assert.equal(await page.locator('#paths .ok').count(), 0);
    assert.match(await page.locator('#egress-active').textContent(), /未知/);
    // Theme tokens: the light override block must actually re-skin the GUI,
    // color-scheme must flip so native form controls follow the active theme,
    // and the dark base must keep its exact original panel colors. Each scheme
    // is asserted after a fresh reload: flipping prefers-color-scheme live on
    // an already-rendered page can leave stale computed var() styles in
    // Chromium, so a reload keeps the fixture deterministic.
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.reload();
    assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme), 'dark');
    const darkCard = await page.evaluate(() => getComputedStyle(document.querySelector('.card')).backgroundColor);
    const darkSidebar = await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar')).backgroundColor);
    const darkNavActive = await page.evaluate(() => getComputedStyle(document.querySelector('.nav.active')).backgroundColor);
    const darkNavActiveColor = await page.evaluate(() => getComputedStyle(document.querySelector('.nav.active')).color);
    assert.equal(darkCard, 'rgb(21, 28, 41)');
    assert.equal(darkNavActive, 'rgb(36, 48, 74)');
    // The active-nav text keeps its exact original #c9d4ff tint: it is a
    // one-off accent step (--ink-750), not the shared --ink-800 button text.
    assert.equal(darkNavActiveColor, 'rgb(201, 212, 255)');
    await assertTextContrast(page);
    await page.emulateMedia({ colorScheme: 'light' });
    await page.reload();
    assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme), 'light');
    const lightCard = await page.evaluate(() => getComputedStyle(document.querySelector('.card')).backgroundColor);
    const lightSidebar = await page.evaluate(() => getComputedStyle(document.querySelector('.sidebar')).backgroundColor);
    const lightNavActive = await page.evaluate(() => getComputedStyle(document.querySelector('.nav.active')).backgroundColor);
    assert.notEqual(lightCard, darkCard);
    assert.notEqual(lightSidebar, darkSidebar);
    assert.notEqual(lightNavActive, darkNavActive);
    await assertTextContrast(page);
    // Reduced-motion emulation must not break rendering of key elements.
    await page.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await page.locator('h1').textContent(), '网络概览');
    assert.equal(await page.locator('.brand strong').textContent(), 'NMD');
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'no-preference' });
    await page.reload();
    await page.waitForFunction(() => document.querySelector('#connection').textContent.includes('尚无监控数据'));
    const refresh = async () => { await page.locator('#refresh').click(); await page.waitForFunction(() => !document.querySelector('#refresh').disabled); };
    snapshot = { schema_version: 1, generated_at: now, collector: { state: 'fresh', last_sample_at: now, interval_seconds: 30 }, samples: [
      { id: '<img src=x onerror="window.injected=true">', type: 'http', path: 'system', status: 'success', timings: { total: 0.125 }, observed_at: now },
      { id: 'proxy-http', type: 'http', path: 'proxy', status: 'failure', error: 'timeout', observed_at: now, timings: {} }
    ], incidents: [
      { id: 2, probe: 'proxy-http', first_failure: now - 120, confirmed_at: now - 60, recovered_at: null, end_reason: 'observation_gap' },
      { id: 1, probe: 'system-http', first_failure: now - 300, confirmed_at: now - 240, recovered_at: now - 120, end_reason: 'recovered' }
    ], gaps: [{ start: now - 70, end: now - 40, reason: 'collector_restart' }] };
    sourceView = { schema_version: 1, sources: [{ id: 'sub-a', kind: 'subscription', node_count: 2 }], active: 'nmd-sub-a-0123456789abcdef0123', controller: 'observed' };
    mode = 'fresh'; await refresh();
    assert.match(await page.locator('#egress-active').textContent(), /nmd-sub-a/);
    assert.match(await page.locator('#egress-sources').textContent(), /URL 已隐藏/);
    assert.match(await page.locator('#overview').textContent(), /不证明网络或 AI 业务可用/);
    assert.equal(await page.locator('#collector-state').textContent(), '最近有采样');
    snapshot.collector.data_origin = 'demo';
    capabilityView.platform = 'macos';
    await refresh();
    assert.equal(await page.locator('#demo-notice').isVisible(), true);
    assert.match(await page.locator('#demo-notice').textContent(), /合成数据/);
    assert.equal(await page.locator('#collector-state').textContent(), '模拟样本');
    assert.match(await page.locator('#platform-capabilities').textContent(), /macOS.*不支持/);
    delete snapshot.collector.data_origin;
    capabilityView.platform = 'linux';
    await refresh();
    assert.equal(await page.locator('#demo-notice').isVisible(), false);
    assert.match(await page.locator('#paths').textContent(), /系统默认路径[\s\S]*成功[\s\S]*显式代理路径[\s\S]*失败/);
    assert.match(await page.locator('#gaps').textContent(), /采集器重启/);
    if (process.env.DASHBOARD_SCREENSHOT) await page.screenshot({ path: process.env.DASHBOARD_SCREENSHOT, fullPage: true });
    sourceView = { schema_version: 1, selection_mode: 'manual', controller: 'observed',
      sources: [{ id: 'sub-a', kind: 'subscription', node_count: 2, url: '[redacted]', expected_ip_configured: false, refreshed_at: now, fallback: 'manual' }],
      nodes: [
        { id: 'nmd-sub-a-0123456789abcdef0123', source: 'sub-a', display: '香港 01 | IEPL' },
        { id: 'nmd-sub-a-aaaaaaaaaaaaaaaaaaaa', source: 'sub-a', display: '<img src=x onerror="window.injected=true">' }
      ], active: 'nmd-sub-a-0123456789abcdef0123', desired: 'nmd-sub-a-0123456789abcdef0123' };
    snapshot.auto_events = [{ id: 1, ts: now - 30, kind: 'auto_switch', detail: { from: 1, to: 0, node: 'nmd-sub-a-0123456789abcdef0123', reason: 'candidate_recovered' } }];
    snapshot.collector.auto_runtime = { target: 0 };
    await refresh();
    await page.locator('[data-page="egress"]').click();
    assert.equal(await page.locator('#egress').isVisible(), true);
    assert.match(await page.locator('#egress-current-name').textContent(), /香港 01 \| IEPL/);
    assert.equal(await page.locator('#egress-node-list img').count(), 0);
    assert.match(await page.locator('#auto-timeline').textContent(), /自动切换/);
    // Saving Channel forms has no refresh/probe/selection/policy side effect.
    assert.equal(await page.locator('#auto-candidate-rows select[data-rank="0"]').inputValue(), '');
    assert.equal(await page.locator('#auto-candidate-rows select[data-rank="1"]').inputValue(), '');
    // The default path creates a Tailnet channel without touching the type selector.
    await assertChannelFields(page, 'tailnet');
    assert.equal(await page.locator('#channel-port').inputValue(), '1080');
    const tailnetPostsBefore = posts.length;
    await page.locator('#channel-id').fill('new-tailnet');
    await page.locator('#channel-name').fill('Tailnet 直连 VPS');
    await page.locator('#channel-server').fill('100.64.0.30');
    await page.locator('#channel-add-submit').click();
    await page.waitForFunction(() => document.querySelector('#channel-list').textContent.includes('Tailnet 直连 VPS'));
    assert.deepEqual(posts.slice(tailnetPostsBefore).map(([url]) => url), ['/api/channels']);
    assert.deepEqual(JSON.parse(posts.at(-1)[1]), {
      id: 'new-tailnet', definition: { kind: 'tailnet', display_name: 'Tailnet 直连 VPS', server: '100.64.0.30', port: 1080 }
    });
    assert.equal(await page.locator('button[data-refresh="new-tailnet"]').count(), 0);
    assert.equal(sourceView.active, 'nmd-sub-a-0123456789abcdef0123');
    assert.equal(sourceView.auto, undefined);
    await assertChannelFields(page, 'tailnet');
    assert.equal(await page.locator('#channel-id').inputValue(), '');
    assert.equal(await page.locator('#channel-server').inputValue(), '');
    assert.equal(await page.locator('#channel-port').inputValue(), '1080');
    const channelPostsBefore = posts.length;
    // Inactive proxy fields must neither block subscription validation nor leak
    // into its payload, even when a draft survives a round trip between types.
    await page.locator('#channel-port').fill('0');
    await page.locator('#channel-username').fill('SYNTHETIC_INACTIVE_USER');
    await page.locator('#channel-password').fill('SYNTHETIC_INACTIVE_PASSWORD');
    await page.locator('#channel-kind').selectOption('subscription');
    await assertChannelFields(page, 'subscription');
    await page.locator('#channel-id').fill('new-sub');
    await page.locator('#channel-name').fill('新增订阅');
    await page.locator('#channel-url').fill('https://fixture.example.invalid/SYNTHETIC_URL_SECRET');
    assert.equal(await page.locator('#channel-add-form').evaluate(form => form.checkValidity()), true);
    await page.locator('#channel-kind').selectOption('tailnet');
    await assertChannelFields(page, 'tailnet');
    assert.equal(await page.locator('#channel-add-form').evaluate(form => form.checkValidity()), false);
    await page.locator('#channel-kind').selectOption('subscription');
    await assertChannelFields(page, 'subscription');
    assert.equal(await page.locator('#channel-url').inputValue(), 'https://fixture.example.invalid/SYNTHETIC_URL_SECRET');
    assert.equal(posts.length, channelPostsBefore, 'changing channel type does not POST');
    await page.locator('#channel-add-submit').click();
    await page.waitForFunction(() => document.querySelector('#channel-list').textContent.includes('新增订阅'));
    assert.deepEqual(posts.slice(channelPostsBefore).map(([url]) => url), ['/api/channels']);
    assert.deepEqual(JSON.parse(posts.at(-1)[1]), {
      id: 'new-sub', definition: { kind: 'subscription', display_name: '新增订阅', url: 'https://fixture.example.invalid/SYNTHETIC_URL_SECRET' }
    });
    await assertChannelFields(page, 'tailnet');
    for (const field of ['id', 'name', 'url', 'server', 'username', 'password']) {
      assert.equal(await page.locator(`#channel-${field}`).inputValue(), '');
    }
    assert.equal(await page.locator('#channel-port').inputValue(), '1080');
    assert.equal(sourceView.active, 'nmd-sub-a-0123456789abcdef0123');
    assert.equal(sourceView.auto, undefined);
    assert.equal(await page.locator('#auto-candidate-rows select[data-rank="0"]').inputValue(), '');
    const rename = page.locator('.channel-rename-form[data-channel="new-sub"]');
    await rename.locator('input').fill('<img src=x onerror="window.injected=true">');
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await page.waitForFunction(() => !document.querySelector('#refresh').disabled);
    assert.equal(await rename.locator('input').evaluate(input => input === document.activeElement), true);
    await rename.locator('button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelector('#channel-list').textContent.includes('onerror'));
    assert.equal(await page.locator('#channel-list img').count(), 0);
    assert.equal(await page.evaluate(() => window.injected), undefined);
    assert.deepEqual(posts.slice(channelPostsBefore).map(([url]) => url), ['/api/channels', '/api/channels/rename']);
    // Subscription channels get an explicit refresh button; while the POST is
    // in flight it is disabled, so a double click cannot fire two fetches.
    const refreshPostsBefore = posts.length;
    refreshHold = 400;
    await page.locator('button[data-refresh="new-sub"]').click();
    await page.waitForFunction(() => {
      const button = document.querySelector('button[data-refresh="new-sub"]');
      return button && button.disabled && button.textContent.includes('更新中');
    });
    await page.evaluate(() => document.querySelector('button[data-refresh="new-sub"]').click());
    assert.match(await page.locator('#channel-action-note').textContent(), /正在更新订阅/);
    await page.waitForFunction(() => document.querySelector('#channel-action-note').textContent.includes('已更新订阅'));
    refreshHold = 0;
    assert.deepEqual(posts.slice(refreshPostsBefore).map(([url]) => url), ['/api/channels/refresh']);
    assert.deepEqual(JSON.parse(posts.at(-1)[1]), { id: 'new-sub' });
    await page.waitForFunction(() => document.querySelector('#channel-list').textContent.includes('3 个缓存节点'));
    assert.equal(await page.locator('button[data-refresh="new-sub"]').isEnabled(), true);
    // Duplicate IDs are a visible, sanitized error and preserve the form draft.
    await page.locator('#channel-kind').selectOption('subscription');
    await assertChannelFields(page, 'subscription');
    await page.locator('#channel-id').fill('new-sub');
    await page.locator('#channel-name').fill('重复');
    await page.locator('#channel-url').fill('https://fixture.example.invalid/SYNTHETIC_DUPLICATE_SECRET');
    await page.locator('#channel-add-submit').click();
    await page.waitForFunction(() => document.querySelector('#channel-action-note').textContent.includes('已存在'));
    assert.equal(await page.locator('#channel-id').inputValue(), 'new-sub');
    await assertChannelFields(page, 'subscription');
    assert.equal(await page.locator('#channel-url').inputValue(), 'https://fixture.example.invalid/SYNTHETIC_DUPLICATE_SECRET');
    const proxyPostsBefore = posts.length;
    await page.locator('#channel-kind').selectOption('proxy');
    await assertChannelFields(page, 'proxy');
    await page.locator('#channel-id').fill('new-proxy');
    await page.locator('#channel-name').fill('公网备用');
    await page.locator('#channel-server').fill('192.0.2.30');
    await page.locator('#channel-port').fill('1088');
    await page.locator('#channel-username').fill('SYNTHETIC_PROXY_USER');
    await page.locator('#channel-password').fill('SYNTHETIC_PROXY_PASSWORD');
    await page.locator('#channel-add-submit').click();
    await page.waitForFunction(() => document.querySelector('#channel-list').textContent.includes('公网备用'));
    assert.deepEqual(posts.slice(proxyPostsBefore).map(([url]) => url), ['/api/channels']);
    // Manual proxy channels never offer a subscription refresh button.
    assert.equal(await page.locator('button[data-refresh="new-proxy"]').count(), 0);
    assert.equal(JSON.parse(posts.at(-1)[1]).definition.url, undefined);
    assert.deepEqual(JSON.parse(posts.at(-1)[1]), {
      id: 'new-proxy', definition: { kind: 'proxy', display_name: '公网备用', server: '192.0.2.30', port: 1088,
        username: 'SYNTHETIC_PROXY_USER', password: 'SYNTHETIC_PROXY_PASSWORD' }
    });
    await assertChannelFields(page, 'tailnet');
    assert.equal(await page.locator('#auto-candidate-rows select[data-rank="0"]').inputValue(), '');
    assert.equal(sourceView.active, 'nmd-sub-a-0123456789abcdef0123');
    const publicChannels = await page.evaluate(() => fetch('/api/sources').then(response => response.json()));
    for (const secret of ['SYNTHETIC_URL_SECRET', 'SYNTHETIC_PROXY_USER', 'SYNTHETIC_PROXY_PASSWORD', '192.0.2.30']) assert.equal(JSON.stringify(publicChannels).includes(secret), false);
    await page.locator('.node-select[data-node="nmd-sub-a-aaaaaaaaaaaaaaaaaaaa"]').click();
    await page.waitForFunction(() => document.querySelector('#egress-current-name').textContent.includes('onerror'));
    assert.ok(posts.some(([url, body]) => url === '/api/egress/select' && body.includes('aaaaaaaaaaaaaaaaaaaa')), 'switch POST');
    await page.locator('.delay-btn[data-node="nmd-sub-a-0123456789abcdef0123"]').click();
    await page.waitForFunction(() => document.querySelector('#egress-node-list').textContent.includes('87 ms'));
    failingNodes.push('nmd-sub-a-0123456789abcdef0123');
    await page.locator('.delay-btn[data-node="nmd-sub-a-0123456789abcdef0123"]').click();
    await page.waitForFunction(() => document.querySelector('#egress-node-list').textContent.includes('失败'));
    failingNodes.length = 0;
    await page.locator('#auto-candidate-rows select[data-rank="0"]').selectOption('nmd-sub-a-0123456789abcdef0123');
    await page.locator('#auto-candidate-rows select[data-rank="1"]').selectOption('nmd-sub-a-0123456789abcdef0123');
    const policyPostsBefore = posts.length;
    await page.locator('#auto-enable').click();
    assert.equal(posts.length, policyPostsBefore);
    // A third row can be added and removed again; two rows stay the minimum.
    await page.locator('#auto-add-candidate').click();
    await page.waitForFunction(() => document.querySelectorAll('#auto-candidate-rows select').length === 3);
    await page.locator('#auto-candidate-rows .candidate-remove[data-rank="2"]').click();
    await page.waitForFunction(() => document.querySelectorAll('#auto-candidate-rows select').length === 2);
    await page.locator('#auto-candidate-rows select[data-rank="1"]').selectOption('nmd-sub-a-aaaaaaaaaaaaaaaaaaaa');
    await page.locator('#auto-enable').click();
    await page.waitForFunction(() => document.querySelector('#auto-state').textContent.includes('运行中'));
    assert.ok(posts.some(([url, body]) => url === '/api/auto' && JSON.parse(body).action === 'enable'
      && JSON.parse(body).nodes.length === 2 && JSON.parse(body).nodes[0] === 'nmd-sub-a-0123456789abcdef0123'
      && JSON.parse(body).nodes[1] === 'nmd-sub-a-aaaaaaaaaaaaaaaaaaaa'), 'auto enable POST');
    assert.match(await page.locator('#auto-state').textContent(), /候选1 香港 01 \| IEPL ●当前/);
    assert.equal(await page.locator('#auto-toggle-primary').count(), 0);
    // Reordering the enabled policy posts set-candidates instead of enable.
    await page.locator('#auto-candidate-rows .candidate-move[data-rank="1"][data-move="up"]').click();
    await page.locator('#auto-enable').click();
    await page.waitForFunction(() => document.querySelector('#egress-action-note').textContent.includes('已更新候选列表'));
    const update = posts.filter(([url]) => url === '/api/auto').at(-1);
    assert.match(update[1], /"action":"set-candidates"/);
    assert.deepEqual(JSON.parse(update[1]).nodes, ['nmd-sub-a-aaaaaaaaaaaaaaaaaaaa', 'nmd-sub-a-0123456789abcdef0123']);
    // One-click layered diagnosis posts a strict empty body and renders the
    // mocked per-layer rows plus the verdict hint from the fixed code set.
    diagnoseView = { schema_version: 1, generated_at: now, selector_now: 'nmd-sub-a-0123456789abcdef0123',
      probes: { direct_foreign: { status: 'ok', error: null, total_ms: 41 },
                egress_cn: { status: 'ok', error: null, total_ms: 18 },
                egress_foreign: { status: 'ok', error: null, total_ms: 152 },
                egress_exit_ip: { status: 'ok', error: null, total_ms: 143 } },
      verdict: { code: 'egress_healthy', hint_key: 'egress_healthy' },
      candidates: [{ source: 'sub-a', kind: 'subscription', node: 'nmd-sub-a-0123456789abcdef0123',
                     health: 'ok', delay_ms: 87, tcp: 'skipped', tcp_ms: null, tcp_reason: 'server_routed_through_tun' }] };
    const diagnosePostsBefore = posts.length;
    await page.locator('#diagnose-run').click();
    await page.waitForFunction(() => document.querySelector('#diagnose-results')?.textContent.includes('各层探测均正常'));
    assert.deepEqual(posts.slice(diagnosePostsBefore).map(([url]) => url), ['/api/egress/diagnose']);
    assert.deepEqual(JSON.parse(posts.at(-1)[1]), {});
    const diagnoseText = await page.locator('#diagnose-results').textContent();
    assert.match(diagnoseText, /本机直连外网/);
    assert.match(diagnoseText, /经节点访问外网/);
    assert.match(diagnoseText, /152 ms/);
    assert.match(diagnoseText, /TCP 跳过（非 Tailnet 路径）/);
    // A fault verdict run re-renders layers and the matching hint.
    diagnoseView = { ...diagnoseView,
      probes: { ...diagnoseView.probes,
        egress_foreign: { status: 'fail', error: 'dns_error', total_ms: null },
        egress_exit_ip: { status: 'ok', error: null, total_ms: 200 } },
      verdict: { code: 'exit_dns_poisoned', hint_key: 'exit_dns_poisoned' } };
    await page.locator('#diagnose-run').click();
    await page.waitForFunction(() => document.querySelector('#diagnose-results').textContent.includes('出口侧解析故障'));
    assert.match(await page.locator('#diagnose-results').textContent(), /失败（dns_error）/);
    assert.equal(await page.locator('#egress img').count(), 0);
    capabilityView.platform = 'macos';
    capabilityView.local_egress_control = false;
    capabilityView.channel_management = false;
    const postsBeforeReadOnly = posts.length;
    await refresh();
    assert.equal(await page.locator('.node-select').first().isEnabled(), false);
    assert.equal(await page.locator('.delay-btn').first().isEnabled(), false);
    // Diagnosis stays a Linux control action: the button is disabled in
    // read-only mode, so no probe battery can be posted.
    assert.equal(await page.locator('#diagnose-run').isEnabled(), false);
    assert.match(await page.locator('#diagnose-results').textContent(), /仅 Linux 出口控制环境可用/);
    assert.equal(await page.locator('#auto-actions').isVisible(), false);
    assert.equal(await page.locator('#channel-add-form').isVisible(), false);
    assert.equal(await page.locator('button[data-refresh]').count(), 0);
    await page.evaluate(() => {
      document.getElementById('channel-add-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
      document.getElementById('auto-config-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });
    assert.equal(posts.length, postsBeforeReadOnly);
    // macOS keeps exactly one write path: monitor-config editing on the
    // settings page. Saving posts one strict config object and nothing else.
    capabilityView.config_management = true;
    await refresh();
    assert.match(await page.locator('#sidebar-mode').textContent(), /观察与配置编辑/);
    assert.match(await page.locator('#platform-capabilities').textContent(), /监控配置可在「设置与帮助」页编辑/);
    await page.locator('[data-page="help"]').click();
    assert.equal(await page.locator('#config-card').isVisible(), true);
    assert.equal(await page.locator('#config-unavailable').isVisible(), false);
    assert.match(await page.locator('#config-path').textContent(), /monitor\.json/);
    assert.match(await page.locator('#config-path').textContent(), /尚未创建/);
    assert.equal(await page.locator('#config-interval').inputValue(), '30');
    assert.equal(await page.locator('#config-probe-list').textContent(), '尚未配置探测项；显式添加并保存后，显式采集才会发起真实探测。');
    await page.locator('#config-probe-add').click();
    const probeRow = page.locator('#config-probe-list .probe-row');
    assert.equal(await probeRow.locator('[name=proxy]').isVisible(), false);
    await probeRow.locator('[name=id]').fill('fixture-http');
    await probeRow.locator('[name=target]').fill('https://example.com/');
    await probeRow.locator('[name=path]').selectOption('proxy');
    assert.equal(await probeRow.locator('[name=proxy]').isVisible(), true);
    await probeRow.locator('[name=path]').selectOption('system');
    assert.equal(await probeRow.locator('[name=proxy]').isVisible(), false);
    await page.locator('#config-interval').fill('15');
    const configPostsBefore = posts.length;
    await page.locator('#config-save').click();
    await page.waitForFunction(() => document.querySelector('#config-note').textContent.includes('已保存'));
    assert.deepEqual(posts.slice(configPostsBefore).map(([url]) => url), ['/api/config']);
    assert.deepEqual(JSON.parse(posts.at(-1)[1]), { config: { interval_seconds: 15, timeout_seconds: 5,
      retention_hours: 168, max_samples: 100000,
      probes: [{ id: 'fixture-http', type: 'http', target: 'https://example.com/', path: 'system', enabled: true }] } });
    assert.match(await page.locator('#config-note').textContent(), /未启动或重启任何采集/);
    assert.equal((await page.locator('#config-path').textContent()).includes('尚未创建'), false);
    // Polling refreshes never clobber the saved values or fire extra writes.
    await refresh();
    assert.equal(await page.locator('#config-interval').inputValue(), '15');
    assert.equal(posts.length, configPostsBefore + 1);
    capabilityView.config_management = false;
    await refresh();
    assert.equal(await page.locator('#config-card').isVisible(), false);
    assert.equal(await page.locator('#config-unavailable').isVisible(), true);
    capabilityView.platform = 'linux';
    capabilityView.local_egress_control = true;
    capabilityView.channel_management = true;
    await refresh();
    assert.equal(await page.evaluate(() => window.injected), undefined);
    sourceView = { schema_version: 1, sources: [{ id: 'sub-a', kind: 'subscription', node_count: 2 }], active: 'nmd-sub-a-0123456789abcdef0123', controller: 'observed' };
    delete snapshot.auto_events; delete snapshot.collector.auto_runtime;
    await refresh();
    await page.locator('[data-page="probes"]').click();
    assert.equal(await page.locator('#probes').isVisible(), true);
    assert.equal(await page.locator('#overview').isVisible(), false);
    assert.match(await page.locator('#probe-list').textContent(), /125.0 ms/);
    assert.equal(await page.locator('#probe-list img').count(), 0);
    assert.equal(await page.evaluate(() => window.injected), undefined);
    await page.locator('[data-page="incidents"]').click();
    assert.match(await page.locator('#incident-list').textContent(), /监控中断 · 结束未知/);
    assert.match(await page.locator('#incident-list').textContent(), /3 分 0 秒/);
    assert.match(await page.locator('#incident-list').textContent(), /根因未判定/);
    await page.locator('[data-page="overview"]').click();
    snapshot.collector.last_sample_at = now - 120; await refresh();
    assert.match(await page.locator('#connection').textContent(), /过期/);
    assert.equal(await page.locator('#paths .ok').count(), 0);
    assert.equal(await page.locator('#incident-count').textContent(), '未知');
    snapshot.collector.last_sample_at = now + 3600; await refresh();
    assert.equal(await page.locator('#collector-state').textContent(), '未知');
    snapshot.collector.last_sample_at = now; mode = 'error'; await refresh();
    assert.match(await page.locator('#connection').textContent(), /无法读取/);
    assert.equal(await page.locator('#paths .ok').count(), 0);
    mode = 'invalid'; await refresh();
    assert.equal(await page.locator('#collector-state').textContent(), '未知');
    mode = 'fresh'; await refresh();
    assert.equal(await page.locator('#collector-state').textContent(), '最近有采样');
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    sourceView = null; await refresh();
    assert.match(await page.locator('#egress-active').textContent(), /未知/);
    await page.locator('[data-page="help"]').click();
    assert.match(await page.locator('#help').textContent(), /关闭窗口不会停止监控/);
    assert.match(await page.locator('#help').textContent(), /nmd CLI/);
    assert.equal(await page.locator('#help').isVisible(), true);
    const before = requests.filter(r => r[1] === '/api/snapshot').length;
    await page.waitForTimeout(5200);
    assert.ok(requests.filter(r => r[1] === '/api/snapshot').length > before, 'visible page polls');
    const readable = ['/', '/app.js', '/style.css', '/logo.png', '/api/snapshot', '/api/sources', '/api/capabilities', '/api/config', '/favicon.ico'];
    const writable = ['/api/egress/select', '/api/egress/delay', '/api/egress/diagnose', '/api/auto', '/api/channels', '/api/channels/rename', '/api/channels/refresh', '/api/config'];
    assert.ok(requests.every(([method, url]) => (method === 'GET' && readable.includes(url)) || (method === 'POST' && writable.includes(url))), 'only intended same-origin requests');
    // Render only the bundled error page. Never launch the desktop binary,
    // invoke a custom URL handler, read real configuration, or start a sidecar.
    const errorPage = await browser.newPage();
    const errorPageRequests = [];
    errorPage.on('request', request => errorPageRequests.push(request.url()));
    await errorPage.setContent(fs.readFileSync(path.join(root, 'desktop-error.html'), 'utf8'));
    assert.equal(await errorPage.locator('h1').textContent(), '本地面板未能启动');
    assert.equal(await errorPage.getByRole('link', { name: '重试连接' }).isVisible(), true);
    assert.equal(await errorPage.getByRole('link', { name: '退出' }).isVisible(), true);
    assert.deepEqual(await errorPage.locator('a').evaluateAll(links => links.map(link => link.getAttribute('href'))),
      ['nmd-startup://retry', 'nmd-startup://quit']);
    assert.equal(await errorPage.locator('script, iframe, img').count(), 0);
    assert.deepEqual(errorPageRequests, []);
    await errorPage.close();
    assert.deepEqual(errors, []);
    console.log('Dashboard browser tests passed: empty, fresh, failed paths, gaps, incidents, egress switch/delay/auto, one-click diagnose, channel subscription refresh, XSS, stale/future, HTTP/schema errors, recovery, mobile, polling, theme dark/light tokens, reduced motion, CSP.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => server.close());
