/* Local viewer with explicit egress controls and save-only private Channel configuration. */
'use strict';
(() => {
  let busy = false, snapshot = null, failure = null, sources = null, pendingSelect = false, capabilities = null;
  const delayResults = new Map(), pendingDelay = new Set(), renameDrafts = new Map();
  let pendingChannel = false, pendingPolicy = false;
  const $ = id => document.getElementById(id);
  const make = (tag, value, cls) => {
    const el = document.createElement(tag);
    if (value !== undefined) el.textContent = String(value);
    if (cls) el.className = cls;
    return el;
  };
  const text = (id, value) => { $(id).textContent = value; };
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const date = value => finite(value) ? new Date(value * 1000).toLocaleString('zh-CN', { hour12: false, timeZoneName: 'short' }) : '未知';
  const elapsed = seconds => {
    if (!finite(seconds) || seconds < 0) return '未知';
    seconds = Math.floor(seconds);
    return seconds < 60 ? `${seconds} 秒` : seconds < 3600 ? `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒` : `${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds % 3600 / 60)} 分`;
  };
  const pathName = value => ({ system: '系统默认路径', proxy: '显式代理路径', local: '本地被动观测' }[value] || '未知路径');
  const statusName = value => ({ success: '成功', failure: '失败', observed: '已观测', unknown: '未知', skipped: '已跳过' }[value] || '未知');
  const badge = (status, label) => make('span', label || statusName(status), `badge ${status === 'success' ? 'ok' : status === 'failure' ? 'fail' : 'unknown'}`);
  const empty = value => make('div', value, 'empty');
  function details(pairs) {
    const dl = make('dl', undefined, 'details');
    for (const [key, value] of pairs) {
      const item = make('div'); item.append(make('dt', key), make('dd', value)); dl.append(item);
    }
    return dl;
  }
  function valid(value) {
    return value && value.schema_version === 1 && value.collector && typeof value.collector === 'object' && ['samples', 'incidents', 'gaps'].every(key => Array.isArray(value[key]) && value[key].every(row => row && typeof row === 'object' && !Array.isArray(row)));
  }
  const controlsEnabled = () => capabilities?.platform === 'linux' && capabilities?.local_egress_control === true && snapshot?.collector?.data_origin !== 'demo';
  const channelManagementEnabled = () => controlsEnabled() && capabilities?.channel_management === true;
  const channelLabel = channel => channel.display_name || channel.id;
  const connectionLabel = kind => ({ subscription: '订阅 · URL 已隐藏', tailnet: 'SOCKS5 · Tailnet 路径', proxy: 'SOCKS5 · 普通路径' }[kind] || '未知通道');
  async function postJSON(path, body) {
    if (!controlsEnabled()) throw new Error('read_only');
    const abort = new AbortController(), timeout = setTimeout(() => abort.abort(), 8000);
    try {
      const response = await fetch(path, { method: 'POST', signal: abort.signal, cache: 'no-store', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
      const data = await response.json().catch(() => null);
      if (!response.ok) throw new Error(data?.error || `http_${response.status}`);
      return data;
    } finally { clearTimeout(timeout); }
  }
  const controlErrors = {
    read_only: '此环境仅支持只读诊断；出口控制不可用。', invalid_body: '输入无效或过长，请检查字段。',
    node_not_found: '节点不存在，可能已随订阅刷新变化。', node_not_deployed_apply_first: '节点未部署，请先运行 nmd apply。',
    selection_outcome_unknown_read_status_before_retry: '切换结果不确定，已停止重试；请刷新查看当前出口。',
    delay_test_failed: '测速失败或该节点当前不可达。', source_operation_busy: '操作冲突，请稍后重试。',
    auto_not_configured: '自动切换尚未配置。', auto_requires_single_tailnet_node: '需要恰好一个 Tailnet 来源节点。',
    auto_requires_subscription_node: '请先选择一个订阅节点作为候选。', auto_primary_required: '需要指定主选侧。',
    invalid_channel_name: '显示名称须为 1–128 个字符，不能含控制字符。', source_already_exists: '通道 ID 已存在，请使用另一个 ID。',
    invalid_source_id: '通道 ID 需以小写字母开头，只含小写字母、数字和短横线，最长 32 字符。',
    subscription_requires_https_url: '订阅需使用 HTTPS 443 URL，不能含用户名、密码或片段。',
    proxy_requires_literal_non_tailnet_ip: '普通路径代理需使用非 Tailnet 的 IP 地址。', tailnet_requires_literal_tailnet_ip: 'Tailnet 通道需使用 Tailnet IP 地址。',
    invalid_proxy_port: '端口须为 1–65535。', auto_candidates_must_differ: '主备节点必须不同。', auto_node_not_in_inventory: '请明确选择两个有效缓存节点。',
    auto_invalid_parameters: '参数无效。', auto_invalid_action: '操作无效。', sources_unavailable: '私有来源数据不可用。'
  };
  const autoEventNames = {
    auto_engaged: '自动接管', auto_switch: '自动切换', auto_switch_failed: '切换失败', auto_verify_adopted: '切换确认',
    auto_suspended: '自动挂起', auto_resumed: '自动恢复', manual_engage_primary: '手动回到主选',
    manual_engage_secondary: '手动选择备选', candidate_changed: '候选变化', controller_unreachable: '控制器不可达',
    both_unhealthy: '双侧不健康', auto_error: '评估异常'
  };
  function note(message) { text('egress-action-note', message || ''); }
  function renderChannels() {
    const canManage = channelManagementEnabled();
    $('channel-add-form').hidden = !canManage;
    $('channel-create-fields').disabled = !canManage || pendingChannel;
    const subscription = $('channel-kind').value === 'subscription';
    $('channel-subscription-fields').hidden = !subscription;
    $('channel-subscription-fields').disabled = !subscription || !canManage || pendingChannel;
    $('channel-proxy-fields').hidden = subscription;
    $('channel-proxy-fields').disabled = subscription || !canManage || pendingChannel;
    $('channel-add-submit').disabled = !canManage || pendingChannel;
    // Preserve an in-progress rename across read-only polling refreshes.
    if (canManage && !pendingChannel && $('channel-list').contains(document.activeElement) && document.activeElement.matches('input')) return;
    $('channel-list').replaceChildren();
    const channels = (sources?.sources || []).slice(0, 32);
    if (!channels.length) $('channel-list').append(make('p', canManage ? '尚无通道，可先保存通道配置。' : '只读环境不读取私有通道配置。', 'muted'));
    for (const channel of channels) {
      const item = make('div', undefined, 'channel-row');
      item.append(make('h3', channelLabel(channel)), make('p', `${channel.id} · ${connectionLabel(channel.kind)} · ${channel.node_count} 个缓存节点`, 'muted'));
      if (canManage) {
        const form = make('form', undefined, 'channel-rename-form');
        form.dataset.channel = channel.id;
        const label = make('label', '显示名称');
        const input = make('input'); input.name = 'display_name'; input.required = true; input.maxLength = 128;
        input.value = renameDrafts.get(channel.id) ?? channelLabel(channel); input.disabled = pendingChannel;
        input.addEventListener('input', () => renameDrafts.set(channel.id, input.value));
        label.append(input);
        const button = make('button', '重命名'); button.type = 'submit'; button.disabled = pendingChannel;
        form.append(label, button); item.append(form);
      }
      $('channel-list').append(item);
    }
  }
  function renderCandidate(select, nodes, preferred, locked) {
    const current = select.value;
    select.replaceChildren(make('option', '请选择节点'));
    select.firstElementChild.value = '';
    for (const node of nodes) {
      const channel = sources?.sources?.find(row => row.id === node.source);
      const option = make('option', `${channel ? channelLabel(channel) : node.source} · ${node.display || node.id}`);
      option.value = node.id; select.append(option);
    }
    const exists = id => nodes.some(node => node.id === id);
    select.value = locked && exists(preferred) ? preferred : exists(current) ? current : exists(preferred) ? preferred : '';
    select.disabled = !controlsEnabled() || locked || pendingPolicy;
  }
  function render() {
    const demoMode = snapshot?.collector?.data_origin === 'demo';
    const canControl = controlsEnabled();
    $('auto-actions').hidden = !canControl;
    text('sidebar-mode', canControl ? '观察与出口控制' : '只读观察模式');
    $('demo-notice').hidden = !demoMode;
    const platformName = { macos: 'macOS', linux: 'Linux', unsupported: '未支持的平台' }[capabilities?.platform];
    text('platform-capabilities', platformName ? `${platformName} · ${canControl ? '本机出口控制' : '只读面板'}${capabilities.platform === 'macos' ? ' · systemd 服务、后台安装和网络管理不支持；不读取出口来源配置。' : ''}` : '平台能力未知。');
    renderChannels();
    const nodes = Array.isArray(sources?.nodes) ? sources.nodes : [];
    const displayOf = id => { const node = nodes.find(item => item.id === id); return node?.display || id; };
    text('egress-active', sources?.controller === 'observed' && sources?.active ? `当前出口：${displayOf(sources.active)}` : '当前出口未知或尚未应用来源配置');
    $('egress-sources').replaceChildren();
    for (const source of (sources?.sources || []).slice(0, 32)) {
      $('egress-sources').append(make('p', `${channelLabel(source)} · ${connectionLabel(source.kind)} · ${source.node_count} 个缓存节点`, 'muted'));
    }
    const auto = sources?.auto || null;
    const runtime = snapshot?.collector?.auto_runtime || null;
    const targetName = runtime?.target === 'primary' ? ' · 当前目标：主选' : runtime?.target === 'secondary' ? ' · 当前目标：备选' : '';
    const activeChannel = sources?.sources?.find(channel => nodes.some(node => node.id === sources.active && node.source === channel.id));
    text('egress-current-name', sources?.controller === 'observed' && sources?.active ? `${activeChannel ? channelLabel(activeChannel) + ' · ' : ''}${displayOf(sources.active)}` : '未知');
    text('egress-current-id', sources?.active || '—');
    text('egress-current-mode', auto
      ? (auto.paused ? '自动 · 已暂停（手动接管）' : auto.enabled ? `自动 · 主选 ${displayOf(auto.primary?.node)}${targetName}` : '手动 · 自动已停用')
      : '手动选择');
    $('egress-node-list').replaceChildren();
    if (!canControl && !nodes.length) $('egress-node-list').append(empty('此环境仅提供只读诊断，不读取出口来源或启用控制。'));
    else if (!nodes.length && sources) $('egress-node-list').append(empty('暂无缓存节点；请通过 nmd source refresh 刷新订阅。'));
    else if (sources) for (const source of (sources.sources || []).slice(0, 32)) {
      const group = make('article', undefined, 'card');
      group.append(make('h2', `${channelLabel(source)} · ${connectionLabel(source.kind)} · ${source.node_count} 个节点`));
      for (const node of nodes.filter(item => item.source === source.id)) {
        const active = sources.active === node.id;
        const row = make('div', undefined, 'node-row' + (active ? ' active' : ''));
        const select = make('button', undefined, 'node-select');
        select.type = 'button'; select.dataset.node = node.id; select.disabled = pendingSelect || !canControl;
        select.append(make('span', active ? '●' : '○', 'node-dot'), make('span', node.display || node.id, 'node-name'), make('span', node.id, 'node-id'));
        const delay = make('button', '测速', 'delay-btn');
        delay.type = 'button'; delay.dataset.node = node.id; delay.disabled = pendingDelay.has(node.id) || !canControl;
        const result = make('span', pendingDelay.has(node.id) ? '测速中…' : delayResults.has(node.id)
          ? (delayResults.get(node.id) === false ? '失败' : `${delayResults.get(node.id)} ms`) : '', 'delay-result');
        row.append(select, delay, result);
        group.append(row);
      }
      $('egress-node-list').append(group);
    }
    text('auto-state', !sources ? '通道数据不可用。' : !auto ? '自动切换未启用。'
      : auto.paused ? '已暂停：手动选择优先；明确恢复后才继续评估原有候选。'
      : auto.enabled ? `运行中 · 主选 ${displayOf(auto.primary.node)} · 备选 ${displayOf(auto.secondary.node)}${targetName}` : '已停用。');
    text('auto-policy', auto ? `连续失败 ${auto.fail_after} 次切换 · 主选连续成功 ${auto.recover_after} 次回切 · 切换后冷却 ${auto.cooldown} 周期` : '');
    renderCandidate($('auto-primary-node'), nodes, auto?.primary?.node, Boolean(auto?.enabled));
    renderCandidate($('auto-secondary-node'), nodes, auto?.secondary?.node, Boolean(auto?.enabled));
    $('auto-enable').disabled = !canControl || Boolean(auto?.enabled) || pendingPolicy;
    $('auto-disable').disabled = !canControl || !auto?.enabled || pendingPolicy;
    $('auto-resume').disabled = !canControl || !auto?.enabled || !auto?.paused || pendingPolicy;
    $('auto-toggle-primary').disabled = !canControl || !auto?.enabled || auto?.paused || pendingPolicy;
    $('auto-timeline').replaceChildren();
    const events = (snapshot?.auto_events || []).slice(0, 20);
    if (!events.length) $('auto-timeline').append(make('p', '暂无自动切换记录。', 'muted'));
    for (const item of events) {
      const detail = item.detail && typeof item.detail === 'object' ? item.detail : {};
      const where = detail.node ? displayOf(detail.node) : '';
      $('auto-timeline').append(make('p', `${date(item.ts)} · ${autoEventNames[item.kind] || item.kind}${where ? ` · ${where}` : ''}${detail.reason ? ` · ${detail.reason}` : ''}`));
    }
    const now = Date.now() / 1000, c = snapshot?.collector;
    const age = finite(c?.last_sample_at) ? now - c.last_sample_at : null;
    const threshold = Math.max(30, finite(c?.expected_cycle_seconds) ? c.expected_cycle_seconds * 2 : finite(c?.interval_seconds) ? c.interval_seconds * 2 : 60);
    const fresh = !failure && c?.state === 'fresh' && age !== null && age >= -2 && age <= threshold;
    const recent = sample => fresh && finite(sample.observed_at) && now - sample.observed_at >= -2 && now - sample.observed_at <= threshold;
    let message = '尚无监控数据。网络状态未知，请通过 nmd CLI 配置并启动采集器。';
    if (failure) message = `${failure} 当前状态未知；旧记录仅供历史参考。`;
    else if (fresh) message = `快照读取正常 · 最近采样 ${elapsed(Math.max(0, age))}前 · 每 5 秒刷新。最近有采样不代表采集器仍在运行。`;
    else if (c && c.state !== 'no_data') message = `监控数据已过期或时间无效，当前网络状态未知。超过 ${threshold} 秒无新采样即视为过期。`;
    text('connection', message); $('connection').classList.toggle('fresh', fresh);
    text('collector-state', demoMode ? '模拟样本' : fresh ? '最近有采样' : '未知');
    text('collector-detail', demoMode ? '临时合成记录；未运行真实采集器' : fresh ? '进程是否仍运行：未验证' : failure ? '无法确认当前监控状态' : c?.state === 'no_data' ? '尚无采集记录' : '数据不新鲜或未提供');
    text('sample-time', date(c?.last_sample_at));
    text('sample-age', age === null ? '暂无采样时间' : `${elapsed(age)}前 · 本地时区`);
    const incidents = (snapshot?.incidents || []).slice(0, 100);
    text('incident-count', fresh ? String(incidents.filter(item => !finite(item.recovered_at) && !item.end_reason).length) : '未知');
    const byId = new Map();
    for (const sample of snapshot?.samples || []) if (typeof sample.id === 'string' && !byId.has(sample.id)) byId.set(sample.id, sample);
    const samples = Array.from(byId.values()).slice(0, 100);
    $('paths').replaceChildren();
    for (const path of ['system', 'proxy']) {
      const group = samples.filter(item => item.path === path);
      const state = !fresh || !group.length || !group.every(recent) ? 'unknown' : group.some(item => item.status === 'failure') ? 'failure' : group.every(item => item.status === 'success') ? 'success' : 'unknown';
      const card = make('article', undefined, 'card'), head = make('div', undefined, 'path-head');
      head.append(make('h2', pathName(path)), badge(state));
      card.append(head, make('p', path === 'system' ? 'SYSTEM DEFAULT / OS ROUTING' : 'EXPLICIT PROXY / CONFIGURED ENDPOINT', 'path-code'));
      card.append(make('p', group.length ? `${group.length} 项最近探测 · ${state === 'unknown' ? '当前结果不足以判断' : state === 'failure' ? '存在失败探测，请检查证据' : '所列最近探测成功'}` : '暂无对应路径的探测数据', 'muted'));
      card.append(make('p', path === 'system' ? '可能经过 TUN 或出口节点，不表示绕过代理。' : '仅表示指定代理端点路径，不代表全部系统流量。', 'muted'));
      $('paths').append(card);
    }
    $('gaps').replaceChildren();
    const gaps = (snapshot?.gaps || []).slice(0, 100);
    if (!gaps.length) $('gaps').append(make('p', '当前快照未记录空窗；这不保证历史监控连续或网络正常。', 'muted'));
    for (const gap of gaps) {
      const reason = { collector_restart: '采集器重启', sleep_or_clock_jump: '休眠或时钟跳变' }[gap.reason] || String(gap.reason || '未知原因');
      $('gaps').append(make('p', `${date(gap.start)} → ${date(gap.end)} · ${reason} · ${elapsed(finite(gap.end) && finite(gap.start) ? gap.end - gap.start : null)}`, 'muted'));
    }
    $('probe-list').replaceChildren();
    if (!samples.length) $('probe-list').append(empty('暂无探测结果。缺少数据不代表成功。'));
    for (const sample of samples) {
      const card = make('article', undefined, 'card'), head = make('div', undefined, 'row-head');
      head.append(make('h2', sample.id), badge(recent(sample) ? sample.status : 'unknown', recent(sample) ? statusName(sample.status) : `当前未知 · 历史${statusName(sample.status)}`));
      const total = sample.timings?.total;
      card.append(head, details([['路径 / 类型', `${pathName(sample.path)} / ${sample.type || '未知'}`], ['观测时间', date(sample.observed_at)], ['总耗时', finite(total) && total >= 0 ? `${(total * 1000).toFixed(1)} ms` : '未提供']]));
      card.append(make('pre', JSON.stringify({ error: sample.error ?? null, http_status: sample.http_status ?? null, timings_seconds: sample.timings || {}, ...(sample.type === 'passive' ? { synthetic: sample.synthetic ?? false, platform: sample.platform, interfaces: sample.interfaces, interface_states: sample.interface_states, interface_observation_error: sample.interface_observation_error, route_observation_error: sample.route_observation_error, services: sample.services, service_observation_error: sample.service_observation_error, ipv4_default_routes: sample.ipv4_default_routes, route_fingerprint: sample.route_fingerprint } : {}) }, null, 2), 'evidence'));
      $('probe-list').append(card);
    }
    $('incident-list').replaceChildren();
    if (!incidents.length) $('incident-list').append(empty('当前快照未记录事件；不等同于网络从未发生故障。'));
    for (const incident of incidents) {
      const recovered = finite(incident.recovered_at) && incident.end_reason === 'recovered';
      const gap = incident.end_reason === 'observation_gap';
      const label = recovered ? '已观察到恢复' : gap ? '监控中断 · 结束未知' : fresh ? '未记录恢复' : '当前未知 · 未记录恢复';
      const card = make('article', undefined, 'card'), head = make('div', undefined, 'row-head');
      head.append(make('h2', `#${incident.id ?? '?'} · ${incident.probe || '未知探测'}`), badge(recovered ? 'success' : 'unknown', label));
      const duration = finite(incident.first_failure) && recovered ? elapsed(incident.recovered_at - incident.first_failure) : '未确定';
      card.append(head, details([['首次失败', date(incident.first_failure)], ['恢复确认', recovered ? date(incident.recovered_at) : '未知'], ['观测区间长度', duration]]));
      card.append(make('p', '时间是探测观察边界，并非精确故障起止；监控中断不视为恢复。', 'muted'));
      card.append(make('pre', JSON.stringify({ confirmed_at: date(incident.confirmed_at), last_success: date(incident.last_success), recovery_first: date(incident.recovery_first), end_reason: incident.end_reason ?? null, evidence: '连续失败达到事件记录阈值；根因未判定' }, null, 2), 'evidence'));
      $('incident-list').append(card);
    }
  }
  async function refresh() {
    if (busy) return;
    busy = true; $('refresh').disabled = true;
    const abort = new AbortController(), timeout = setTimeout(() => abort.abort(), 4000);
    const capabilityRequest = fetch('/api/capabilities', { signal: abort.signal, cache: 'no-store', credentials: 'same-origin' })
      .then(response => response.ok ? response.json() : null)
      .then(value => { capabilities = value?.schema_version === 1 ? value : null; })
      .catch(() => { capabilities = null; });
    const sourceRequest = fetch('/api/sources', { signal: abort.signal, cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(response => response.ok ? response.json() : null)
      .then(value => { sources = value?.schema_version === 1 && Array.isArray(value.sources) ? value : null; })
      .catch(() => { sources = null; });
    try {
      const response = await fetch('/api/snapshot', { signal: abort.signal, cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('snapshot_http_error');
      const data = await response.json();
      if (!valid(data)) throw new Error('invalid_snapshot');
      snapshot = data; failure = null;
    } catch (error) { failure = error.name === 'AbortError' ? '读取快照超时。' : '无法读取有效监控快照。'; }
    finally { await Promise.all([sourceRequest, capabilityRequest]); clearTimeout(timeout); busy = false; $('refresh').disabled = false; render(); }
  }
  const titles = { overview: '网络概览', probes: '探测明细', incidents: '事件记录', egress: '出口节点', help: '设置与帮助' };
  document.querySelectorAll('[data-page]').forEach(button => button.addEventListener('click', () => {
    document.querySelectorAll('.page').forEach(page => { page.hidden = page.id !== button.dataset.page; });
    document.querySelectorAll('[data-page]').forEach(nav => {
      nav.classList.toggle('active', nav === button);
      if (nav === button) nav.setAttribute('aria-current', 'page'); else nav.removeAttribute('aria-current');
    });
    text('page-title', titles[button.dataset.page]);
  }));
  async function controlSelect(id) {
    if (pendingSelect) return;
    pendingSelect = true; note('正在切换出口…'); render();
    try { await postJSON('/api/egress/select', { node: id }); note('已切换并读回确认。'); }
    catch (error) { note(controlErrors[error.message] || '切换失败。'); }
    finally { pendingSelect = false; await refresh(); }
  }
  async function controlDelay(id) {
    if (pendingDelay.has(id)) return;
    pendingDelay.add(id); note(''); render();
    try { const data = await postJSON('/api/egress/delay', { node: id }); delayResults.set(id, data.delay_ms); }
    catch { delayResults.set(id, false); }
    finally { pendingDelay.delete(id); render(); }
  }
  $('egress-node-list').addEventListener('click', event => {
    const delay = event.target.closest('.delay-btn');
    if (delay) { controlDelay(delay.dataset.node); return; }
    const select = event.target.closest('.node-select');
    if (select) controlSelect(select.dataset.node);
  });
  $('channel-kind').addEventListener('change', renderChannels);
  $('channel-add-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!channelManagementEnabled() || pendingChannel) return;
    const kind = $('channel-kind').value;
    const definition = { kind, display_name: $('channel-name').value };
    if (kind === 'subscription') definition.url = $('channel-url').value;
    else {
      definition.server = $('channel-server').value;
      definition.port = Number($('channel-port').value);
      if ($('channel-username').value) definition.username = $('channel-username').value;
      if ($('channel-password').value) definition.password = $('channel-password').value;
    }
    const body = { id: $('channel-id').value, definition };
    pendingChannel = true; text('channel-action-note', '正在保存私有配置…'); renderChannels();
    try {
      await postJSON('/api/channels', body);
      $('channel-add-form').reset();
      text('channel-action-note', '已保存；未刷新、探测、部署或切换。订阅请通过 CLI 显式刷新。');
    } catch (error) { text('channel-action-note', controlErrors[error.message] || '保存失败，请检查输入后重试。'); }
    finally { pendingChannel = false; await refresh(); }
  });
  $('channel-list').addEventListener('submit', async event => {
    const form = event.target.closest('.channel-rename-form');
    if (!form) return;
    event.preventDefault();
    if (!channelManagementEnabled() || pendingChannel) return;
    const body = { id: form.dataset.channel, display_name: form.elements.display_name.value };
    pendingChannel = true; renderChannels();
    try {
      await postJSON('/api/channels/rename', body); renameDrafts.delete(body.id);
      text('channel-action-note', '已重命名；节点 ID、选择和候选保持不变。');
    } catch (error) { text('channel-action-note', controlErrors[error.message] || '重命名失败。'); }
    finally { pendingChannel = false; await refresh(); }
  });
  $('auto-config-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!controlsEnabled() || pendingPolicy) return;
    const primary = $('auto-primary-node').value, secondary = $('auto-secondary-node').value;
    if (!primary || !secondary || primary === secondary) { note('请明确选择两个不同的缓存节点。'); return; }
    pendingPolicy = true; note('正在保存并启用策略…'); render();
    try { await postJSON('/api/auto', { action: 'enable', primary_node: primary, secondary_node: secondary }); note('已启用明确指定的两个候选。'); }
    catch (error) { note(controlErrors[error.message] || '策略保存失败。'); }
    finally { pendingPolicy = false; await refresh(); }
  });
  const autoActions = [
    ['auto-disable', () => ({ action: 'disable' })],
    ['auto-resume', () => ({ action: 'resume' })],
    ['auto-toggle-primary', () => ({ action: 'swap' })]
  ];
  for (const [id, build] of autoActions) {
    $(id).addEventListener('click', async () => {
      if (!controlsEnabled() || pendingPolicy) return;
      pendingPolicy = true; note('正在执行…'); render();
      try { await postJSON('/api/auto', build()); note('已执行。'); }
      catch (error) { note(controlErrors[error.message] || '操作失败。'); }
      finally { pendingPolicy = false; await refresh(); }
    });
  }
  $('refresh').addEventListener('click', refresh);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  text('timezone', `浏览器时区：${Intl.DateTimeFormat().resolvedOptions().timeZone}`);
  render(); refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 5000);
})();
