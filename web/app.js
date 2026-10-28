/* Local viewer with explicit egress controls and save-only private Channel configuration. */
'use strict';
(() => {
  let busy = false, snapshot = null, failure = null, sources = null, pendingSelect = false, capabilities = null;
  const delayResults = new Map(), pendingDelay = new Set(), renameDrafts = new Map(), pendingRefresh = new Set();
  let pendingChannel = false, pendingPolicy = false, candidateDrafts = null, diagnoseReport = null, pendingDiagnose = false;
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
  async function postJSON(path, body, timeoutMs = 8000) {
    if (!controlsEnabled()) throw new Error('read_only');
    const abort = new AbortController(), timeout = setTimeout(() => abort.abort(), timeoutMs);
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
    auto_not_configured: '自动切换尚未配置。', auto_legacy_payload_removed: '旧版主备参数已移除；请使用候选列表配置或更新候选。',
    invalid_channel_name: '显示名称须为 1–128 个字符，不能含控制字符。', source_already_exists: '通道 ID 已存在，请使用另一个 ID。',
    invalid_source_id: '通道 ID 需以小写字母开头，只含小写字母、数字和短横线，最长 32 字符。',
    subscription_requires_https_url: '订阅需使用 HTTPS 443 URL，不能含用户名、密码或片段。',
    proxy_requires_literal_non_tailnet_ip: '普通路径代理需使用非 Tailnet 的 IP 地址。', tailnet_requires_literal_tailnet_ip: 'Tailnet 通道需使用 Tailnet IP 地址。',
    invalid_proxy_port: '端口须为 1–65535。', auto_candidates_must_differ: '候选节点必须互不相同。', auto_node_not_in_inventory: '请按优先级选择 2–8 个有效缓存节点。',
    auto_invalid_parameters: '参数无效。', auto_invalid_action: '操作无效。', sources_unavailable: '私有来源数据不可用。',
    subscription_source_not_found: '未找到该订阅通道；只有订阅通道可以刷新。',
    subscription_fetch_failed: '订阅下载失败；已保留原有节点缓存，可稍后重试。',
    subscription_timeout: '订阅下载超时；已保留原有节点缓存，可稍后重试。',
    subscription_http_error_no_redirects: '订阅服务器返回错误（不跟随重定向）；已保留原有节点缓存。',
    subscription_too_large: '订阅内容超出大小上限；已保留原有节点缓存。',
    provider_requires_proxies_mapping: '订阅内容缺少有效的 proxies 节点列表。',
    provider_requires_1_to_256_nodes: '订阅节点数量须在 1–256 之间。',
    invalid_provider_yaml: '订阅内容不是有效的 YAML。', invalid_yaml_keys: '订阅 YAML 含重复或非字符串键。',
    unsupported_yaml_alias_or_tag: '订阅 YAML 含不支持的别名或标签。',
    duplicate_proxy_name: '订阅内存在重复的节点名称。', invalid_or_unsupported_proxy_node: '订阅包含无效或不支持的节点。',
    selected_node_would_disappear_choose_another_first: '当前选中节点会随刷新消失；请先切换到其他节点再刷新。',
    yaml_dependency_missing_PyYAML_6_0_3: '缺少 PyYAML 6.0.3 依赖，无法解析订阅。'
  };
  const autoEventNames = {
    auto_engaged: '自动接管', auto_switch: '自动切换', auto_switch_failed: '切换失败', auto_verify_adopted: '切换确认',
    auto_suspended: '自动挂起', auto_resumed: '自动恢复', manual_engage: '手动选择候选',
    candidate_changed: '候选变化', controller_unreachable: '控制器不可达',
    all_unhealthy: '全部候选不健康', auto_error: '评估异常'
  };
  const runtimeStateNames = {
    paused: '已暂停', suspended: '候选缺失 · 评估挂起', pending_verify: '切换待确认',
    all_unhealthy: '全部候选不健康 · 保持当前出口', engaging: '等待首次接管',
    active: '当前候选健康', failing: '当前候选失败计数中', recovering: '高优先候选恢复计数中'
  };
  const diagnoseProbeNames = {
    direct_foreign: '本机直连外网', egress_cn: '国内直连',
    egress_foreign: '经节点访问外网', egress_exit_ip: '经节点出口 IP（免 DNS）'
  };
  const diagnoseHealthNames = { ok: '健康', fail: '失败', controller_unreachable: '控制器故障', skipped: '未探测' };
  const diagnoseTcpNames = { ok: 'TCP 可达', refused: 'TCP 拒绝', timeout: 'TCP 超时', unreachable: 'TCP 不可达', skipped: '跳过' };
  const diagnoseHints = {
    egress_healthy: '各层探测均正常，出口链路健康。',
    local_internet_down: '本机直连外网失败：先排查本地网络与路由，与出口节点无关。',
    node_service_down: '候选全部失测且节点主机拒绝连接：节点服务疑似停机，可切换其他候选。',
    node_network_unreachable: '候选节点 TCP 连接超时或不可达：到节点的网络路径不通或被丢弃。',
    exit_dns_poisoned: '出口 IP 可达但域名访问失败：疑似出口侧 DNS 污染，可对照诊断手册 3.3 处理。',
    egress_degraded: '链路可用但经节点耗时超过 3 秒：中继路径劣化，可考虑切换候选。',
    controller_unreachable: '本地控制器探测故障：不能据此判定节点失效，请检查核心与控制器。',
    egress_anomaly: '失败组合未命中固定结论：请按诊断手册 3.3 人工排查。'
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
        form.append(label, button);
        // Subscription channels can be refreshed in place; one explicit HTTPS
        // fetch per click, never automatic, never for manual proxy channels.
        if (channel.kind === 'subscription') {
          const refreshing = pendingRefresh.has(channel.id);
          const refresh = make('button', refreshing ? '更新中…' : '更新订阅');
          refresh.type = 'button'; refresh.dataset.refresh = channel.id;
          refresh.disabled = refreshing || pendingChannel;
          form.append(refresh);
        }
        item.append(form);
      }
      $('channel-list').append(item);
    }
  }
  function fillCandidateSelect(select, nodes, preferred) {
    select.replaceChildren(make('option', '请选择节点'));
    select.firstElementChild.value = '';
    for (const node of nodes) {
      const channel = sources?.sources?.find(row => row.id === node.source);
      const option = make('option', `${channel ? channelLabel(channel) : node.source} · ${node.display || node.id}`);
      option.value = node.id; select.append(option);
    }
    select.value = nodes.some(node => node.id === preferred) ? preferred : '';
    select.disabled = !controlsEnabled() || pendingPolicy;
  }
  function renderCandidateRows(nodes, auto) {
    const box = $('auto-candidate-rows');
    // Preserve an open dropdown across read-only polling refreshes; row
    // buttons may rebuild immediately after moving or removing a candidate.
    const editing = box.contains(document.activeElement) && document.activeElement.matches('select');
    if (pendingPolicy || editing || sources === null) return;  // Never seed drafts before the policy data arrives.
    if (candidateDrafts === null) {
      candidateDrafts = Array.isArray(auto?.candidates) ? auto.candidates.map(pin => pin.node).filter(Boolean) : [];
      while (candidateDrafts.length < 2) candidateDrafts.push('');
    }
    box.replaceChildren();
    candidateDrafts.forEach((id, index) => {
      const row = make('div', undefined, 'candidate-row');
      const label = make('label', `候选 ${index + 1}`);
      const select = make('select');
      select.dataset.rank = index;
      fillCandidateSelect(select, nodes, id);
      label.append(select);
      const up = make('button', '↑', 'candidate-move');
      up.type = 'button'; up.dataset.move = 'up'; up.dataset.rank = index;
      up.disabled = index === 0 || !controlsEnabled() || pendingPolicy;
      const down = make('button', '↓', 'candidate-move');
      down.type = 'button'; down.dataset.move = 'down'; down.dataset.rank = index;
      down.disabled = index === candidateDrafts.length - 1 || !controlsEnabled() || pendingPolicy;
      const remove = make('button', '✕', 'candidate-remove');
      remove.type = 'button'; remove.dataset.rank = index;
      remove.disabled = candidateDrafts.length <= 2 || !controlsEnabled() || pendingPolicy;
      row.append(label, up, down, remove);
      box.append(row);
    });
    $('auto-add-candidate').disabled = !controlsEnabled() || pendingPolicy || candidateDrafts.length >= 8;
  }
  function renderDiagnose() {
    const canControl = controlsEnabled();
    $('diagnose-run').disabled = !canControl || pendingDiagnose;
    $('diagnose-run').textContent = pendingDiagnose ? '排查中…' : '一键排查';
    const box = $('diagnose-results');
    box.replaceChildren();
    if (!canControl) {
      box.append(empty('仅 Linux 出口控制环境可用一键排查。'));
      return;
    }
    if (!diagnoseReport) return;
    for (const [key, label] of Object.entries(diagnoseProbeNames)) {
      const probe = diagnoseReport.probes?.[key];
      if (!probe) continue;
      const row = make('div', undefined, 'diagnose-row');
      row.append(make('span', label),
        badge(probe.status === 'ok' ? 'success' : 'failure', probe.status === 'ok' ? '成功' : `失败（${probe.error || '未知'}）`),
        make('span', finite(probe.total_ms) ? `${probe.total_ms} ms` : '—', 'diagnose-ms'));
      box.append(row);
    }
    for (const candidate of (Array.isArray(diagnoseReport.candidates) ? diagnoseReport.candidates : [])) {
      const node = (sources?.nodes || []).find(item => item.id === candidate.node);
      const health = candidate.health === 'ok' && finite(candidate.delay_ms)
        ? `健康 ${candidate.delay_ms} ms` : diagnoseHealthNames[candidate.health] || '未知';
      const tcp = candidate.tcp === 'skipped' ? 'TCP 跳过（非 Tailnet 路径）' : diagnoseTcpNames[candidate.tcp] || '—';
      const row = make('div', undefined, 'diagnose-row');
      row.append(make('span', `候选 · ${node?.display || candidate.node}`),
        badge(candidate.health === 'ok' ? 'success' : candidate.health === 'fail' ? 'failure' : 'unknown', health),
        make('span', tcp, 'diagnose-ms'));
      box.append(row);
    }
    const code = diagnoseReport.verdict?.code;
    box.append(make('p', `结论：${diagnoseHints[code] || '结论未知，请按诊断手册 3.3 人工排查。'}`,
      'diagnose-verdict ' + (code === 'egress_healthy' ? 'ok' : 'fail')));
  }
  async function runDiagnose() {
    if (!controlsEnabled() || pendingDiagnose) return;
    pendingDiagnose = true; note('正在分层探测（最长约 15 秒）…'); render();
    try {
      const data = await postJSON('/api/egress/diagnose', {}, 30000);
      if (data?.schema_version !== 1 || !data.verdict?.code || !data.probes) throw new Error('invalid_response');
      diagnoseReport = data; note('');
    } catch (error) {
      diagnoseReport = null;
      note(controlErrors[error.message] || '一键排查失败，请稍后重试。');
    } finally { pendingDiagnose = false; render(); }
  }
  $('diagnose-run').addEventListener('click', runDiagnose);
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
    const candidates = Array.isArray(auto?.candidates) ? auto.candidates : [];
    const targetName = Number.isInteger(runtime?.target) ? ` · 当前目标：候选 ${runtime.target + 1}` : '';
    const runtimeDetail = runtimeStateNames[runtime?.state] ? ` · ${runtimeStateNames[runtime.state]}` : '';
    const cooldownLeft = finite(runtime?.cooldown_remaining) && runtime.cooldown_remaining > 0
      ? ` · 切换冷却剩 ${runtime.cooldown_remaining} 周期` : '';
    const activeChannel = sources?.sources?.find(channel => nodes.some(node => node.id === sources.active && node.source === channel.id));
    text('egress-current-name', sources?.controller === 'observed' && sources?.active ? `${activeChannel ? channelLabel(activeChannel) + ' · ' : ''}${displayOf(sources.active)}` : '未知');
    text('egress-current-id', sources?.active || '—');
    text('egress-current-mode', auto
      ? (auto.paused ? '自动 · 已暂停（手动接管）'
        : auto.enabled ? `自动 · ${candidates.length} 个候选 · 首选 ${displayOf(candidates[0]?.node)}${targetName}` : '手动 · 自动已停用')
      : '手动选择');
    renderDiagnose();
    $('egress-node-list').replaceChildren();
    if (!canControl && !nodes.length) $('egress-node-list').append(empty('此环境仅提供只读诊断，不读取出口来源或启用控制。'));
    else if (!nodes.length && sources) $('egress-node-list').append(empty('暂无缓存节点；请在通道列表点击「更新订阅」，或使用 nmd source refresh。'));
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
    const candidatesText = candidates.length
      ? candidates.map((pin, index) => `候选${index + 1} ${displayOf(pin.node)}${runtime?.target === index ? ' ●当前' : ''}`).join(' · ')
      : '';
    text('auto-state', !sources ? '通道数据不可用。' : !auto ? '自动切换未启用。'
      : auto.paused ? '已暂停：手动选择优先；明确恢复后才继续评估原有候选。'
      : auto.enabled ? `运行中 · ${candidatesText}${runtimeDetail}${cooldownLeft}` : '已停用。');
    text('auto-policy', auto ? `连续失败 ${auto.fail_after} 次切到下一健康候选 · 更高优先候选连续成功 ${auto.recover_after} 次回切 · 切换后冷却 ${auto.cooldown} 周期` : '');
    renderCandidateRows(nodes, auto);
    text('auto-enable', auto?.enabled ? '更新候选列表' : '保存并启用候选');
    $('auto-enable').disabled = !canControl || pendingPolicy;
    $('auto-disable').disabled = !canControl || !auto?.enabled || pendingPolicy;
    $('auto-resume').disabled = !canControl || !auto?.enabled || !auto?.paused || pendingPolicy;
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
      text('channel-action-note', '已保存；未刷新、探测、部署或切换。订阅可在通道行点击「更新订阅」显式刷新。');
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
  async function controlRefresh(id) {
    // Per-channel pending state: a double click cannot start two fetches.
    if (!channelManagementEnabled() || pendingChannel || pendingRefresh.has(id)) return;
    pendingRefresh.add(id); text('channel-action-note', '正在更新订阅…'); renderChannels();
    try {
      await postJSON('/api/channels/refresh', { id }, 30000);
      text('channel-action-note', '已更新订阅并重写节点缓存；列表稍后自动刷新，部署仍需 nmd apply。');
    } catch (error) { text('channel-action-note', controlErrors[error.message] || '更新订阅失败。'); }
    finally { pendingRefresh.delete(id); await refresh(); }
  }
  $('channel-list').addEventListener('click', event => {
    const refresh = event.target.closest('button[data-refresh]');
    if (refresh) controlRefresh(refresh.dataset.refresh);
  });
  $('auto-candidate-rows').addEventListener('change', event => {
    const select = event.target.closest('select[data-rank]');
    if (!select || candidateDrafts === null) return;
    candidateDrafts[Number(select.dataset.rank)] = select.value;
  });
  $('auto-candidate-rows').addEventListener('click', event => {
    const move = event.target.closest('.candidate-move');
    const remove = event.target.closest('.candidate-remove');
    if (!move && !remove) return;
    if (!controlsEnabled() || pendingPolicy || candidateDrafts === null) return;
    if (move) {
      const rank = Number(move.dataset.rank), other = rank + (move.dataset.move === 'up' ? -1 : 1);
      if (other < 0 || other >= candidateDrafts.length) return;
      [candidateDrafts[rank], candidateDrafts[other]] = [candidateDrafts[other], candidateDrafts[rank]];
    } else if (candidateDrafts.length > 2) {
      candidateDrafts.splice(Number(remove.dataset.rank), 1);
    }
    render();
  });
  $('auto-add-candidate').addEventListener('click', () => {
    if (!controlsEnabled() || pendingPolicy || candidateDrafts === null || candidateDrafts.length >= 8) return;
    candidateDrafts.push('');
    render();
  });
  $('auto-config-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!controlsEnabled() || pendingPolicy || candidateDrafts === null) return;
    const picked = candidateDrafts.filter(Boolean);
    if (picked.length !== candidateDrafts.length || picked.length < 2 || picked.length > 8
        || new Set(picked).size !== picked.length) {
      note('请按优先级选择 2–8 个互不相同的缓存节点。'); return;
    }
    const updating = Boolean(sources?.auto?.enabled);
    const action = updating ? 'set-candidates' : 'enable';
    pendingPolicy = true; note(updating ? '正在更新候选列表…' : '正在保存并启用策略…'); render();
    try {
      await postJSON('/api/auto', { action, nodes: picked });
      note(updating ? '已更新候选列表；下一周期起按新优先级评估。' : '已启用明确指定的候选列表。');
    } catch (error) { note(controlErrors[error.message] || '策略保存失败。'); }
    finally { pendingPolicy = false; candidateDrafts = null; await refresh(); }
  });
  const autoActions = [
    ['auto-disable', () => ({ action: 'disable' })],
    ['auto-resume', () => ({ action: 'resume' })]
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
