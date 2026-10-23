#!/usr/bin/env bash
# Local Ubuntu/systemd manager. Read-only commands never require sudo.
set -euo pipefail
SETUP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG_DIR=/etc/mihomo
SYSTEMD_DIR=/etc/systemd/system/mihomo.service.d
RESOLVED_DIR=/etc/systemd/resolved.conf.d
MIHOMO=/usr/bin/mihomo
NMD_SOURCES_DIR=${NMD_SOURCES_DIR:-/etc/nmd/egress}
# The manager passes the recorded scope across sudo as a path, never credentials.
if [[ ${2:-} == --sources-dir && $# == 3 ]]; then NMD_SOURCES_DIR=$3; fi
source_mode() { [[ -e "$NMD_SOURCES_DIR/sources.json" || -L "$NMD_SOURCES_DIR/sources.json" ]]; }
source_backend() { python3 "$SETUP_DIR/scripts/egress_sources.py" "$@" --sources-dir "$NMD_SOURCES_DIR"; }
VPS_TS_DEFAULT=203.0.113.20
VPS_PORT=1080
# 仓库保持脱敏：203.0.113.10 是 RFC 5737 文档占位端点。真实 VPS 公网出口经
# NMD_LOCAL_ENV（默认 /etc/mihomo/nmd-local.env）的 NMD_VPS_TS_IP / NMD_VPS_PUB
# 注入。仓库里的服务地址同样只是文档占位，不能用来探测或部署。
VPS_PUB_DEFAULT=203.0.113.10
NMD_LOCAL_ENV=${NMD_LOCAL_ENV:-/etc/mihomo/nmd-local.env}
if ! source_mode && [[ -r $NMD_LOCAL_ENV ]]; then
  # This is data, never shell code: do not source an environment-selected file
  # before privilege checks. Only the two literal endpoint assignments are accepted.
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
    if [[ $line =~ ^(NMD_VPS_PUB|NMD_VPS_TS_IP)=[\"\']?([0-9.]+)[\"\']?$ ]]; then
      case ${BASH_REMATCH[1]} in
        NMD_VPS_PUB) NMD_VPS_PUB=${BASH_REMATCH[2]} ;;
        NMD_VPS_TS_IP) NMD_VPS_TS_IP=${BASH_REMATCH[2]} ;;
      esac
    else
      echo '只允许 NMD_VPS_TS_IP=IPv4 / NMD_VPS_PUB=IPv4 的字面赋值；拒绝执行 shell 内容。' >&2
      exit 2
    fi
  done < "$NMD_LOCAL_ENV"
fi
VPS_PUB=${NMD_VPS_PUB:-$VPS_PUB_DEFAULT}
VPS_TS_IP=${NMD_VPS_TS_IP:-$VPS_TS_DEFAULT}

valid_ipv4() {
  local part
  local -a octets
  IFS=. read -ra octets <<< "$1"
  ((${#octets[@]} == 4)) || return 1
  for part in "${octets[@]}"; do
    [[ $part =~ ^[0-9]{1,3}$ ]] && ((10#$part <= 255)) || return 1
  done
}

if ! source_mode; then
  if ! valid_ipv4 "$VPS_PUB" || ! valid_ipv4 "$VPS_TS_IP"; then
    echo 'NMD_VPS_TS_IP / NMD_VPS_PUB 必须是有效 IPv4；输入值已省略。' >&2
    exit 2
  fi
fi

require_legacy_endpoint() {
  source_mode && return 0
  case $VPS_TS_IP in
    192.0.2.*|198.51.100.*|203.0.113.*)
      echo '旧 VPS 地址尚为文档占位；先在私有本机配置中填写 NMD_VPS_TS_IP，未探测或部署。' >&2
      return 2 ;;
  esac
}

usage() {
  cat <<'HELP'
用法: nmd <命令>  (也可用 bash local-setup.sh)
  status       本机服务、Tailscale、路由和 DNS 状态（只读，不做外网探测）
  check        校验当前安装配置，不覆盖运行配置
  verify       检查必要 DNS/路由、国内及当前选择出口；不代表 AI 业务可用
  --sources-dir PATH  管理器传递的已记录 scope 来源目录；直接调用默认 /etc/nmd/egress
  diagnostics  可选设备探测；通过 NMD_TAILNET_HOST / NMD_LAN_HOST 配置目标
  环境变量: NMD_VPS_TS_IP / NMD_VPS_PUB 配置旧 VPS 地址及期望出口（默认读 /etc/mihomo/nmd-local.env）
  logs         查看最近 50 条 mihomo 日志
  start        启动已部署配置，不改开机自启或 Tailscale 偏好
  stop         停止 mihomo、清 DNS 缓存；保留 Tailscale 和直连网络
  restart      校验已部署配置并重启
  enable       开机自启（不立即启动）
  disable      取消开机自启（不立即停止）
  setup        首次安装资产与管理配置；不启动 mihomo
  apply        先校验，再部署配置和 DNS 保护；保持原来的启停状态
  cutover      检查 VPS 后关闭 exit node，应用并启动分流、设为自启
  rollback     停止分流并取消自启，显式恢复 VPS exit node（仍依赖 VPS）
  test-stop    临时停机验证 Tailscale 连通性，结束时恢复原来的启停状态
修改系统的命令自动调用 sudo；verify/test-stop 会发起网络探测。
HELP
}

require_root() {
  if [[ $(id -u) != 0 ]]; then
    # Use the checkout's absolute path; sudo secure_path need not contain ~/.local/bin.
    # exec preserves sudo's failure status and avoids executing the action twice.
    exec sudo -- bash "$SETUP_DIR/local-setup.sh" "$@"
  fi
}

render_config() {
  if source_mode; then
    source_backend render --template "$SETUP_DIR/config.yaml" --output "$1"
    return
  fi
  # $1 = destination. Inject operator-owned endpoints over both doc placeholders.
  local dest=$1
  python3 - "$SETUP_DIR/config.yaml" "$VPS_PUB_DEFAULT" "$VPS_PUB" "$VPS_TS_DEFAULT" "$VPS_TS_IP" > "$dest" <<'PY' || return 1
from pathlib import Path
import re, sys
text = Path(sys.argv[1]).read_text()
public_default, public, server_default, server = sys.argv[2:]
if public != public_default and public_default not in text:
    raise SystemExit('config.yaml 缺少公网出口占位字段；未部署。')
if server != server_default and not re.search(r'(?m)^\s*server:\s*' + re.escape(server_default) + r'\s*$', text):
    raise SystemExit('config.yaml 缺少旧 VPS 服务地址占位字段；未部署。')
for default, value in ((public_default, public), (server_default, server)):
    text = re.sub(r'\b' + re.escape(default) + r'\b', value, text)
print(text, end='')
PY
  chmod 644 "$dest"
}

check_source() (
  local stage
  stage=$(mktemp -d)
  stage=$(cd "$stage" && pwd -P)
  trap 'rm -rf -- "$stage"' EXIT
  # A private data directory prevents validation from changing live geodata.
  install -m644 "$SETUP_DIR/geoip.metadb" "$SETUP_DIR/GeoSite.dat" "$stage/"
  render_config "$stage/config.yaml"
  validate_runtime "$stage"
)

validate_runtime() (
  if source_mode; then
    # Installed config directories can be 0755. Capture only in a fresh 0700
    # directory with a new 0600 file; never follow or truncate a fixed log path.
    umask 077
    validation_stage=$(mktemp -d) || return 1
    trap 'rm -rf -- "$validation_stage"' EXIT
    if ! "$MIHOMO" -t -d "$1" > "$validation_stage/validation.log" 2>&1; then
      echo '来源运行配置校验失败；原始错误已抑制，检查私有节点配置。' >&2
      return 1
    fi
  else
    "$MIHOMO" -t -d "$1"
  fi
)

check_installed() {
  validate_runtime "$CONFIG_DIR"
}

deploy_files() (
  # Call only after check_source succeeds. Keep one inspectable previous config.
  local stage
  stage=$(mktemp -d)
  stage=$(cd "$stage" && pwd -P)
  trap 'rm -rf -- "$stage"' EXIT
  render_config "$stage/config.yaml"
  if source_mode; then
    install -m644 "$SETUP_DIR/geoip.metadb" "$SETUP_DIR/GeoSite.dat" "$stage/"
    # Validate exactly the bytes being deployed even if a CLI edit raced check.
    validate_runtime "$stage"
  fi
  install -d "$CONFIG_DIR" "$SYSTEMD_DIR" "$RESOLVED_DIR"
  if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
    cp -p "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yaml.previous"
  fi
  install -m644 "$SETUP_DIR/geoip.metadb" "$SETUP_DIR/GeoSite.dat" "$CONFIG_DIR/"
  if source_mode; then
    install -d -m700 "$CONFIG_DIR/providers"
    install -m600 "$stage"/providers/*.json "$CONFIG_DIR/providers/"
    install -m600 "$stage/config.yaml" "$CONFIG_DIR/config.yaml.new"
  else
    install -m644 "$stage/config.yaml" "$CONFIG_DIR/config.yaml.new"
  fi
  mv -f "$CONFIG_DIR/config.yaml.new" "$CONFIG_DIR/config.yaml"
  install -m644 "$SETUP_DIR/systemd/mihomo-override.conf" "$SYSTEMD_DIR/10-tailscale.conf"
  install -m644 "$SETUP_DIR/systemd/mihomo-tailscale.conf" "$RESOLVED_DIR/mihomo-tailscale.conf"
  # Retire the old installer-owned global search domain. With global public DNS
  # it could leak tailnet lookups; tailscaled now owns the per-link search domain.
  if [[ -f "$RESOLVED_DIR/tailnet-search.conf" ]]; then
    mv -f "$RESOLVED_DIR/tailnet-search.conf" "$RESOLVED_DIR/tailnet-search.conf.previous"
  fi
  systemctl daemon-reload
)

activate_dns() {
  systemctl restart systemd-resolved
  # Let tailscaled own MagicDNS even while mihomo is stopped. No logout/reset.
  tailscale set --accept-dns=true
  resolvectl flush-caches
}

ensure_no_exit_node() {
  # A selected exit node would retain a VPS dependency after stopping mihomo.
  tailscale debug prefs | python3 -c '
import json,sys
p=json.load(sys.stdin)
if p.get("ExitNodeID") or p.get("ExitNodeIP"):
    sys.exit("已选择 Tailscale exit node；请用 cutover 显式迁移后再启动分流。")'
}

wait_running() {
  local attempt state
  for attempt in {1..20}; do
    state=$(systemctl show mihomo -p SubState --value)
    if [[ $state == running ]] && ip link show mihomo >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "mihomo 未就绪；查看 nmd logs。" >&2
  return 1
}

start_service() {
  ensure_no_exit_node
  check_installed
  systemctl start mihomo
  wait_running
}

stop_service() {
  systemctl stop mihomo
  resolvectl flush-caches
  if systemctl is-active --quiet mihomo || ip link show mihomo >/dev/null 2>&1; then
    echo "停止失败或 mihomo TUN 仍存在；未更改 Tailscale。" >&2
    return 1
  fi
  echo "mihomo 已停止；Tailscale 配置保持不变。"
}

apply_config() {
  # A failed initial deploy must not become a successful stopped apply.
  if [[ -f "$CONFIG_DIR/.initial-deploy-pending" ]]; then
    deploy_initial
    return
  fi
  local was_active=0
  check_source
  ensure_no_exit_node
  systemctl is-active --quiet mihomo && was_active=1
  deploy_files
  activate_dns
  if (( was_active )); then
    systemctl restart mihomo
    wait_running
  fi
  echo "配置已部署；原运行状态=$was_active（1=运行，0=停止）。"
}

status() {
  local failed=0
  echo '== mihomo =='
  systemctl show mihomo -p LoadState -p ActiveState -p SubState -p Result -p UnitFileState
  ip -br addr show mihomo 2>/dev/null || echo '(无 mihomo TUN)'
  echo '== Tailscale =='
  if ! tailscale status --json | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("state:",d.get("BackendState"),"online:",d.get("Self",{}).get("Online"))
print("health:",d.get("Health") or [])
sys.exit(0 if d.get("BackendState")=="Running" and d.get("Self",{}).get("Online") else 1)'; then
    failed=1
  fi
  tailscale debug prefs | python3 -c '
import json,sys
p=json.load(sys.stdin)
print("accept-dns:",p.get("CorpDNS"),"exit-node:",p.get("ExitNodeIP") or p.get("ExitNodeID") or "none")' || failed=1
  echo '== 路由 =='
  ip rule show
  if source_mode; then
    ip route get 100.100.100.100 || failed=1
  else
    case $VPS_TS_IP in
      192.0.2.*|198.51.100.*|203.0.113.*) echo 'SKIP 旧 VPS 目标路由：尚未配置 NMD_VPS_TS_IP。' ;;
      *) ip route get "$VPS_TS_IP" || failed=1 ;;
    esac
  fi
  ip route get 192.200.0.104 mark 0x80000 || failed=1
  echo '== DNS =='
  resolvectl status || failed=1
  return "$failed"
}

probe() {
  local name=$1
  shift
  if "$@"; then echo "PASS $name"; else echo "FAIL $name" >&2; return 1; fi
}

peer_probe() {
  # $1 = operator-configured tailnet IP. A pong can arrive through DERP even
  # when tailscale ping returns nonzero; report the observed path, not a direct-link promise.
  local pong
  pong=$(timeout 10 tailscale ping --c=1 --timeout=5s "$1" 2>&1) || true
  if [[ $pong != 'pong from '* ]]; then
    echo "FAIL 尾网对端: ${pong:-无响应}" >&2
    return 1
  fi
  if [[ $pong == *' via DERP('* ]]; then
    echo 'PASS 尾网对端（经 DERP 中继，无直连——已知降级）'
  else
    echo 'PASS 尾网对端（直连）'
  fi
}

tailscale_checks() {
  local failed=0 route destination
  ensure_no_exit_node || failed=1
  probe 'Tailscale 域名返回真实 IP' timeout 20 python3 "$SETUP_DIR/scripts/check-tailscale-dns.py" || failed=1
  probe 'Tailscale 登录 HTTPS' curl --noproxy '*' --connect-timeout 4 --max-time 10 \
    -fsS -o /dev/null https://login.tailscale.com/ || failed=1
  probe 'Tailscale 控制服务 HTTPS' curl --noproxy '*' --connect-timeout 4 --max-time 10 \
    -fsS -o /dev/null https://controlplane.tailscale.com/derpmap/default || failed=1
  if source_mode; then
    echo 'SKIP 固定旧 VPS 对端检查：多来源出口由当前 selector 与 HTTPS 验收。'
  else
    peer_probe "$VPS_TS_IP" || failed=1
  fi
  route=$(ip route get 192.200.0.104 mark 0x80000) || return 1
  if [[ $route != *' dev '* || $route == *' dev mihomo '* || $route == *' dev tailscale0 '* ]]; then
    echo "FAIL Tailscale 标记流量未直连: $route" >&2
    failed=1
  else
    echo 'PASS Tailscale 标记流量绕过两层隧道'
  fi
  # These paths must also work when mihomo is alive but no longer responding.
  for destination in 223.5.5.5 119.29.29.29 192.200.0.104; do
    if ! route=$(ip route get "$destination" ipproto udp dport 53); then
      failed=1
    elif [[ $route != *' dev '* || $route == *' dev mihomo '* || $route == *' dev tailscale0 '* ]]; then
      echo "FAIL bootstrap 路由依赖隧道: $route" >&2
      failed=1
    else
      echo "PASS bootstrap 直连路由: $destination"
    fi
  done
  return "$failed"
}

verify() {
  local failed=0 egress baidu fip attempt before
  if [[ ${1:-} == running ]] && ! systemctl is-active --quiet mihomo; then
    echo "FAIL 首次部署必须运行 mihomo" >&2
    return 1
  fi
  require_legacy_endpoint || return $?
  tailscale_checks || failed=1
  baidu=$(curl --noproxy '*' --connect-timeout 4 --max-time 10 \
    -sS -o /dev/null -w '%{http_code}' https://www.baidu.com/) || failed=1
  if [[ $baidu == 200 ]]; then
    echo 'PASS 国内 HTTPS 200'
  else
    echo "FAIL 国内 HTTPS: ${baidu:-不可达}" >&2
    failed=1
  fi
  if systemctl is-active --quiet mihomo; then
    if source_mode; then
      before=$(source_backend current) || return 1
    fi
    # 刚重启后 VPS 拨号有短暂预热期（context deadline exceeded）；有界重试只容忍
    # 该瞬态，接受标准不变：curl 成功但出口不符时不重试，直接判 FAIL。
    for attempt in 1 2 3; do
      if egress=$(curl --noproxy '*' --connect-timeout 4 --max-time 15 -fsS \
        https://www.cloudflare.com/cdn-cgi/trace | sed -n 's/^ip=//p'); then
        break
      fi
      egress=
      if (( attempt < 3 )); then sleep 2; fi
    done
    [[ -n $egress ]] || failed=1
    if source_mode; then
      source_backend verify --before "$before" --observed "$egress" || failed=1
    elif [[ $egress == "$VPS_PUB" ]]; then
      echo "PASS VPS 出口 $egress"
    else
      echo "FAIL VPS 出口: ${egress:-不可达}，期望 $VPS_PUB" >&2
      if [[ $VPS_PUB == "$VPS_PUB_DEFAULT" ]]; then
        echo "提示: 期望值仍为文档占位符；配置 NMD_VPS_PUB=<真实公网出口> 到 $NMD_LOCAL_ENV 后重试。" >&2
      fi
      failed=1
    fi
    fip=$(timeout 5 getent ahostsv4 www.google.com | awk 'NR == 1 {print $1}') || failed=1
    if [[ $fip == 198.18.* ]]; then
      echo 'PASS 普通海外域名 fake-ip 生效'
    else
      echo "FAIL 普通海外域名 fake-ip: ${fip:-无结果}" >&2
      failed=1
    fi
  else
    if [[ ${1:-} == running ]]; then
      echo 'FAIL 验证期间 mihomo 已停止' >&2
      failed=1
    else
      echo 'SKIP VPS 出口和普通域名 fake-ip：mihomo 未运行'
    fi
  fi
  if [[ ${1:-} == running ]] && ! systemctl is-active --quiet mihomo; then
    echo 'FAIL 验证结束时 mihomo 未运行' >&2
    failed=1
  fi
  return "$failed"
}

# Keep the receipt until readiness, enablement AND verification succeed. A
# pre-existing stopped installation without this receipt remains deliberately stopped.
deploy_initial() {
  ensure_no_exit_node
  # dpkg can create config.yaml before failing; record intent before that write.
  install -d "$CONFIG_DIR"
  touch "$CONFIG_DIR/.initial-deploy-pending"
  if [[ ! -x "$MIHOMO" ]]; then dpkg -i "$SETUP_DIR/mihomo.deb"; fi
  check_source
  deploy_files
  activate_dns
  if systemctl is-active --quiet mihomo; then
    systemctl restart mihomo
    wait_running
  else
    start_service
  fi
  systemctl enable mihomo
  verify running
  rm -f "$CONFIG_DIR/.initial-deploy-pending"
}

diagnostics() {
  local failed=0
  if [[ -n ${NMD_TAILNET_HOST:-} ]]; then
    probe '可选 tailnet DNS' timeout 5 getent ahostsv4 "$NMD_TAILNET_HOST" || failed=1
    probe '可选 tailnet 设备' ping -c1 -W3 "$NMD_TAILNET_HOST" || failed=1
  fi
  if [[ -n ${NMD_LAN_HOST:-} ]]; then
    probe '可选局域网设备' ping -c1 -W3 "$NMD_LAN_HOST" || failed=1
  fi
  if [[ -z ${NMD_TAILNET_HOST:-}${NMD_LAN_HOST:-} ]]; then
    echo '未配置可选探测目标；设置 NMD_TAILNET_HOST / NMD_LAN_HOST。'
  fi
  return "$failed"
}

test_stop() (
  local was_active=0
  ensure_no_exit_node
  systemctl is-active --quiet mihomo && was_active=1
  # Restore even when a probe fails or the operator interrupts the test.
  restore() {
    local result=$?
    trap - EXIT
    if (( was_active )); then
      if ! systemctl start mihomo || ! wait_running; then
        echo 'FAIL 停机演练后恢复 mihomo 失败' >&2
        result=1
      fi
    fi
    exit "$result"
  }
  trap restore EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  stop_service
  tailscale_checks
)

main() {
  local cmd=${1:-help}
  if (( $# > 1 )); then
    if [[ $# != 3 || $2 != --sources-dir || $3 != /* ]]; then usage >&2; return 2; fi
    NMD_SOURCES_DIR=$3
  fi
  if source_mode && [[ $cmd == cutover || $cmd == rollback ]]; then
    echo '多来源模式不推断 exit node 回退；请查看 nmd source status，显式选择来源。旧 VPS cutover/rollback 仅适用于旧配置。' >&2
    return 2
  fi
  case $cmd in
    verify|setup|apply|deploy|cutover|rollback|test-stop)
      require_legacy_endpoint || return $? ;;
  esac
  case $cmd in
    help|-h|--help) usage; return ;;
    status) status; return ;;
    check) check_source; return ;;
    verify) verify; return ;;
    diagnostics) diagnostics; return ;;
    logs)
      if source_mode; then
        echo '来源模式不导出可能含节点凭据的核心原始日志；请用 nmd source status 查看脱敏状态。'
      else
        journalctl -u mihomo -n 50 --no-pager
      fi
      return ;;
    start|stop|restart|enable|disable|setup|apply|deploy|cutover|rollback|test-stop) ;;
    *) echo "未知命令: $cmd" >&2; usage >&2; return 2 ;;
  esac
  if (( $# > 1 )); then require_root "$cmd" --sources-dir "$NMD_SOURCES_DIR"; else require_root "$cmd"; fi
  case $cmd in
    start) start_service ;;
    stop) stop_service ;;
    restart)
      ensure_no_exit_node
      check_installed
      systemctl restart mihomo
      wait_running
      ;;
    enable|disable) systemctl "$cmd" mihomo ;;
    setup)
      # Existing installations use apply; avoid silently replacing live settings.
      if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
        echo '已有安装；请用 apply 更新配置。' >&2
        return 1
      fi
      if [[ ! -x "$MIHOMO" ]]; then dpkg -i "$SETUP_DIR/mihomo.deb"; fi
      check_source
      deploy_files
      activate_dns
      echo '安装完成；使用 cutover 检查 VPS 并启动分流。'
      ;;
    apply) apply_config ;;
    deploy)
      ensure_no_exit_node
      if [[ -f "$CONFIG_DIR/config.yaml" && ! -f "$CONFIG_DIR/.initial-deploy-pending" ]]; then
        apply_config
      else
        deploy_initial
      fi
      ;;
    cutover)
      check_source
      curl --noproxy '' --proxy "socks5h://$VPS_TS_IP:$VPS_PORT" \
        --connect-timeout 4 --max-time 15 -fsS \
        https://www.cloudflare.com/cdn-cgi/trace | grep -q "^ip=${VPS_PUB//./\\.}$"
      tailscale set --exit-node= --accept-dns=true
      apply_config
      start_service
      systemctl enable mihomo
      verify
      ;;
    rollback)
      stop_service
      systemctl disable mihomo
      tailscale set --accept-dns=true --exit-node="$VPS_TS_IP"
      echo '已选择 VPS exit node；此模式仍依赖 VPS，不属于故障直连。'
      ;;
    test-stop) test_stop ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi

