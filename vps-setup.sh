#!/usr/bin/env bash
# VPS-only installer. All downloads and config validation precede activation.
set -euo pipefail
VER=v1.19.30
BINARY=/usr/local/bin/mihomo
CONFIG_DIR=/etc/mihomo
UNIT=/etc/systemd/system/mihomo.service

wait_ready() {
  local attempt trace
  for attempt in {1..10}; do
    if systemctl is-active --quiet mihomo &&
       trace=$(curl --noproxy '' --proxy "socks5h://$TSIP:1080" \
         --connect-timeout 2 --max-time 5 -fsS https://www.cloudflare.com/cdn-cgi/trace) &&
       grep -qE '^ip=[0-9a-fA-F.:]+$' <<< "$trace"; then
      echo 'PASS SOCKS5 HTTPS 出口响应'
      return 0
    fi
    sleep 1
  done
  echo 'FAIL VPS 代理未就绪；未完成部署。' >&2
  return 1
}

main() (
  local stage was_active=0 was_enabled=0 activated=0
  stage=$(mktemp -d)
  cleanup() {
    local result=$? rollback_failed=0 entry target
    trap - EXIT
    if (( result != 0 && activated )); then
      # Restore only installer-owned artifacts and their prior service state.
      for entry in binary config unit; do
        case $entry in binary) target=$BINARY;; config) target=$CONFIG_DIR/config.yaml;; unit) target=$UNIT;; esac
        if [[ -f $stage/old-$entry ]]; then
          if cp -p "$stage/old-$entry" "$target.restore"; then
            mv -f "$target.restore" "$target" || rollback_failed=1
          else rollback_failed=1; fi
        else
          rm -f "$target" || rollback_failed=1
        fi
      done
      systemctl daemon-reload || rollback_failed=1
      if (( was_enabled )); then systemctl enable mihomo || rollback_failed=1
      else systemctl disable mihomo || rollback_failed=1; fi
      if (( was_active )); then systemctl restart mihomo || rollback_failed=1
      else systemctl stop mihomo || rollback_failed=1; fi
      echo '部署失败；已尝试恢复原文件和服务状态，请检查日志。' >&2
    fi
    if (( rollback_failed )); then
      echo "恢复未完成；原文件备份保留在 $stage，请先恢复后再删除。" >&2
      result=1
    else
      rm -rf -- "$stage"
    fi
    exit "$result"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # Do not replace masked units or follow operator-managed artifact symlinks.
  local target
  for target in "$BINARY" "$CONFIG_DIR/config.yaml" "$UNIT"; do
    if [[ -L $target || ( -e $target && ! -f $target ) ]]; then
      echo "拒绝替换非普通文件: $target" >&2
      exit 1
    fi
  done
  case "$(uname -m)" in
    x86_64) A=amd64 ;;
    aarch64) A=arm64 ;;
    *) echo "不支持的架构: $(uname -m)" >&2; exit 1 ;;
  esac
  LVL=
  if [[ $A == amd64 ]] && grep -qm1 avx2 /proc/cpuinfo; then LVL=-v3; fi
  URL="https://github.com/MetaCubeX/mihomo/releases/download/$VER/mihomo-linux-$A$LVL-$VER.gz"
  curl --connect-timeout 10 --max-time 120 -fsSL -o "$stage/mihomo.gz" "$URL"
  gunzip "$stage/mihomo.gz"
  chmod 755 "$stage/mihomo"
  TSIP=$(tailscale ip -4 | head -1)
  [[ $TSIP =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '无有效 Tailscale IPv4' >&2; exit 1; }
  mkdir "$stage/config"
  cat > "$stage/config/config.yaml" <<EOF
mixed-port: 1080
bind-address: $TSIP
allow-lan: true
ipv6: true
log-level: warning
rules:
  - MATCH,DIRECT
EOF
  "$stage/mihomo" -t -d "$stage/config"
  cat > "$stage/unit" <<EOF
[Unit]
Description=mihomo tailnet proxy egress
After=tailscaled.service network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BINARY -d $CONFIG_DIR
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl is-active --quiet mihomo && was_active=1
  systemctl is-enabled --quiet mihomo && was_enabled=1
  [[ ! -f $BINARY ]] || cp -p "$BINARY" "$stage/old-binary"
  [[ ! -f $CONFIG_DIR/config.yaml ]] || cp -p "$CONFIG_DIR/config.yaml" "$stage/old-config"
  [[ ! -f $UNIT ]] || cp -p "$UNIT" "$stage/old-unit"
  activated=1
  install -d "$(dirname "$BINARY")" "$CONFIG_DIR" "$(dirname "$UNIT")"
  # Rename avoids writing through a running executable (ETXTBSY).
  install -m755 "$stage/mihomo" "$BINARY.new"
  mv -f "$BINARY.new" "$BINARY"
  install -m644 "$stage/config/config.yaml" "$CONFIG_DIR/config.yaml"
  install -m644 "$stage/unit" "$UNIT"
  systemctl daemon-reload
  systemctl enable mihomo
  systemctl restart mihomo
  wait_ready
  activated=0
  echo '== VPS 侧完成 ✓ =='
)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
