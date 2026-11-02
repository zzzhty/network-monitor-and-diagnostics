#!/usr/bin/env bash
# VPS-only installer. All downloads and config validation precede activation.
set -euo pipefail
VER=v1.19.30
BINARY=/usr/local/bin/mihomo
CONFIG_DIR=/etc/mihomo
UNIT=/etc/systemd/system/mihomo.service
WATCHDOG_SCRIPT=/usr/local/bin/nmd-vps-watchdog
WATCHDOG_SERVICE=/etc/systemd/system/nmd-vps-watchdog.service
WATCHDOG_TIMER=/etc/systemd/system/nmd-vps-watchdog.timer
WATCHDOG_STATE=/var/lib/nmd-vps-watchdog

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
  local stage was_active=0 was_enabled=0 was_watchdog=0 activated=0
  stage=$(mktemp -d)
  cleanup() {
    local result=$? rollback_failed=0 entry target
    trap - EXIT
    if (( result != 0 && activated )); then
      # Restore only installer-owned artifacts and their prior service state.
      for entry in binary config unit watchdog watchdog-service watchdog-timer; do
        case $entry in
          binary) target=$BINARY;; config) target=$CONFIG_DIR/config.yaml;; unit) target=$UNIT;;
          watchdog) target=$WATCHDOG_SCRIPT;; watchdog-service) target=$WATCHDOG_SERVICE;; watchdog-timer) target=$WATCHDOG_TIMER;;
        esac
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
      if (( was_watchdog )); then systemctl enable nmd-vps-watchdog.timer && systemctl restart nmd-vps-watchdog.timer || rollback_failed=1
      else systemctl disable --now nmd-vps-watchdog.timer || rollback_failed=1; fi
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
  for target in "$BINARY" "$CONFIG_DIR/config.yaml" "$UNIT" "$WATCHDOG_SCRIPT" "$WATCHDOG_SERVICE" "$WATCHDOG_TIMER"; do
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
  # mihomo intermittently stalls without exiting (observed 2026-11-01: 62
  # minutes unresponsive, zero log lines, Restart=always useless). A local
  # watchdog restarts it after consecutive failed egress checks; the direct
  # control fetch keeps a VPS-side internet outage from counting as a stall.
  cat > "$stage/watchdog" <<EOF
#!/usr/bin/env bash
# Restart mihomo when its SOCKS5 egress stops answering while the process
# keeps running. Strikes reset on the first success; direct-egress failure
# skips the round entirely (not a mihomo fault).
set -euo pipefail
TSIP=\$(tailscale ip -4 | head -1)
URL=https://www.gstatic.com/generate_204
STATE=$WATCHDOG_STATE
STRIKES=3
mkdir -p "\$STATE"
log() { echo "\$(date -u +%FT%TZ) \$*" >>"\$STATE/last-check"; }
curl --noproxy '' --connect-timeout 3 --max-time 8 -fsS -o /dev/null "\$URL" || { log 'skip: direct egress down'; exit 0; }
if curl --noproxy '' --proxy "socks5h://\$TSIP:1080" --connect-timeout 3 --max-time 8 -fsS -o /dev/null "\$URL"; then
  log ok; rm -f "\$STATE/strikes"; exit 0
fi
n=\$(( \$(cat "\$STATE/strikes" 2>/dev/null || echo 0) + 1 ))
echo "\$n" >"\$STATE/strikes"
log "fail strike \$n/\$STRIKES"
if (( n >= STRIKES )); then
  echo "\$(date -u +%FT%TZ) restarting mihomo after \$n strikes" | systemd-cat -t nmd-vps-watchdog -p warning
  rm -f "\$STATE/strikes"
  systemctl restart mihomo
fi
EOF
  cat > "$stage/watchdog-service" <<EOF
[Unit]
Description=NMD VPS mihomo stall watchdog
After=mihomo.service

[Service]
Type=oneshot
ExecStart=$WATCHDOG_SCRIPT
EOF
  cat > "$stage/watchdog-timer" <<EOF
[Unit]
Description=Run the NMD VPS mihomo stall watchdog every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF
  systemctl is-active --quiet mihomo && was_active=1
  systemctl is-enabled --quiet mihomo && was_enabled=1
  systemctl is-enabled --quiet nmd-vps-watchdog.timer && was_watchdog=1
  [[ ! -f $BINARY ]] || cp -p "$BINARY" "$stage/old-binary"
  [[ ! -f $CONFIG_DIR/config.yaml ]] || cp -p "$CONFIG_DIR/config.yaml" "$stage/old-config"
  [[ ! -f $UNIT ]] || cp -p "$UNIT" "$stage/old-unit"
  [[ ! -f $WATCHDOG_SCRIPT ]] || cp -p "$WATCHDOG_SCRIPT" "$stage/old-watchdog"
  [[ ! -f $WATCHDOG_SERVICE ]] || cp -p "$WATCHDOG_SERVICE" "$stage/old-watchdog-service"
  [[ ! -f $WATCHDOG_TIMER ]] || cp -p "$WATCHDOG_TIMER" "$stage/old-watchdog-timer"
  activated=1
  install -d "$(dirname "$BINARY")" "$CONFIG_DIR" "$(dirname "$UNIT")" "$(dirname "$WATCHDOG_SCRIPT")" "$WATCHDOG_STATE"
  # Rename avoids writing through a running executable (ETXTBSY).
  install -m755 "$stage/mihomo" "$BINARY.new"
  mv -f "$BINARY.new" "$BINARY"
  install -m644 "$stage/config/config.yaml" "$CONFIG_DIR/config.yaml"
  install -m644 "$stage/unit" "$UNIT"
  install -m755 "$stage/watchdog" "$WATCHDOG_SCRIPT"
  install -m644 "$stage/watchdog-service" "$WATCHDOG_SERVICE"
  install -m644 "$stage/watchdog-timer" "$WATCHDOG_TIMER"
  systemctl daemon-reload
  systemctl enable mihomo nmd-vps-watchdog.timer
  systemctl restart mihomo
  systemctl restart nmd-vps-watchdog.timer
  wait_ready
  activated=0
  echo '== VPS 侧完成 ✓ =='
)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
