# Future TODO

按优先级排列的待办。完成后把条目移除并在对应提交说明里记录证据。

## P1 — 进行中

1. **VPS mihomo 挂起**：2026-11-02 日志定性——**静默挂起**（11-01 复发 12 窗口，
   最长 62min；journalctl 全天仅 1 行、零报错零退出，`Restart=always` 无效；无 OOM、
   负载 0、磁盘 35% 空闲，外部因素排除，系进程内部停摆）。**对策已入库并部署**：
   vps-setup.sh 新增 `nmd-vps-watchdog`（systemd timer 每分钟经自身 socks5 探测
   出口，连续 3 次失败且 VPS 直连正常时 restart mihomo；成功即清零）。
   2026-11-02 已部署 VPS 生效（三件套直装、mihomo 零触碰，首检 ok、NRestarts=0）；
   后续复发会在 ~3 分钟内自愈并在 HOME 侧表现为至多一次 `all_unhealthy` 闪断而非
   小时级窗口。2026-11-11 复核：VPS 侧运行正常。继续常态观察复发签名。

## P2 — 低优先

2. **真 P2P 直连（已定性收档，2026-11-02）**：HOME↔VPS 稳定运行于 peer-relay
   （aliyun UDP，71ms 零抖动）。VPS 侧 root 实勘：端点通告正常
   （203.0.113.154:41641）、netcheck UDP true、且日志出现过 `via=direct` 到 HOME
   公网地址——但 HOME 侧始终 `direct connection not established`。结论：该线路
   WG 形态 UDP 受 GFW 间歇干扰，单包可穿、会话不稳，**peer-relay 即终态方案**；
   仅换 VPS/线路时再重开此项。

## 已关闭（留档）

- P1 oness 订阅：2026-11-11 用户取消订阅（供应商已迁移且节点长死）。本地遗留
  `~/.config/nmd/egress-defs/`（含私钥订阅 URL 的 oness.json 与旧版 vps-tailnet.json）
  已整目录清除；现行 `egress/sources.json`、监控库、auto 候选均无 oness 残留。
- P0 出口中继：2026-10-30 打通 peer-relay，24h 监控达标后于 10-31 关闭。
- P2 vm-aliyun 安全组 UDP 41641：2026-10-30 用户完成。
- P2 GUI 亮色主题对比度：2026-10-30 修复（ink-300/400 加深，双主题 WCAG 断言）。
