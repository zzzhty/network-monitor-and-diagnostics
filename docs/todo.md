# Future TODO

按优先级排列的待办。完成后把条目移除并在对应提交说明里记录证据。

## P1 — 进行中

1. **VPS mihomo 挂起**：2026-11-02 日志定性——**静默挂起**（11-01 复发 12 窗口，
   最长 62min；journalctl 全天仅 1 行、零报错零退出，`Restart=always` 无效；无 OOM、
   负载 0、磁盘 35% 空闲，外部因素排除，系进程内部停摆）。**对策已入库**：
   vps-setup.sh 新增 `nmd-vps-watchdog`（systemd timer 每分钟经自身 socks5 探测
   出口，连续 3 次失败且 VPS 直连正常时 restart mihomo；成功即清零）。
   待部署到 VPS 生效；后续复发会在 ~3 分钟内自愈并在 HOME 侧表现为至多一次
   `all_unhealthy` 闪断而非小时级窗口。
2. **oness 订阅复活**：GUI「更新订阅」拉取新入口（供应商侧疑似换 IP）；任一节点
   恢复即重建四候选冗余。

## P2 — 低优先

3. **真 P2P 直连（观察项，非必须）**：当前 HOME↔VPS 走 peer-relay
   （`203.0.113.47:40000:vni:1`，aliyun UDP），2026-10-30 → 10-31 实测 24h 零失败、
   p50/p95 = 72/73ms、max 268ms，egress_foreign p95 621ms——已达生产标准并正式关闭
   P0。真直连仅作为消除 aliyun 中继跳的进一步优化。

## 已关闭（留档）

- P0 出口中继：2026-10-30 打通 peer-relay，24h 监控达标后于 10-31 关闭。
- P2 vm-aliyun 安全组 UDP 41641：2026-10-30 用户完成。
- P2 GUI 亮色主题对比度：2026-10-30 修复（ink-300/400 加深，双主题 WCAG 断言）。
