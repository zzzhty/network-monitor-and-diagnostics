# Future TODO

按优先级排列的待办。完成后把条目移除并在对应提交说明里记录证据。

## P1 — 进行中

1. **VPS mihomo 挂起根因**（非 DNS 问题，勿往 dns 段方向查——2026-10-29"DNS 污染"系
   误诊已更正）：挂起签名 = tailnet SSH 通 + 节点服务无响应（socks/healthcheck 失败）。
   一键诊断已有 `node_service_unresponsive` 结论码。2026-10-30 → 10-31 的 24h 监控
   零挂起窗口（2900/2900 全成功，p95 73ms）；继续常态观察，复发时用当天的挂起
   窗口清单到 VPS 对 `journalctl -u mihomo` 取日志定根因；若频繁复发，在
   vps-setup.sh 层面加看门狗。
2. **oness 订阅复活**：GUI「更新订阅」拉取新入口（供应商侧疑似换 IP）；任一节点
   恢复即重建四候选冗余。

## P2 — 低优先

3. **真 P2P 直连（观察项，非必须）**：当前 HOME↔VPS 走 peer-relay
   （`47.112.2.196:40000:vni:1`，aliyun UDP），2026-10-30 → 10-31 实测 24h 零失败、
   p50/p95 = 72/73ms、max 268ms，egress_foreign p95 621ms——已达生产标准并正式关闭
   P0。真直连仅作为消除 aliyun 中继跳的进一步优化。

## 已关闭（留档）

- P0 出口中继：2026-10-30 打通 peer-relay，24h 监控达标后于 10-31 关闭。
- P2 vm-aliyun 安全组 UDP 41641：2026-10-30 用户完成。
- P2 GUI 亮色主题对比度：2026-10-30 修复（ink-300/400 加深，双主题 WCAG 断言）。
