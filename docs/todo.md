# Future TODO

按优先级排列的待办。完成后把条目移除并在对应提交说明里记录证据。

## 已达成（待收尾确认）

1. **P0 出口中继**：2026-10-30 用户打通 peer-relay（`47.112.2.196:40000:vni:1`，aliyun
   UDP 中继）——ping 71-72ms 零抖动，候选 healthcheck 73ms，egress_foreign 581ms。
   24h 稳定性报告排期 2026-10-31 11:47（durable 定时任务）；达标即正式关闭。
   真 P2P 直连（不经中继）仍可作为后续优化保留观察。
2. ~~P2 vm-aliyun 安全组 UDP 41641~~：已完成（2026-10-30，用户操作）。

## P1 — 进行中

3. **VPS mihomo 挂起根因**（非 DNS 问题，勿往 dns 段方向查——2026-10-29"DNS 污染"系
   误诊已更正）：挂起签名 = tailnet SSH 通 + 节点服务无响应（socks/healthcheck 失败）。
   已纳入 24h 监控：一键诊断新增 `node_service_unresponsive` 结论码；24h 报告输出
   挂起窗口的精确起止，用于到 VPS 上对 `journalctl -u mihomo` 逐窗取日志定根因；
   若复发频繁，在 vps-setup.sh 层面加看门狗。
4. **oness 订阅复活**：GUI「更新订阅」拉取新入口（供应商侧疑似换 IP）；任一节点
   恢复即重建四候选冗余。

## P2 — 低优先

5. ~~GUI 亮色主题 muted 文字对比度~~：已修（2026-10-30，亮色 ink 阶加深至全部
   ≥4.5:1，浏览器 spec 增加双主题 WCAG 断言覆盖）。
