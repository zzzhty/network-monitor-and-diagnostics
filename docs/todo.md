# Future TODO

按优先级排列的待办。完成后把条目移除并在对应提交说明里记录证据。

## P0 — 出口链路结构（当前单腿依赖 DERP 东京，拥塞即全灭）

1. **Tailscale 直连修复（VPS ↔ HOME）**
   - 实况：本机 netcheck `UDP: true`（简单 NAT、局域网 peer 直连正常）；VPS 对端
     `CurAddr` 空、**通告端点为空**，`tailscale ping` 全部 DERP(tok)，直连从未建立。
   - VPS 主机防火墙已确认全放行；真因待 VPS 侧实查：`tailscale netcheck`（STUN 映射）
     与 `ss -ulnp | grep tailscaled`（本地监听端口）；怀疑 provider 网络层丢 UDP 或
     tailscaled 端点发现异常。
   - 若需固定端口：tailscaled unit 加 `--port=41641` 后重启。
   - 验收：`tailscale ping 100.107.214.100` 输出 direct；GUI「一键排查」egress_foreign
     延迟降至中国↔VPS 单程 RTT 量级。
   - 注意：HOME↔aliyun 与 VPS↔aliyun 直连良好**不能**帮助 VPS↔HOME 直连（全对等
     mesh，每对独立协商）。

2. **自建 DERP（vm-aliyun）作为结构性兜底**
   - 动机：直连若被 GFW 拦死无解时，官方东京 DERP 是唯一腿且随国际拥塞劣化
     （2026-10-29 晚实例：DERP pong 稳定 200ms 但 TCP 流 3-6s 重传、候选全超时）。
   - 做法：vm-aliyun 跑 `derper`（域名 + Let's Encrypt 证书），管理台 ACL 增加
     `derpMap` 注册 custom DERP，安全组放行 TCP 443。aliyun 自身零 UDP 端点不影响
     当 DERP（走 TCP/TLS）。
   - 收益：整个 tailnet 所有 peer 的中继兜底从东京换为国内中转，两段都快。
   - 与 #1 可并存：直连为主、自建 DERP 兜底。

## P1 — 冗余与根因

3. **oness 订阅复活**：GUI「更新订阅」拉取新入口（供应商侧疑似换 IP）；任一节点
   恢复即重建四候选冗余，单点故障场景即消除。
4. **VPS mihomo 间歇挂起根因**：2026-10-28 曾完全停止（1080 拒连，手动重启恢复）。
   VPS 上 `journalctl -u mihomo` 与 OOM/内存检查；若复发，在 vps-setup.sh 层面加
   看门狗。注意：vps-setup.sh 配置模板不含 dns 段是**正确现状**（"DNS 污染"系
   2026-10-29 误诊，已更正：劣化链路上域名败 ≠ DNS 故障，勿再加）。

## P2 — 低优先

5. **vm-aliyun 安全组放行 UDP 41641**：修复其零端点通告（不影响本链路）。
6. **GUI 亮色主题 muted 文字对比度**：`--ink-300` 4.03–4.43:1 边缘低于 WCAG AA 4.5
   （弱化文本，2026-10-29 评审搁置记录）。
