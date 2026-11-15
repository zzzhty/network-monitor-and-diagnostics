# 跨平台分工

NMD 按机器角色分工，不在每台电脑上重复做一遍网关。

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| 角色 | 服务器 / 网关 | 桌面机 | 桌面机 |
| 谁管流量 | NMD 部署并管理系统 mihomo，TUN 接管整机 | 外部 mihomo/代理客户端（具体软件调研中，待定） | 外部 mihomo/代理客户端（具体软件调研中，待定） |
| NMD 在这里做什么 | 部署、分流、监控、自动修复 | 只读监控和诊断 | 只读监控和诊断 |
| 后台 | systemd：系统 mihomo，以及独立的 monitor 单元 | 没有采集服务。可选 LaunchAgent 只启动桌面壳 | 当前用户的计划任务 `\NMD\Monitor`，登录期间运行 |

桌面端外部流量由外部 mihomo/代理客户端管理（具体软件调研中，待定）。NMD 在 macOS 和 Windows 上只做监控和诊断，不部署 mihomo，不改 DNS、路由、TUN 或系统代理。安装和命令见 [macOS 使用说明](macos.md)、[Windows 使用说明](windows.md)。Linux 的部署、切换和验收见 [runbook.md](../runbook.md)。

## 为什么这样分

无头服务器适合脚本和 systemd。`cutover` 检查 VPS、清掉 Tailscale exit node、再应用并启动 mihomo；`rollback` 停掉 mihomo 并改回 VPS exit node。配置、路由和 DNS 可以在应用前后对照，失败时留下现场，而不是在图形界面里点一步看一步。已有来源注册表时，旧的单 VPS `cutover` / `rollback` 会拒绝执行，避免切回错误的 exit node，见 [出口通道](egress-sources.md)。

Linux 有 nftables、fwmark 和 systemd-resolved，NMD 才能做可校验、可回滚的部署。本仓库的模板让 Tailscale 的 5210–5270 规则先于 mihomo 的 9000 规则；带标记的 tailscaled 传输走主路由表，mihomo 使用自己的路由表。这些是 Linux 策略路由，不是桌面 TUN 的开关。细节和依据在 [runbook.md](../runbook.md) 的「避免 Tailscale 与 VPS 循环依赖」。

桌面系统的 TUN 驱动、权限和登录自启交给外部客户端。NMD 再部署一套 mihomo TUN，会和那个客户端、Tailscale 抢同一条默认路由。具体用哪一个客户端还在调研，文档不绑定某一款。桌面机只留 NMD 的观察：macOS 用可选的用户级 LaunchAgent 启动桌面壳，不安装采集服务；Windows 用当前用户的计划任务采集，任务只在该用户登录后运行。

## Linux

模板是仓库根目录的 `config.yaml`。结构是：TUN 接管之后，国内、私网和 tailnet 直连，其余经 VPS 上的 SOCKS5 出海。`203.0.113.20:1080` 是文档占位，真实 Tailnet 地址由 `NMD_VPS_TS_IP` 注入。

规则顺序以该文件的 `rules:` 为准，包括：

- `connectivity-check.ubuntu.com` 直连，避免 NetworkManager 把联网检测标成受限。
- `tailscaled` 进程，以及 `tailscale.com`、`tailscale.io` 直连。
- `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48` 直连。
- `GEOSITE,cn`、`GEOIP,private`、`GEOIP,CN` 直连。
- 其余匹配到名为 `VPS` 的 SOCKS5。

TUN 的 `route-exclude-address` 排除私网、tailnet，以及模板里的占位网段。`198.51.100.0/24` 和 `203.0.113.0/24` 是本仓库文档用的测试网段，不是要抄到其他机器上的 Tailscale 官方地址。DERP 地址会变；Linux 上由 tailscaled 的 fwmark 绕过 TUN，不靠一份固定的 DERP 网段。

MagicDNS 仍由 tailscaled 提供。模板把 `+.ts.net` 送到 `100.100.100.100`，并绑定 Linux 接口 `tailscale0`。exit node 必须为空，否则关掉 mihomo 之后整机仍走 VPS。

monitor 单元和 mihomo 服务是两件事。`nmd monitor install` 不部署网络；`nmd apply`、`nmd cutover` 才动系统 mihomo。

## macOS 与 Windows

这两个系统是桌面机。NMD 的边界：

- macOS：源码 CLI、只读诊断面板，以及「设置与帮助」里对自己 `monitor.json` 的编辑。可选 `nmd desktop install` 做用户级桌面壳；登录自启是 LaunchAgent，只启动这个壳。没有 monitor 服务，也没有网络部署。
- Windows：当前用户的 CLI、SQLite 和可编辑监控配置的面板。后台是计划任务 `\NMD\Monitor`。不安装 Windows 服务，不安装桌面壳。

两边都拒绝 `apply`、来源/通道管理、`adopt` 和系统网络命令。

### 外部客户端

桌面端外部流量由外部 mihomo/代理客户端管理（具体软件调研中，待定）。它负责外部流量，包括 Tailscale 网络上的出口。NMD 不部署这套客户端，也不写它的配置。

Linux `config.yaml` 里可以跨平台对照的意图是：`tailscale.com` 与 `tailscale.io` 直连，tailnet `100.64.0.0/10` 和 `fd7a:115c:a1e0::/48` 直连，`GEOSITE,cn`、`GEOIP,private`、`GEOIP,CN` 直连，其余走自有 VPS。`GEOSITE` / `GEOIP` 依赖对应的 geodata，客户端是否自带这份数据，要等软件选定后再看。

这些 Linux 条目留在网关模板里，不当作桌面客户端的配置：

| 条目 | 原因 |
| --- | --- |
| `PROCESS-NAME,tailscaled,DIRECT` | Linux 上的进程名。macOS 与 Windows 的进程名不同。 |
| `DOMAIN,connectivity-check.ubuntu.com,DIRECT` | 只服务于 Ubuntu 的 NetworkManager。 |
| 接口名 `tailscale0` | Linux 上的 Tailscale 接口。桌面接口名不同。 |
| `iproute2-table-index`、`iproute2-rule-index`、fwmark | Linux 策略路由。桌面没有这套 nftables 绕行。 |
| `198.51.100.0/24`、`203.0.113.0/24` 以及模板里的 `203.0.113.20` | 本仓库的文档占位，不是 Tailscale 或 VPS 的真实地址。 |

与 Tailscale 共存时，保持这几条：

- tailnet `100.64.0.0/10` 和 IPv6 `fd7a:115c:a1e0::/48` 直连。Linux 规则带 `no-resolve`，避免为了匹配网段再去解析。
- MagicDNS 继续由 Tailscale 解析。Linux 模板把 `+.ts.net` 送到 `100.100.100.100`，并绑定接口 `tailscale0`。桌面不要写死这个接口名。
- DERP 和打洞流量不要被 TUN 劫持。Linux 靠 tailscaled 的 fwmark，不靠一份固定网段。`config.yaml` 里的 `198.51.100.0/24` 与 `203.0.113.0/24` 不能当作 DERP 排除项。
- 不要同时开 Tailscale exit node。exit node 会把整机再交回某个出口，和客户端接管默认路由叠在一起。Linux 上的 `cutover` 同样先清掉 exit node，再启动 mihomo。

### 配置校验（规划）

这一节是规划，当前没有实现。校验分成两块，配置彼此分开：

- 外部客户端只读校验。选定软件之后，只读取它已经生效的配置或状态，对照上面列出的跨平台意图。不写入该客户端，不预设它的配置路径、字段或操作步骤。
- NMD 自有探测。沿用监控配置里的 DNS、TCP、TLS、HTTP 探测，观察本机连通性。探测项写在 NMD 自己的 `monitor.json`。

解耦保持不变：NMD 的监控配置和外部客户端的配置是两份东西。校验失败只留下观察结果，不因此部署 mihomo，也不改 DNS、路由、TUN 或系统代理。
