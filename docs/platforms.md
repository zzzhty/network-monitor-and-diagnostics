# 跨平台分工

NMD 按机器角色分工，不在每台电脑上重复做一遍网关。

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| 角色 | 服务器 / 网关 | 桌面机 | 桌面机 |
| 谁管流量 | NMD 部署并管理系统 mihomo，TUN 接管整机 | 与 Clash Verge Rev 共同使用时，由 Clash Verge Rev 管理 | 与 Clash Verge Rev 共同使用时，由 Clash Verge Rev 管理 |
| NMD 在这里做什么 | 部署、分流、监控、自动修复 | 监控（monitor）和诊断（diagnostics） | 监控（monitor）和诊断（diagnostics） |
| 后台 | systemd：系统 mihomo，以及独立的 monitor 单元 | 可选常驻守护（root supervisor + 用户 daemon，`nmd macos daemon install`，默认关）；桌面壳 LaunchAgent 仍可选 | 当前用户的计划任务 `\NMD\Monitor`，登录期间运行 |

macOS 和 Windows 上，NMD 的默认定位是监控（monitor）和诊断（diagnostics）。与 Clash Verge Rev 共同使用时，流量由 Clash Verge Rev 管理。桌面端长期用哪一款客户端仍在调研（具体软件调研中，待定）。macOS 另有两条实验路径：`sudo nmd macos takeover` 以 sudo 前台方式自行运行 mihomo 接管整机出口（绝对截止、幂等回退、无常驻），以及 `nmd macos daemon install` 安装 Paseo 式常驻守护（root 管理器监督接管、无绝对截止、健康驱动回退与 panic 恢复、面板归属 daemon）——两者见 [macos-mihomo-tailscale.md](macos-mihomo-tailscale.md)，均默认关闭、显式启用；Windows 无此路径。除此之外 NMD 不部署 mihomo，不改 DNS、路由、TUN 或系统代理。安装和命令见 [macOS 使用说明](macos.md)、[Windows 使用说明](windows.md)。Linux 的部署、切换和验收见 [runbook.md](../runbook.md)。

## 为什么这样分

无头服务器适合脚本和 systemd。`cutover` 检查 VPS、清掉 Tailscale exit node、再应用并启动 mihomo；`rollback` 停掉 mihomo 并改回 VPS exit node。配置、路由和 DNS 可以在应用前后对照，失败时留下现场，而不是在图形界面里点一步看一步。已有来源注册表时，旧的单 VPS `cutover` / `rollback` 会拒绝执行，避免切回错误的 exit node，见 [出口通道](egress-sources.md)。

Linux 有 nftables、fwmark 和 systemd-resolved，NMD 才能做可校验、可回滚的部署。本仓库的模板让 Tailscale 的 5210–5270 规则先于 mihomo 的 9000 规则；带标记的 tailscaled 传输走主路由表，mihomo 使用自己的路由表。这些是 Linux 策略路由，不是桌面 TUN 的开关。细节和依据在 [runbook.md](../runbook.md) 的「避免 Tailscale 与 VPS 循环依赖」。

桌面系统的 TUN 驱动、权限和登录自启交给外部客户端。NMD 再部署一套 mihomo TUN，会和那个客户端、Tailscale 抢同一条默认路由。具体用哪一个客户端还在调研。与 Clash Verge Rev 共同使用时，NMD 只做监控和诊断，用来验证当前方案能否在它上面跑通。桌面机的后台是：macOS 默认只有可选的用户级 LaunchAgent 启动桌面壳，显式安装的常驻守护（`nmd macos daemon install`）会补上采集监督、面板服务与受监督的接管；Windows 用当前用户的计划任务采集，任务只在该用户登录后运行。

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

两边都拒绝来源/通道管理、`adopt` 和 Linux 的系统网络命令。`nmd apply` / `refresh` 在 Linux 和 macOS 上是同一次事务：先标待应用，再激活本机已安装的运行面，成功后才记录版本。Linux 激活 mihomo 部署并校验；macOS 在已安装常驻守护时先做只读预检，通过后才执行 `nmd macos daemon restart`（先 stop 再 start），不下载代理资产，不调用 `takeover-start`。预检失败则不 stop、不 sudo。若当时有进行中的接管，stop 会先按快照回退，DNS、路由或 Tailscale exit node 会回到接管前；若 `on_boot` 为 true，且这次启动被管理器当成新的一次开机，它可能开始接管。Windows 仍拒绝 `apply`。

### 外部客户端

桌面端长期用哪一款客户端仍在调研（具体软件调研中，待定）。与 Clash Verge Rev 共同使用时，外部流量由 Clash Verge Rev 管理，包括 Tailscale 网络上的出口。NMD 不部署这套客户端，也不写它的配置。

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

### Clash Verge Rev 配置校验（规划）

这一节只写设计和验收标准，是后续工作。本 PR 不实现校验器。

与 Clash Verge Rev 共同使用时，NMD 的功能是监控（monitor）和诊断（diagnostics）。校验用来确认当前方案能在 Clash Verge Rev 上跑通：私有地址和国内直连，其余经 Tailscale 上的 VPS 出海，并记下每次状态。这部分监控是 NMD 自己的实现。

读两类材料：

- 只读读取 Verge/mihomo 的配置文件。配置文件路径和字段名需按实际 Verge/mihomo 版本核对。这里不预设路径，也不给一份 Verge 专用字段表。
- 可选的运行时观察由 NMD 自己做：本机出口、DNS、路由，以及监控配置里已有的 DNS、TCP、TLS、HTTP 连通性探测。探测项写在 NMD 自己的 `monitor.json`。

对照依据是 Linux 模板 `config.yaml` 里已经写明的意图。Verge 配置是否使用同一字段，需按实际 Verge/mihomo 版本核对。对不上的项记为待核对，不用 Linux 字段名判成通过。

| 要点 | 对照依据 | 验收 |
| --- | --- | --- |
| TUN 开启 | 模板 `tun.enable: true` | 记录里能看出 TUN 是否开启。Verge 用哪个字段表示，需按实际 Verge/mihomo 版本核对。 |
| private 与 CN 直连 | `GEOIP,private`、`GEOSITE,cn`、`GEOIP,CN` 为 DIRECT | 私网和国内的规则意图是直连。 |
| 境外走代理，经 Tailscale 到 VPS | `MATCH,VPS`，VPS 为 SOCKS5 | 私网、国内、tailnet 之外走代理，代理落在 Tailscale 上的 VPS。节点在 Verge 里的名字需按实际 Verge/mihomo 版本核对。 |
| `100.64.0.0/10` 不被劫持 | `IP-CIDR,100.64.0.0/10,DIRECT,no-resolve`，且 TUN 排除该网段 | tailnet 直连。 |
| MagicDNS 不被劫持 | `+.ts.net` 在 `fake-ip-filter` 中，解析到 `100.100.100.100` | MagicDNS 仍由 Tailscale 解析。桌面不要写死 `tailscale0`。接口绑定方式需按实际 Verge/mihomo 版本核对。 |
| 不与 Tailscale exit node 冲突 | Linux `cutover` 先清掉 exit node | exit node 与 Verge 接管默认路由同时存在时，这一项失败。exit node 怎么读取，需按实际版本核对。 |

DERP 和打洞不要被 TUN 劫持。Linux 靠 tailscaled 的 fwmark。`198.51.100.0/24` 和 `203.0.113.0/24` 是文档占位，不能当成 DERP 排除网段。

解耦：

- 不调用 Clash 或 Verge 的 external-controller API。Linux 模板里的 `external-controller: 127.0.0.1:9090` 只属于网关，桌面校验不使用它。
- 不依赖 Clash/Verge 的原生功能，包括它自带的测速、日志或配置检查。
- 不修改它的配置。读取保持只读。
- 证据只有两样：只读配置文件，加上 NMD 自己的探测和本机观察。NMD 的 `monitor.json` 与 Verge 配置是两份文件。校验失败只留下观察结果，不因此部署 mihomo，也不改 DNS、路由、TUN 或系统代理。

每次校验把结果和时间戳写入 NMD 自己的状态目录，也就是现有采集器的 `--state-dir`。Windows 安装后的目录是 `%LOCALAPPDATA%\nmd-monitor`。面板按时间展示这些记录。记录属于 NMD，不写回 Verge。

后续实现同时满足这四条才算完成：

1. 一次校验产出一条带时间戳的记录，上表每一项都有结果。对不上版本的字段标成「需按实际 Verge/mihomo 版本核对」，不记成通过。
2. 记录留在 NMD 状态目录里，面板能按时间看到历史。
3. 实现不调用 external-controller，不修改 Verge/mihomo 配置，不把两份配置合成一份文件。
4. 在上述实现落地之前，仓库里没有这个校验器。本 PR 不含它。
