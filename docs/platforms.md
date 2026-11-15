# 跨平台分工

NMD 按机器角色分工，不在每台电脑上重复做一遍网关。

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| 角色 | 服务器 / 网关 | 桌面机 | 桌面机 |
| 谁管流量 | NMD 部署并管理系统 mihomo，TUN 接管整机 | Clash Verge Rev，含它的 TUN | Clash Verge Rev，含它的 TUN |
| NMD 在这里做什么 | 部署、分流、监控、自动修复 | 只读监控和诊断 | 只读监控和诊断 |
| 后台 | systemd：系统 mihomo，以及独立的 monitor 单元 | 没有采集服务。可选 LaunchAgent 只启动桌面壳 | 当前用户的计划任务 `\NMD\Monitor`，登录期间运行 |

桌面机的出口由 Clash Verge Rev 管理。NMD 在 macOS 和 Windows 上不部署 mihomo，不改 DNS、路由、TUN 或系统代理。安装和命令见 [macOS 使用说明](macos.md)、[Windows 使用说明](windows.md)。Linux 的部署、切换和验收见 [runbook.md](../runbook.md)。

## 为什么这样分

无头服务器适合脚本和 systemd。`cutover` 检查 VPS、清掉 Tailscale exit node、再应用并启动 mihomo；`rollback` 停掉 mihomo 并改回 VPS exit node。配置、路由和 DNS 可以在应用前后对照，失败时留下现场，而不是在图形界面里点一步看一步。已有来源注册表时，旧的单 VPS `cutover` / `rollback` 会拒绝执行，避免切回错误的 exit node，见 [出口通道](egress-sources.md)。

Linux 有 nftables、fwmark 和 systemd-resolved，NMD 才能做可校验、可回滚的部署。本仓库的模板让 Tailscale 的 5210–5270 规则先于 mihomo 的 9000 规则；带标记的 tailscaled 传输走主路由表，mihomo 使用自己的路由表。这些是 Linux 策略路由，不是桌面 TUN 的开关。细节和依据在 [runbook.md](../runbook.md) 的「避免 Tailscale 与 VPS 循环依赖」。

桌面系统的 TUN 驱动、权限和登录自启，Clash Verge Rev 已经做成日常可用的图形客户端。NMD 再部署一套 mihomo TUN，会和 Verge、Tailscale 抢同一条默认路由。所以桌面机只留 NMD 的观察：macOS 用可选的用户级 LaunchAgent 启动桌面壳，不安装采集服务；Windows 用当前用户的计划任务采集，任务只在该用户登录后运行。

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

### 配合 Clash Verge Rev

在 Clash Verge Rev 里管理外部流量，并打开它的 TUN 模式，让 Tailscale 网络也走这套分流。不要同时打开 Tailscale 的 exit node。exit node 会把整机再交回某个出口；Verge 的 TUN 也在接管默认路由，两套叠在一起就会抢路由。Linux 上的 `cutover` 同样要求先清掉 exit node，再启动 mihomo。

Verge 的配置文件是 mihomo 配置。下面这些 `rules:` 行与 `config.yaml` 的意图相同，可以直接放进桌面配置，代理节点的名字换成这份 Verge 配置里的实际节点：

```yaml
- DOMAIN-SUFFIX,tailscale.com,DIRECT
- DOMAIN-SUFFIX,tailscale.io,DIRECT
- IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
- IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve
- GEOSITE,cn,DIRECT
- GEOIP,private,DIRECT,no-resolve
- GEOIP,CN,DIRECT
- MATCH,你的出口节点
```

`GEOSITE,cn` 和 `GEOIP,CN` 需要对应的 geodata。Verge 是否随版本带上 `geoip.metadb` 与 `GeoSite.dat`，需按实际 Verge/mihomo 版本核对。

这些 Linux 条目不要原样抄进桌面配置：

| 条目 | 原因 |
| --- | --- |
| `PROCESS-NAME,tailscaled,DIRECT` | 这是 Linux 上的进程名。macOS 与 Windows 的进程名不同，需按实际 Verge/mihomo 版本核对。 |
| `DOMAIN,connectivity-check.ubuntu.com,DIRECT` | 只服务于 Ubuntu 的 NetworkManager。 |
| `interface-name: tailscale0` | 只是 Linux 上的 Tailscale 接口。桌面接口名不同。 |
| `iproute2-table-index`、`iproute2-rule-index`、fwmark | Linux 策略路由。桌面 TUN 没有这套 nftables 绕行。 |
| `198.51.100.0/24`、`203.0.113.0/24` 以及模板里的 `203.0.113.20` | 本仓库的文档占位，不是 Tailscale 或 VPS 的真实地址。 |

与 Tailscale 共存时，保持这几条：

- tailnet `100.64.0.0/10` 和 IPv6 `fd7a:115c:a1e0::/48` 直连，规则上加 `no-resolve`，避免为了匹配网段再去解析。
- MagicDNS 继续由 Tailscale 解析。模板把 `+.ts.net`、`+.tailscale.com`、`+.tailscale.io` 放进 `fake-ip-filter`，避免这些名字拿到 fake-ip。`+.ts.net` 在 Linux 上送到 `100.100.100.100`。桌面配置可以保留同样的过滤；要不要把解析绑定到某个接口，需按实际 Verge/mihomo 版本核对，不要写死 `tailscale0`。
- DERP 和打洞流量不要被 TUN 劫持。Linux 靠 tailscaled 的 fwmark，不靠一份固定网段。桌面没有这套标记路由。`config.yaml` 里的 `198.51.100.0/24` 与 `203.0.113.0/24` 不能当作 DERP 排除项。Verge 用哪一项避开 DERP 和打洞，需按实际 Verge/mihomo 版本核对。
- 不要同时开 Tailscale exit node。关掉 Verge 之后，exit node 仍会让整机依赖那个出口。

Verge 打开 TUN 之后，是否改写配置里的 `tun:`、`dns-hijack` 或系统代理，需按实际 Verge/mihomo 版本核对。NMD 不替桌面机写这些字段。
