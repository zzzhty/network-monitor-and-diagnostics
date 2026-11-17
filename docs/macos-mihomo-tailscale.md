# macOS：mihomo 与官方 Tailscale 共存（实验）

这是一条显式选择的 macOS 实验路径，不自动启用，也不是生产稳定。它不改 Linux Home 上已经在用的 mihomo 与默认行为，Windows 延期。仓库不因此安装服务、不改系统网络，也不连接真实机器。

记录来自用户本机实测，时间是 2026-11-17（Asia/Shanghai）。本仓库没有重跑这些测试，也没有原始日志。下面不写真实主机地址、用户目录、完整配置、账户或密钥。规则示例用文档占位地址 `203.0.113.20`，并注明它不是实测机器上的地址。

实测表明：mihomo 1.19.34 的 TUN 可以和官方 Tailscale 同时运行。当时清掉了官方 Tailscale 的 exit node，官方 Tailscale 仍负责 tailnet 和 MagicDNS。mihomo 的海外出口是每台 VPS 自己的 SOCKS over tailnet，不是 Tailscale exit node。短时真实应用测试通过，随后在保持唤醒的情况下做了近 8 小时网络探针。

## 状态矩阵

| 项 | 状态 | 说明 |
| --- | --- | --- |
| mihomo 1.19.34 TUN 与官方 Tailscale 同时运行，短时应用测试与近 8 小时探针 | 已验证 | 用户本机实测。本仓库未重跑 |
| 清 exit node，保留 tailnet 与 MagicDNS；海外出口为 VPS SOCKS over tailnet | 已验证 | 用户本机实测 |
| 路由排除 `100.64.0.0/10`、`fd7a:115c:a1e0::/48`；接口动态发现 | 已验证 | 不得把接口写成固定 utun 序号，例如 utun4 或 utun5 |
| TUN 接口前缀 `198.18.0.1/30`；`tun.dns-mode=native` 在 scutil 登记 `198.18.0.2`，order 1 | 已验证 | `disabled` 不接管系统 DNS。不要把前缀上不存在的地址设成系统 DNS |
| `resolv.conf` 仍可能显示 Tailscale DNS | 已验证 | 不能只凭 `resolv.conf` 判断。作用域 DNS 不保证全部查询走 native |
| MagicDNS 定向可达与国内直连仍然保留 | 已验证 | 用户本机实测 |
| Wi-Fi 的 HTTP / HTTPS / SOCKS 指向没有监听的 `127.0.0.1:7897` 时，App 和网页失败；三项关闭后恢复 | 已验证 | 来源 Clash 只是推测。curl 默认不读 macOS 系统代理 |
| 近 8 小时采样统计，以及 04:06 前后的 1080 失败窗口 | 已观察 | 窗口根因未定。95 次 `critical=false` 不代表没有故障 |
| `ws.chatgpt.com` 有两条命中国内 GeoIP 后直连超时 | 已观察 | DNS 来源未知，不能据此证明污染 |
| 四个域名的 `DOMAIN-SUFFIX` 放在国内 geosite / geoip 之前 | 仅静态校验 | 用户隔离配置上 `mihomo -t` 已通过，本仓库未重跑，尚未实机短测 |
| 探针三分法、dead proxy 只读告警、回退清单 | 仅静态校验 | 纯函数和固定样例，不接触系统网络 |
| App 实际发送、短测后的回退、1080 取证、睡眠唤醒、真实 IPv6 | 未验证 | 见文末清单。Linux CI 通过不能标成 macOS 运行通过 |

## 配置落点

Linux 网关仍然用仓库根目录的 `config.yaml`。这条 macOS 路径不改那个文件，也不另起一套 YAML 主配置。

可审查的产物是 JSON 包装，不是 mihomo 能直接加载的配置：

- 生成与校验：`scripts/macos_coexist.py`
- 示例：`examples/macos-mihomo-coexist.experiment.json`
- 回归：`tests/test_macos_coexist.py`

示例里的规则顺序是结构样例，不是用户机器的完整配置。国内域名规则、私网 CIDR、`GEOIP,CN,DIRECT`（没有 `no-resolve`）和 `MATCH,NMD-EXIT` 只用来固定先后次序。私网 CIDR 用文档网段代替当时夹在 geosite 与 geoip 之间的直连规则。

`NMD-EXIT` 是既有海外出口组。域名修复只在国内 `GEOSITE,cn` 和 `GEOIP,CN` 之前加入：

```text
DOMAIN-SUFFIX,chatgpt.com,NMD-EXIT
DOMAIN-SUFFIX,openai.com,NMD-EXIT
DOMAIN-SUFFIX,oaistatic.com,NMD-EXIT
DOMAIN-SUFFIX,oaiusercontent.com,NMD-EXIT
```

`DOMAIN-SUFFIX` 覆盖该名本身和它的子域，例如 `ws.chatgpt.com`、`api.openai.com`。它不匹配 `notchatgpt.com`、`chatgpt.com.evil.test` 这类只是长得像的名字。国内域名和国内 IP 仍走原来的直连规则。修复不改全局 IP 规则，也不把 `GEOIP,CN` 改到出口组。

静态匹配用的“中国 IP”是调用方给的夹具，不是 GeoIP 数据库，也不是当时日志里的地址。

出口块要求：

- 类型是 socks5 over tailnet，`tailscale_exit_node` 为 false
- 服务器必须是文档网段里的占位地址，示例为 `203.0.113.20:1080`
- 接口发现为 `dynamic`，配置里不写 utun 序号，也不写 Linux 的 `tailscale0`

DNS 约束：

- 观察到的 TUN 接口前缀是 `198.18.0.1/30`。这里把它记成接口前缀，不把它写成 fake-ip 地址池
- `tun.dns-mode=disabled` 不接管系统 DNS
- `native` 只接受 `198.18.0.2`，并且该地址必须是这条前缀上的主机地址。`198.18.0.1` 是接口地址，不是这次登记的解析器；`198.18.0.5` 不在这条前缀上
- scutil 顺序是 1，使默认系统解析和本机 mihomo DNS 一致
- `resolv.conf` 不够用。作用域 DNS 不保证每一条查询都走 native

IPv6：无 AAAA 不是故障。`curl -6` 可能打到 IPv4 映射地址，不能据此声称真实 IPv6 已经通过。示例里的 `real_ipv6_path_verified` 固定为 false。

## 系统代理

只做只读检测。启用中的 HTTP、HTTPS 或 SOCKS 指向已确认没有监听的地址时，记一条 `dead_proxy` 警告。监听状态未知时记 `listener_unknown`，不把它说成已经确认的 dead proxy。

保存了 `127.0.0.1:7897` 但 Enabled No，不算故障。bypass 原样保留；代理禁用时，留下 bypass 无害。结果里没有关闭、打开或恢复动作。restore 不重新开启这些代理。

curl 能经 TUN 或 VPS 成功，只说明这次 curl 成功。它默认不读 macOS 系统代理，所以不能代表 App 正常，也不能代表海外直连。

## 探针分类

旧的本地探针不在本仓库里。这里用纯函数把一条 `tun-` 样本分成下面几类，不再在路由和 DNS 通过之后一律标成待人工 TLS 复查：

| 结果 | 分类 |
| --- | --- |
| rc 0，TLS 有效 | `tun_network_ok_needs_app_confirm` |
| rc 28，HTTP 2xx/3xx，TLS 有效 | `tun_network_incomplete_transfer_needs_app_confirm` |
| TLS 无效，或 rc 35/60，或其他非 0 且不属于上一行 | `tun_tls_or_transport_issues` |
| 路由或 DNS 未通过 | `tun_route_or_dns_not_ready` |
| 还没有 TLS 结论 | `tun_tls_evidence_missing` |

rc 不是 0 时，传输不算完成。HTTP 200 不是 App 登录或聊天通过。`remote_ip` 只被记下，不用来判断是不是假站点。TLS 是否有效和 HTTP 应用层分开记录。

单站 401、403、404、429、503，无 AAAA，以及单次 ping 失败，都不上升成整网关键故障。`system_proxy_disabled` 和 `local_7897_connection_refused` 是控制变量，不是故障。一条样本即使有 TLS 或传输问题，也不单独升成整网关键故障。

## 用户本机实测摘要

探针从 00:53:53 开始，测试标记 00:53:57，绝对截止 08:53:53，08:53:55 回退成功（rc 0）。约每 5 分钟一次，共 95 次。没有超过 7.5 分钟的缺口，也没有睡眠。交流电睡眠为 0，由应用持有 `NoIdleSleepAssertion`，不是脚本里的 `caffeinate`。

95 次都是 `critical=false`。这不代表没有故障。Baidu、Google 和出口的 TLS 与 HTTP 基本都通过。chatgpt 有一次 rc 28 且 HTTP 200，上限 5 秒。tailnet ping 有一次失败。RSS 大约从 48MB 升到 60MB 后趋稳，CPU 最高 3.7%。56 条 warning，0 条 error，0 条 fatal。启动时以及 04:06–04:07 有出口异常。

`ws.chatgpt.com` 共 75 条。73 条 `MATCH` 到 `NMD-EXIT` 并成功。03:14:38.501 和 04:40:40.507 两条命中 RuleSet / geoip-cn 后 `DIRECT`，随后超时；解析结果是中国 IP，DNS 来源未知，不能证明污染。当时没有单独的 OpenAI 域名规则，顺序是 geosite-cn、内网 CIDR、geoip-cn（没有 `no-resolve`）、再 `MATCH` 到出口。

### 1080 窗口

04:06:50.261 到 04:07:13.720，经 tailnet 访问 VPS 的 SOCKS 1080 失败 29 次：先 4 次 `network is unreachable`，后 25 次超时（21 次 TCP、4 次 UDP），其中 5 次是自动健康检查。04:06:40.685 有一次成功，04:07:15.272 又成功。没有 Sleep/Wake，也没有 TUN 或默认接口变化。窗口夹在两次全绿采样之间。

没有同期的 Tailscale 历史，也没有 VPS 侧日志。根因未定。不能声称 VPS 进程崩溃，也不能声称双 TUN 冲突。短测若要复查，需要把路由、接口、Tailscale 状态和 1080 可达性放在同一条时间线上，VPS 日志只是可选项。没有已授权的 VPS 通道，不能把单侧日志说成两端都覆盖了。不启动 SSH。

### watchdog_unhealthy

同一次运行里有一条 `watchdog_unhealthy`，比例 1/3。心跳新鲜度 8 秒，检查间隔 20 秒。这个搭配可能偏紧，但现有材料不能证明它一定是逻辑冲突。根因未知，不构成必须修复。

## 回退约束

本仓库没有实验启动器，这次也不把风险网络控制器做进产品。下面只是以后若有独立实验工具时必须满足的清单；`implemented_in_this_repository` 为 false，校验函数不会快照、启动或回退。

- 先做快照，独立 watchdog 确认存活之后才切网
- 绝对截止时间。短测 10 分钟，过夜最长 8 小时，到期不续期
- STOP 或到期都回退。只结束自己的进程
- 清掉 native 动态 DNS 后，确认 scutil 里不再有 198.18，再恢复原来的 Tailscale exit node、allow-lan、accept-dns 和网卡 DNS
- 不改系统代理，也不改 bypass
- 连续 3 次关键故障才回退
- 不自愈循环，不安装 daemon 或自动启动，不改电源设置
- 睡眠唤醒之后仍按绝对截止时间计算
- 不保证 watchdog 和采样进程都被杀掉之后还能恢复

## 后续实机验收

合并前需要用户在 Mac 上另行确认。本文件的单测通过只说明静态校验。

1. App 实际发送，而不是只看 curl。
2. `ws.chatgpt.com` 不再因 GeoIP 走到国内直连。域名修复尚未实机短测。
3. 短测结束后按上面的清单回退，并核对 scutil、Tailscale 和网卡 DNS。系统代理与 bypass 保持不动。
4. 若 1080 再波动，按上一节取证。不启动 SSH。
5. 睡眠唤醒之后，截止时间仍是原来的绝对时间，并确认没有把“进程被杀后仍能恢复”当成保证。
6. 真实 IPv6 需要非 IPv4 映射的对端证据。无 AAAA 或映射后的 `curl -6` 成功都不算通过。

Linux CI 通过不能标成 macOS 运行通过。这条 PR 保持打开，等用户完成 Mac 短测后再合并。
