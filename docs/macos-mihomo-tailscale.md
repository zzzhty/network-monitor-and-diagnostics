# macOS：mihomo 与官方 Tailscale 共存（实验）

这是一条显式选择的 macOS 实验路径，不自动启用，也不是生产稳定。它不改 Linux Home 上已经在用的 mihomo 与默认行为，Windows 延期。仓库不因此安装服务、不改系统网络，也不连接真实机器。

记录来自用户本机实测，时间是 2026-11-17（Asia/Shanghai）。本仓库没有重跑这些测试，也没有原始日志。下面不写真实主机地址、用户目录、完整配置、账户或密钥。规则示例用文档占位地址 `203.0.113.20`，并注明它不是实测机器上的地址。

实测表明：mihomo 1.19.34 的 TUN 可以和官方 Tailscale 同时运行。当时清掉了官方 Tailscale 的 exit node，官方 Tailscale 仍负责 tailnet 和 MagicDNS。mihomo 的海外出口是每台 VPS 自己的 SOCKS over tailnet，不是 Tailscale exit node。短时真实应用测试通过，随后在保持唤醒的情况下做了近 8 小时网络探针。

## 状态矩阵

三列不要混写。用户隔离配置是机器上另一个目录里的实验，不是本 PR 的代码或安装包。本 PR 的静态/CI 只说明仓库里的纯函数和文档。本 PR 代码尚未在实机运行。这句指共存实验和回退实现；只读采集在 `4044472` 上有过一次部分验收。代理交叉读取已于 2026-11-19 在已安装代码上复跑，见下文。

| 项 | 用户隔离配置 | 本 PR 静态 / CI | 本 PR 实机 |
| --- | --- | --- | --- |
| mihomo 1.19.34 TUN 与官方 Tailscale 同时运行 | 短时应用测试与近 8 小时探针已观察 | 未重跑 | 未跑 |
| 清 exit node，保留 tailnet 与 MagicDNS；海外出口为 VPS SOCKS over tailnet | 已观察 | 示例里写明约束 | 未跑 |
| 路由排除 `100.64.0.0/10`、`fd7a:115c:a1e0::/48`；接口动态发现 | 已观察 | 示例拒绝写死 utun 序号 | 未跑 |
| TUN 前缀 `198.18.0.1/30`；`native` 登记 `198.18.0.2` order 1 | 已观察 | 纯函数拒绝不存在的系统 DNS | 未跑 |
| `resolv.conf` 不能单独判断；作用域 DNS 不保证全部走 native | 已观察 | 示例把这两项标成 false | 未跑 |
| 三项代理指向无监听的 `127.0.0.1:7897`；关闭后恢复。Enabled No 不是故障 | 已观察。来源 Clash 只是推测 | dead proxy 只读分类有单测 | 未跑 |
| 过夜 95 次采样，以及 04:06 的 1080 窗口 | 已观察。窗口根因未定 | 结论边界有单测 | 未跑 |
| 过夜回退 08:53:55 rc 0 | 已观察 | 回退清单有单测，控制器未实现 | 未跑 |
| 域名修复前 `ws.chatgpt.com` 有两条 GeoIP 直连超时 | 已观察。DNS 来源未知 | 旧顺序的夹具能复现这条直连 | 未跑 |
| 四个 `DOMAIN-SUFFIX` 放在国内规则前，10 分钟短测命中 | 已观察，见下节 | 规则顺序和子域有单测 | 未跑 |
| 10 分钟结束时的 RESTORED 12:14:30 | 只读核查通过 | 清单有单测 | 未跑。仓库实现尚未验证 |
| Tailscale status 时间序列 | 55 次字段因 2000 字节截断而不可用 | 纯函数拒绝先截断再解析 | 采集器未接入 |
| 睡眠唤醒、真实 IPv6、04:06 的 23 秒根因 | 未完成。短测未复现不等于修复 | 只锁定“不能标成完成” | 未跑 |

Linux CI 通过不能标成 macOS 运行通过。

## 配置落点

Linux 网关仍然用仓库根目录的 `config.yaml`。这条 macOS 路径不改那个文件，也不另起一套 YAML 主配置。

可审查的产物是 JSON 包装，不是 mihomo 能直接加载的配置，也不能交给 `mihomo -f`：

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

一批探针里只要有一条 incomplete transfer，`summarize_probe_batch` 的 `fully_ok` 就是 false。它不从探针推断 App 是否正常。用户确认应用和网页正常，与同一次运行里的单次传输未完成可以同时成立。

## 用户本机实测摘要

探针从 00:53:53 开始，测试标记 00:53:57，绝对截止 08:53:53，08:53:55 回退成功（rc 0）。约每 5 分钟一次，共 95 次。没有超过 7.5 分钟的缺口，也没有睡眠。交流电睡眠为 0，由应用持有 `NoIdleSleepAssertion`，不是脚本里的 `caffeinate`。

95 次都是 `critical=false`。这不代表没有故障。Baidu、Google 和出口的 TLS 与 HTTP 基本都通过。chatgpt 有一次 rc 28 且 HTTP 200，上限 5 秒。tailnet ping 有一次失败。RSS 大约从 48MB 升到 60MB 后趋稳，CPU 最高 3.7%。56 条 warning，0 条 error，0 条 fatal。启动时以及 04:06–04:07 有出口异常。

`ws.chatgpt.com` 共 75 条。73 条 `MATCH` 到 `NMD-EXIT` 并成功。03:14:38.501 和 04:40:40.507 两条命中 RuleSet / geoip-cn 后 `DIRECT`，随后超时；解析结果是中国 IP，DNS 来源未知，不能证明污染。当时没有单独的 OpenAI 域名规则，顺序是 geosite-cn、内网 CIDR、geoip-cn（没有 `no-resolve`）、再 `MATCH` 到出口。

### 1080 窗口

04:06:50.261 到 04:07:13.720，经 tailnet 访问 VPS 的 SOCKS 1080 失败 29 次：先 4 次 `network is unreachable`，后 25 次超时（21 次 TCP、4 次 UDP），其中 5 次是自动健康检查。04:06:40.685 有一次成功，04:07:15.272 又成功。没有 Sleep/Wake，也没有 TUN 或默认接口变化。窗口夹在两次全绿采样之间。

没有同期的 Tailscale 历史，也没有 VPS 侧日志。根因未定。不能声称 VPS 进程崩溃，也不能声称双 TUN 冲突。短测若要复查，需要把路由、接口、Tailscale 状态和 1080 可达性放在同一条时间线上，VPS 日志只是可选项。没有已授权的 VPS 通道，不能把单侧日志说成两端都覆盖了。不启动 SSH。

### watchdog_unhealthy

同一次运行里有一条 `watchdog_unhealthy`，比例 1/3。心跳新鲜度 8 秒，检查间隔 20 秒。这个搭配可能偏紧，但现有材料不能证明它一定是逻辑冲突。根因未知，不构成必须修复。

### 10 分钟隔离短测与只读回退

这次仍是用户隔离配置，不是本 PR 的代码或安装包。时间是 2026-11-17（Asia/Shanghai）。watchdog 12:04:28 启动，mihomo 12:04:29 启动，截止 12:14:28。12:07:19 时进程、心跳、native DNS、系统代理关闭和空的 Tailscale exit node 都正常。四个 `DOMAIN-SUFFIX` 已经加载在国内规则前面。

从 12:05:21 起，`ws.chatgpt.com` 至少 7 次都是 `DomainSuffix(chatgpt.com)` 到 `NMD-EXIT`。`chatgpt.com`、`ab`、`codex-cloud`、`chat.openai.com`、`api.openai.com`、`cdn.platform.openai.com`、`oaiusercontent` 和 `persistent.oaistatic.com` 也命中专用规则，没有再走 GeoIP 或 DIRECT。整段 10 分钟里，四个后缀共 55 条：chatgpt 族 42、openai 8、oaiusercontent 3、oaistatic 2。其中 ws 的 7 条都走代理，这一族没有 GeoIP/DIRECT。

用户在 12:07 确认应用和网页正常。探针 12:04:31 全部完成；12:05:37 的 chatgpt 是 rc 28、HTTP 200、TLS 通过、耗时 5.029 秒，按新逻辑记成 incomplete transfer，`fully_ok=false`，`notes=chatgpt_incomplete_transfer`，`critical=false`；12:06:45 恢复为全部完成。10 轮探针共 40 个请求：39 次 ok，1 次 incomplete transfer，0 次传输失败，0 次 critical。所以“应用正常”和单次传输未完成是同时成立的，不能写成全部探针都没有异常。

到 VPS SOCKS 1080 的 TCP 是 55/55 成功，耗时 75–164 毫秒，路由稳定。warning 只有 2 条，分别是启动和结束时的默认接口变化；0 条 error。没有 1080 失败。这不表示过夜那次 23 秒窗口的根因已经修复，那次窗口仍然根因未定。

Tailscale status 仍不可用：隔离采集把 `tailscale status --json` 的 stdout 先切到 2000 字节再解析，命令 rc 是 0，但 backend、self online 和 peer 字段全是空。同一次运行里单独查询看到 BackendState 为 Running、Self.Online 为 true。路由、prefs 和 1080 记录还在，status 时间序列没有。55 次都是这个结果。VPS 侧没有采集，也没有已授权通道。不启动 SSH。

截止 12:14:28 的回退在 12:14:30 返回 rc 0，标记 RESTORED。12:17:43 的只读核查没有本次测试的 mihomo、watchdog、sampler 或 collector，没有 utun5，scutil 里没有 198.18，也没有 sing-tun。默认路由回到官方 Tailscale，原来的 exit node、allow-lan 和 CorpDNS 已恢复，HTTP、HTTPS 和 SOCKS 仍是关闭。watchdog 和 sampler 在截止的同一秒各调用了一次 restore，两次都成功。这记下同秒重复回退的幂等风险。仓库实现尚未验证，本仓库没有实验启动器。

过夜 08:53:55 的回退成功仍然有效。它和这次 10 分钟回退都只属于用户隔离配置。

## 开发入口

后续 macOS 工作从下面的纯函数接着做，不从隔离目录里的临时脚本搬进产品。

| 顺序 | 模块任务 | 状态 |
| --- | --- | --- |
| 1 | `scripts/macos_coexist.py` 的规则、探针、代理和 status 白名单 | 本 PR。不改网络 |
| 2 | 只读适配：把完整 stdout 交给 `normalize_tailscale_status` | 已由 `scripts/macos_readonly.py` 接入。不在解析前按输出上限切片 |
| 3 | 显式打开的 macOS 采样字段，默认关闭 | 已接入。`macos_readonly.enabled` 默认为 false |
| 4 | 配置生成与启动前快照 | 已接入：`scripts/macos_prepare.py`（Phase A）。离线生成 + 只读快照；不启动进程、不改网络、不用 sudo |
| 5 | 切网或回退控制器 | 已接入：`scripts/macos_takeover.py`（Phase B）。sudo 前台、绝对截止、幂等回退；未实机运行 |
| 6 | 常驻守护与开机自启 | 已接入：`scripts/nmd_daemon.py`（Phase C）。root 管理器 + 用户 daemon、无绝对截止、健康/panic 回退、面板归属 daemon；未实机运行 |

现有采集器 `scripts/nmd_monitor.py` 的 `_run` 在命令输出超过 65536 字节时返回 `output_too_large` 和空正文，不会把截断前缀解析成健康。Tailscale status 另有一条有界读取，上限是解析器的 1 MiB；超过上限或读到一半时丢掉正文，不解析前缀。仓库里没有先切 2000 字节再解析 Tailscale JSON 的实现。Linux 的 `local-setup.sh` 把完整 JSON 交给解析器，这次不改它。

`normalize_tailscale_status` 的契约：

- 输入是完整 stdout（`str` 或 UTF-8 `bytes`）、整数 returncode、`truncated` 和解析上限。上限必须大于 2000。调用方先收齐有界输出，再调用；函数自己不跑命令。
- 先判断截断、命令是否执行、体积和 returncode，再 `json.loads`。只有解析成功才读取白名单。
- 输出只有 `availability`、`reason`、`backend_state`、`self_online`、`peer_summary`、`peer_count`、`peers_online`。没有主机名、地址、公钥或原文。
- `unavailable` 是命令失败、超限、截断或 JSON 无效。`unknown` 是 JSON 有效但 BackendState 或 Self.Online 缺失。`offline` 是字段齐了但不是 Running 且 Online。`healthy` 只表示 BackendState 为 Running 且 Self.Online 为 true。peer 缺失时 peer 摘要是 unknown，不会把节点说成 offline，也不会把缺字段说成 healthy。

权限和平台：上面的纯函数没有系统权限，也不自己执行命令。Linux Home 的 `config.yaml` 与 Windows 范围不变。只读命令在 `scripts/macos_readonly.py`，由下面的采集接入在 macOS 上显式执行。它不写入路由、DNS、代理或 Tailscale，也不使用 sudo。

离线命令是真实的，示例输出也来自这条命令，不是一次实机采集：

```bash
python3 scripts/macos_coexist.py profile
python3 scripts/macos_coexist.py normalize-status --returncode 0 <<'JSON'
{"BackendState":"Running","Self":{"Online":true,"HostName":"example-host"},"Peer":{"p1":{"Online":true},"p2":{"Online":false}}}
JSON
```

`profile` 打印的就是 `examples/macos-mihomo-coexist.experiment.json`。它带 `nmd_experiment` 包装，`directly_loadable_by_mihomo` 为 false。不要把它交给 `mihomo -f`。

`normalize-status` 的示例输出：

```json
{
  "availability": "healthy",
  "reason": null,
  "backend_state": "Running",
  "self_online": true,
  "peer_summary": "known",
  "peer_count": 2,
  "peers_online": 1
}
```

示例输入里的 `HostName` 不会出现在输出里。没有 `restore` 或 `cutover` 子命令。

## 只读采集接入

这一步把 Tailscale、路由、DNS、系统代理和可选 VPS 端口接进现有采集器。它依赖 PR #4（`cursor/macos-mihomo-tailscale-coexist-2919`）。合并顺序是先合并 PR #4，再合并本变更。本变更不合并 PR #4。

入口有两个，都只读：

- 采集器：`monitor.json` 的 `macos_readonly.enabled` 为 true 时，`nmd monitor run` 的本地样本带 `macos_readonly`。缺省是 false，不跑这些命令。示例见 `examples/monitor-local.json`。
- 显式命令：`python3 scripts/macos_readonly.py observe`。在 Linux 或 Windows 上打印 `not_applicable`，不调用 macOS 命令。`--config` 只取其中的 `vps`；命令本身就是一次显式读取，不看 `enabled`。

离线开发可以在没有 macOS 的环境运行。这里的 `observe` 得到 `not_applicable`，这不是健康：

```bash
python3 scripts/macos_readonly.py observe
python3 -m unittest test_macos_readonly test_macos_coexist -v
python3 scripts/check_architecture.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

不要把 Linux 测试当成实机通过，也不要使用 sudo：

1. 不要执行会改路由、DNS、代理或 Tailscale 的命令。
2. 在自己的 `monitor.json` 里把 `macos_readonly.enabled` 设为 true。VPS 只填写已经在用的地址和端口；端口不能是 22。不写 `vps` 就不会做 TCP，也不会扫描 tailnet。
3. 运行 `python3 scripts/macos_readonly.py observe --config <monitor.json>`。
4. 看字段：`tailscale.availability` 只有完整 JSON 解析成功才可能是 healthy；`routes.default_interfaces` 来自路由表，不是写死的接口名；`dns` 只留布尔，不回显解析器地址；关闭的代理即使保存着 127.0.0.1:7897 也进入 `disabled_saved`，没有 `dead_proxy`；`vps_tcp.status` 为 ok 时 `business_stable` 仍是 false，也不表示 tailnet、路由、DNS 或应用正常。
5. 再看一次系统代理和路由，确认这次命令没有改它们。已启用但端口不通只留下警告，不会自动关闭，也不会改 bypass。
6. `real_machine_verified` 和 `overnight_23s_root_cause_fixed` 在代码里固定为 false。

2026-11-17 14:55–14:59（Asia/Hong_Kong）用 `git archive` 在用户 Mac 上跑过 PR5 `4044472`（`40444724a36079da9919b5089e6b48ab345dc69f`）的 `python3 scripts/macos_readonly.py observe`。Tailscale 完整 JSON 解析通过。路由是按路由表发现的。DNS 已回到官方 MagicDNS，没有 198.18。当时 `scutil --proxy` 几乎只剩 FTP passive，没有 HTTPEnable、HTTPSEnable、SOCKSEnable，旧逻辑把 `system_proxy.status` 记成 `unknown` / `missing_field`。同一时刻 `networksetup` 显示 Wi-Fi 的 HTTP、HTTPS、SOCKS 都是 Enabled: No，Server/Port 仍是 127.0.0.1:7897，旧输出没有写入 `disabled_saved`。VPS 没有 monitor 配置，所以是 `not_configured`，没有编造或扫描地址。这次验收时三项代理是关闭的，保存着的地址不是故障，机器在代理关闭时是安全的。下面的交叉读取当时还没有复跑。此次新代码没有在实机运行。

### 2026-11-19 只读复跑

在已安装的 `df26516` 上复跑了两条只读入口，没有 sudo，没有改路由、DNS、代理或 Tailscale。配置是空 `probes`、`macos_readonly.enabled` 为 true、没有 `vps`。前后 `scutil --proxy` 的摘要一致，默认路由仍是 `utun5`，没有 `198.18`。

`python3 scripts/macos_readonly.py observe` 的整份报告 `status` 为 `observed`。Tailscale 完整 JSON 解析为 `healthy`（BackendState Running，Self.Online true）。路由按路由表发现，默认接口是 `en0` 和 `utun5`，`interface_discovery` 为 `dynamic`。DNS 为 `observed`，MagicDNS 在，没有 fake-ip，也没有 `198.18`。没有配置 VPS，所以 `vps_tcp` 和 `tailnet_route_status` 都是 `not_configured`，没有扫描地址。`ipv6_default_status` 为 `not_applicable`，这不是真实 IPv6 验收。

系统代理交叉读取：`scutil` 仍是 `missing_field`（没有 HTTPEnable、HTTPSEnable、SOCKSEnable）。`networksetup` 读了 Thunderbolt Bridge、Wi-Fi、Tailscale，三项都是 Enabled No，保存的地址是 `127.0.0.1:7897`。合并结果 `status` 为 `observed`，`effect` 为 `not_a_fault`，三项 `state` 为 `disabled`，`sources_agree` 为 true，地址进入 `disabled_saved`，`disabled_saved_address_is_fault` 为 false，没有 `dead_proxy`。缺键没有再把整段代理盖成未知。

同一次配置又做了 `nmd monitor run --once`，状态目录是本次私有临时目录。`monitor status` 为 `fresh`，一条样本，`macos_readonly.status` 为 `observed`，代理效果同样是 `not_a_fault`。样本的 `service_observation_error` 为 `unsupported_platform`，这是 macOS 没有 systemd。

`real_machine_verified`、`overnight_23s_root_cause_fixed`、`business_stable`、`report_is_health` 仍是 false。`real_machine_verified` 在读任何命令之前就写进报告，一次成功的观察不能把它改成 true。没有启用外部探测，没有看应用是否真的发出，没有启动 SSH，也没有把这次观察写成健康。过夜 23 秒窗口先不分析，`overnight_23s_root_cause_fixed` 保持 false；这次没有配置 `vps`，采集不会连接 1080。窗口以后再出现时，用当时的样本和同一条时间线上的路由、接口、Tailscale 一起看。

常驻用户 daemon 不能锁属 root 且为 0700 的接管目录。样本改写到旁边的 `nmd-monitor-user`，接管目录、`on_boot` 和 root supervisor 不动。已放上只读 `monitor.json`（空 `probes`，没有 `vps`）。重载后的第一笔样本是 `observed`，代理效果 `not_a_fault`，Tailscale `healthy`，`vps_tcp` 为 `not_configured`。这仍不证明 1080 窗口会被记下。

### 系统代理交叉读取

历史情况要按实际范围写。卸载 Clash 之后，macOS Wi-Fi 的系统 HTTP、HTTPS、SOCKS 代理仍是启用，并指向 127.0.0.1:7897，但本机没有进程监听。遵守系统代理的 ChatGPT Mac App、浏览器，以及后来的 Google 连不上。curl 默认不读 macOS 系统代理，所以 TUN 或 VPS 探针仍可能成功，让人误以为整网正常。用户关掉这三项之后确认应用恢复。官方 Tailscale 自己通常不走这条 HTTP 代理，当时的 bot 连接也可能仍然是通的；这不是“Tailscale 协议本身必然中断”。要防的是已启用且不可达的系统代理，再次让遵守系统代理的应用（包括可能走这条代理的相关连接）静默失败。

只读诊断同时看两个来源，不能只信可能缺键的 `scutil --proxy`：

- `scutil --proxy` 提供 HTTPEnable、HTTPSEnable、SOCKSEnable 和对应的 Proxy/Port。
- `networksetup -listallnetworkservices` 之后，对活跃服务读 `-getwebproxy`、`-getsecurewebproxy`、`-getsocksfirewallproxy` 的 Enabled、Server、Port。带星号的停用服务不查询。服务过多时保留 Wi-Fi，并标明被截断。
- 某一来源命令失败或缺少启用字段时，该来源记为 `unavailable` 或 `missing_field` / `unknown`。另一来源已经证实的启用或关闭保留，不用未知结果盖掉它。两个来源都没有证实，才让整段代理保持未知或不可用。两个来源不一致时不把启用的那一侧藏起来。
- 未启用，即使 Server/Port 仍是 127.0.0.1:7897，也写入 `disabled_saved`。`effect` 为 `not_a_fault`，`disabled_saved_address_is_fault` 为 false。bypass 只计数，不保存域名，也不改写。
- 已启用，并且指向本机端口，连接被拒绝或超时：`dead_proxy`，`priority` 为 `high`，`affects_system_proxy_clients` 为 true。`effect` 为 `system_proxy_clients_blocked`。Tailscale 为 healthy、tailnet 通、ping 通或 curl 成功都不把 `report_is_health` 变成 true；`dead_proxy_blocks_health_claim` 为 true。`tailscale_reachable_means_apps_ok` 恒为 false。curl 不读系统代理，所以 curl 成功同样不能排除这个问题。
- 已启用且本机端口能接通：记下启用，`effect` 为 `enabled_and_reachable`。这不是上面那种失效代理。
- 已启用但目标不是本机地址：不拨号，不把地址写进报告。
- 失败命令的正文不解析。报告不保存账户、机器身份或非本机代理地址。

这次不会自动关闭代理，不会改 bypass，不用 sudo，也不写网络设置。`monitoring_prevents_reenable` 恒为 false。诊断没有在运行时，挡不住有人再次启用一个失效代理；那是以后的持续监控或显式管理，不是这次的自动禁用。

样本字段 `macos_readonly` 的契约：

- `status`：`not_applicable`（不是 macOS）、`not_enabled`（macOS 但未打开）、`observed`（读完了，不是健康）、`partial`、`unavailable`。
- `report_is_health` 恒为 false。`actions` 恒为空。`mutates_network` 和 `uses_sudo` 恒为 false。
- `tailscale` 只保留 PR #4 的白名单。超限、截断、命令失败、非法文本是 `unavailable`；缺字段是 `unknown`。不会把 2000 字节前缀解析成 healthy。
- `routes.interface_discovery` 为 `dynamic`。没有配置 VPS 时 `tailnet_route_status` 是 `not_configured`。
- `system_proxy` 同时带 `sources.scutil` 和 `sources.networksetup`。`disabled_saved_address_is_fault` 为 false。`bypass_reset`、`auto_disable`、`monitoring_prevents_reenable` 为 false。已关闭但保存的本机地址在 `disabled_saved`。失效的已启用代理是高优先级 `dead_proxy`，不能被 Tailscale 连通结果抵消。
- `vps_tcp` 不保存主机地址，只保存端口、地址类别和指纹。未配置是 `not_configured`。单次 TCP 成功不等于业务稳定。

原第二阶段清单至此全部落地：开机自启已由常驻 daemon 提供（`scripts/nmd_daemon.py`，默认关闭、显式 `nmd macos daemon install` 安装）；配置生成与启动前快照由 `scripts/macos_prepare.py` 提供（离线与只读），单次有界接管由 `scripts/macos_takeover.py` 提供（sudo 前台、绝对截止），常驻接管与面板归属由 daemon 提供（无绝对截止，健康驱动回退与 panic 恢复，策略见 `DAEMON_POLICY`）。daemon 代码同样没有在实机运行。

Linux 的 `config.yaml`、默认采集命令和 `local-setup.sh` 不改。Windows 仍只做原来的检查，不把这套 macOS 命令搬过去。此次新代码没有在实机运行。过夜 23 秒窗口的根因未定。

## 配置生成（Phase A）

`scripts/macos_prepare.py` 的 `config` 子命令从实验 profile 加用户输入离线生成一份 mihomo 可加载的 YAML。它不跑 `mihomo -t`（CI 没有 mihomo 二进制；实机 `-t` 是后续阶段步骤），校验全部离线完成：复用 `macos_coexist` 的 `validate_experiment_profile`、`validate_rule_order`、`insert_overseas_domain_rules`、`find_hardcoded_utun` 和 `mihomo_would_load`。

- 输入：profile（默认 `examples/macos-mihomo-coexist.experiment.json`）+ inputs JSON（`server`/`port`，可选 `proxy_name`）。`server` 只接受 Tailnet 字面 IP（100.64.0.0/10 或 fd7a:115c:a1e0::/48）或恰好是文档占位 `203.0.113.20`；占位的锚点是服务器地址——用占位地址时端口须保持示例对 `1080`，真实 Tailnet 地址配任意合法端口（含标准 SOCKS `1080`）；端口 22 拒绝。
- 相对 Linux `config.yaml` 的 macOS 适配（`validate_document` 逐条断言）：删 `iproute2-*`、`device`、代理 `interface-name`、`mixed-port`/`external-controller`、文档占位网段 DIRECT、`PROCESS-NAME,tailscaled` 与 Ubuntu 联网检测域名；TUN 加 `dns-mode: native`（mihomo ≥ 1.19.33，macOS 默认 disabled 故显式写明）；`nameserver-policy` 不绑定接口。
- 真实地址永不进仓库：`--out` 拒绝仓库树内的路径，父目录 0700、文件 0600 原子写；仓库里只有占位版 `examples/macos-mihomo-takeover.inputs.example.json` 与黄金文件 `examples/macos-mihomo-takeover.example.yaml`（用 `--stdout` 刷新，字节级比对入测试）。输出确定性：无时间戳、固定键序。

```bash
PYTHONPATH=scripts python3 scripts/macos_prepare.py config \
  --inputs examples/macos-mihomo-takeover.inputs.example.json --stdout
```

## 启动前快照（Phase A）

`snapshot` 子命令按固定顺序只读采集系统状态，为后续幂等回退留证据：`netstat -rn -f inet/inet6`、`scutil --dns`、`scutil --proxy`、`ps -axo pid=,comm=`、`networksetup -listallnetworkservices` + 活跃服务（Wi-Fi 优先，≤8，跳过带星号）的 `-getdnsservers`、`tailscale status --json`，以及 `tailscale debug prefs`（ExitNodeID/ExitNodeIP/CorpDNS/RouteAll/ExitNodeAllowLANAccess/WantRunning——macOS 侧首个 prefs 读取，只读）。全部 argv 过本模块白名单后经 `macos_readonly.bounded_run` 执行；写 flag 与 `tailscale set` 在进程启动前就被拒绝。

- 快照文件保留真实值（exit node id、解析器、网关、代理端点），写在默认 `~/.local/state/nmd-monitor/`（尊重绝对 XDG_STATE_HOME；与来源注册表同一私有信任域）的 `pre-start-<UTC时间戳>.json`，目录 0700、文件 0600 原子写；检查与写入都作用在解析后的真实路径上，符号链接无法把文件重定向进仓库。
- stdout 只输出 `summarize_snapshot` 的脱敏视图：各段 status、计数、布尔和 exit node id 的 sha256 指纹，不回显任何地址。
- `takeover_ready` 记录三个前置判断：scutil 无 198.18、无 mihomo 进程、是否选定 exit node；缺哪段读不到就进 notes，不猜。`ps -axo pid=,comm=` 看全部用户，`comm` 是完整路径，匹配时只取 basename。不用 `ucomm` 或 `-c`（短名 16 字节会截断，`-c` 也不是同一列），也不按当前 uid 过滤（会漏掉 root，进程再涨仍会顶到上限）。只读上限是 1MiB，也是共享有界读取器的上限。一台进程较多的 Darwin 27 主机上，默认环境和 `LANG=C LC_ALL=C PATH=/usr/bin:/bin` 各跑两次都是 rc 0、约 20ms、stderr 空、stdout 78965 字节 / 853 行、合法 UTF-8；旧的 64KiB 上限读到 65537 字节后丢掉正文，快照变成 unknown。超过 1MiB 时同样整段丢掉，不把前缀当成完整观察。超时、非零退出、超限或正文不是合法 UTF-8 时，`mihomo_absent` 仍是 null，notes 同时有 `ps_unavailable` 和 `ps_timeout` / `ps_command_failed` / `ps_output_too_large` / `ps_invalid_text` 中对应的一条。这些记号不带进程列表。null 不是「没有 mihomo」，不能当作 ready。stdout 摘要的 `mihomo_running` 这时也是 null，不会写成 false。只有 `ps` 成功且列表里没有 mihomo 时，`mihomo_absent` 才是 true。快照只保留命中的 pid 和 basename。
- 后续阶段的回退只消费这份文件：复验 scutil 无 198.18 后恢复 exit node、allow-lan、accept-dns，按 services 恢复网卡 DNS（空列表即 Automatic）。exit node 传给官方 CLI 的是对端 Tailscale IP，没有 IP 时用 MagicDNS 基名；不用 prefs 里的 StableNodeID，也不用 `auto:any`。快照另记 `exit_node_cli`，status 当时读不到时回退用这个值。stdout 摘要不回显它。系统代理与 bypass 始终只读不回写。同秒重复回退的幂等风险继续由回退约束承担。
- 非 macOS 平台返回 `not_applicable` 且零命令。只读快照已在 Darwin 上核对过这条 `ps` 的体积。两分钟 accept 已在实机跑过；当时回退把 StableNodeID 传给 `tailscale set --exit-node`，官方 CLI 拒绝，后面的恢复步骤没有继续。这次修正还没有在实机复跑。

```bash
PYTHONPATH=scripts python3 scripts/macos_prepare.py snapshot [--state-dir DIR]
```

## 常驻守护（Phase C）

`scripts/nmd_daemon.py` 把接管做成 Paseo 式常驻守护：daemon 拥有状态与本地
API，UI 全是薄客户端。两个进程：root 管理器（`/Library/LaunchDaemons`，
launchd KeepAlive，持有 `/var/run/nmd-daemon.sock`，root:admin 0660）监督
接管——**无绝对截止**，替代语义是健康驱动回退（连续关键故障周期，默认 3，
可配）+ panic 恢复（mihomo 退出立即回退）+ 手动停止（IPC `takeover.stop`，
admin 组可用；面板按钮同路经）+ 开机策略（`daemon.json` 的 `on_boot`，默认
关；同 boot 的 KeepAlive 重启永不自动续接，防振荡）。用户 daemon（登录
LaunchAgent）监督采集线程（配置变更即重载）并常驻面板（复用
`DashboardServer`）；桌面壳经既有复用路径连接，不再 spawn。每次接管前——
包括开机——**重新快照**，新的一次接管不拿上一次的快照当切网前状态。切网前
把本次快照文件名写入 `rollback-pin.json`，再清 exit node；中途崩溃时回退用的
就是这份 pin（会话文件里的 `snapshot_name` 同一份），而不是清掉 exit node
之后新拍到的快照。root 启动时先按会话回收残留：
`active`、`starting` 和 `needs_rollback` 都先回退。回退结果不是
`rollback_restored`（native DNS 仍有 198.18、prefs 读不到、exit node 无法
安全写回、或某一块网卡 DNS 失败）时阶段留在 `needs_rollback`，管理器稍后重试
这一次恢复，**不会**因此再开一轮接管，`takeover.start` 在此期间返回
`rollback_pending`。恢复完成后也不自动再接管。原先的 `critical_failures` 等开机抑制结果在这次恢复里保留，不会被改写成 `recovered_leftovers`，因此 `on_boot` 不会在恢复刚完成时再开一轮接管。策略清单见
`macos_coexist.DAEMON_POLICY`；单次路径的 `ROLLBACK_POLICY` 不变，两者互斥靠
既有 preflight 双向失败关闭。健康检查含 Tailscale status 和配置里的 VPS SOCKS
TCP 连接；TCP 成功只说明端口接受了握手，不是应用成功，HTTP 200 不在这项检查里。
安装/卸载/生命周期：`nmd macos daemon install|uninstall|start|stop|restart|status|
takeover-start|takeover-stop`（收据独立 `daemonReceipt`，sudo 只用于 root plist 与
launchctl；面板只能停接管，启动需 `takeover-start` 的 uid-0 对端）。`restart`
等于先 `stop` 再 `start`；`stop` 失败则不 `start`。`stop` 会
`bootout` 系统任务，`start` 在 `kickstart` 发现任务未加载时用已安装的 plist
重新 `bootstrap` 再 `kickstart`。卸载同时 `bootout` 当前用户的 LaunchAgent。
示例配置 `examples/macos-daemon.json`（占位地址，install/start 拒绝占位）。
**`nmd update` 只更新磁盘代码，不重载进程。** 已安装守护时，`nmd apply`
（`refresh` 同义）若这次重载需要地理数据，先补齐缺少的文件，再做只读预检，通过后才执行 `nmd macos daemon restart`。
它不跑 Linux 的网络部署，不调用 `takeover-start`，也不改 `on_boot`。
预检失败则不 stop、不 sudo，待应用保留。若当时有进行中的接管，stop 会先按
快照回退，路由、DNS 或 Tailscale exit node 会变。若 `on_boot` 为 true，且
这次启动被管理器当成新的一次开机，它可能开始接管。会话若停在 active、
starting 或 needs_rollback，启动会先把那次回退做完。未安装守护时 `nmd apply`
只记录版本，不执行 sudo。`start` 会在任务未加载时 bootstrap，因此已安装但未
加载的 root 管理器会被 `apply` 拉起。用户 LaunchAgent 不在这次重载里。
显式只读入口是 `nmd macos preflight --tier readonly|daemon|takeover`：面板档
不要求 mihomo；守护档在 start/restart 之前；接管档在改网络之前。`fail` 和
`unknown` 都不继续。daemon 代码没有在实机运行。另一终端的
`sudo nmd macos rollback` 不拿管理器的锁：它读 pin，只在 `owned-mihomo.json`
里的 pid、`ps` 的启动时间、完整 argv（含精确的 `-d` 工作目录）和会话组
长身份同时对得上时才发信号，再按这份原始快照恢复。pid 被同名进程复用、
或启动时没记下启动时间时，不发信号。回退不删除 state 目录里已有的文件，
也不删除 pin 和快照。管理器进程没了、身份对不上、或者 198.18 一直清不掉时，
这次回退仍可能停在 `rollback_blocked_dirty_dns`；`ROLLBACK_POLICY` 里
`guarantees_restore_if_watchdog_dies` 和
`guarantees_restore_if_watchdog_and_sampler_die` 都仍是 false。常驻 supervisor
在墙钟相对单调钟向前跳时复查正在进行的接管：native DNS、IPv4 默认路由、exit
node 或系统代理漂移不对，就按本次 pin 回退。直接或已经回退的阶段不会因此再开
一轮接管，也不改 `on_boot`。系统代理仍然不写。这不是实机睡眠验收。

## 接管控制器（Phase B）

`scripts/macos_takeover.py` 把上面的实验落成仓库内的 sudo 前台控制器，经 `sudo nmd macos takeover|rollback` 或直接 `sudo python3 scripts/macos_takeover.py …` 调用（非 root 自动把自身交还 sudo 重跑）。变更面是封闭集合，逐一在 `mutating_allowlisted` 里把关后才执行：`tailscale set` 仅限 `--exit-node=`（空值表示清除）或 `--exit-node=<IP 或 MagicDNS 基名>`，以及 `--exit-node-allow-lan-access=true|false` / `--accept-dns=true|false`。StableNodeID、node key 和 `auto:any` 不在这个集合里，`networksetup -setdnsservers`，以及 mihomo 的 `-d <工作目录> -t -f <该目录下的配置>` 校验和 `-d <工作目录> -f <该目录下的配置>` 启动。配置必须是工作目录的直接子文件，不能是符号链接。系统代理与 bypass 永不触碰。

state 目录、mihomo 工作目录和 daemon 配置在写入或读取前按路径分量 `lstat`，不 `resolve` 整条路径。除了 root 拥有、且目标正好是 `/private/tmp`、`/private/var`、`/private/etc` 的 `/tmp`、`/var`、`/etc` 之外，任何祖先符号链接都拒绝。组或其他人可写只允许出现在 `/tmp`、`/private/tmp`、`/var/tmp`、`/private/var/tmp` 这四个 sticky 目录上；叶子目录本身有组/其他写位也拒绝。这挡的是替换父目录，挡不住检查返回之后的替换。

地理数据先由 `nmd macos geodata ensure` 补齐，再复制普通文件。复制来源是显式 `--geodata-dir`，否则是当前账户的 `~/.config/mihomo`。`sudo` 把 HOME 设成 `/var/root`，所以 euid 0 时不用 `Path.home()`：前台用 `SUDO_USER` 的家目录，launchd 没有这个变量，就用 daemon 配置文件所有者的家目录。ensure 要由这个账户自己运行，不要 sudo，这样写出来的文件和后面 root 复制的是同一目录。`--geodata-dir` 在规则来自 `--inputs` 或已安装 `daemon.json` 时都是写入目录。uid 0、目录是符号链接、祖先不安全、或缺账户时不复制任何文件。root 只在文件已经通过格式校验时继续，不会下载，也不会改权限。校验失败即零网络变更。显式传入的目录如果不安全，在任何变更之前直接报错。复制名单包含 `geoip.db`，避免只认这个别名时工作目录里没有 MMDB。

生成配置不写 `geodata-mode`。mihomo 1.19 的 `GEOIP` 因此读 MMDB：`geoip.metadb`，或目录里已有且带 MaxMind 标记的 `Country.mmdb` / `geoip.db`。`geoip.dat` 只在 `geodata-mode` 打开时使用，ensure 不下载它。空文件、网页或截断内容不会被当成已经备好；下载失败时原文件保持不变，并且这次启动、重启或接管不会继续。`GEOSITE` 读 `geosite.dat`（与 `GeoSite.dat` 大小写不敏感）。下载地址与 Linux `fetch-assets.sh` 相同，是 MetaCubeX `meta-rules-dat` `latest` 上的这两个文件，并用旁边的 `.sha256sum` 核对；Linux 脚本本身不改，也不做这项核对。规则没有对应前缀时不下载那个文件。已有合法文件时不访问网络。下载失败不会替换原文件，也不会进入 sudo、stop 或改网络。`preflight` 只报告，并给出这条命令。

一次 takeover 的顺序：确认 state 与 geodata 路径 → 生成配置并写入私有 state 目录 → 按上面的 argv 做 `mihomo -t`（失败即止，零变更）→ Phase A 快照与前置断言（scutil 已无 198.18、无 mihomo 进程）→ 把快照文件名写入 `rollback-pin.json` → 清 exit node → 启动自有进程组，并用 `ps -p <pid> -o lstart=,args=` 记下启动时间和完整 argv → 就绪轮询（native DNS 登记）→ watchdog（20 秒周期：Tailscale status + 经系统路径对 VPS SOCKS 的 TCP；TCP 成功不是应用成功；任一关键检查失败的周期记一次故障，连续 3 个故障周期回退；全过的周期重置计数）→ STOP / 到期 / 故障阈任一触发回退。绝对截止默认 10 分钟、上限 8 小时、到期不续期；Ctrl-C（SIGINT/SIGTERM）即回退。回退幂等：flock 序列化同秒重复回退，每步先读现状一致即跳过。独立 `rollback` 先读 pin（没有 pin 才用最新的普通 `pre-start-*.json`，跳过符号链接），再只在启动时间、完整 argv 和 `-d` 工作目录都与记录一致、且该 pid 仍是会话组长时发信号。对不上就不发信号。然后确认 scutil 无 198.18，再恢复 exit node、allow-lan（`=true`/`=false`）、accept-dns 和每块网卡 DNS。exit node 先按当时的 `tailscale status --json` 把 ExitNodeID 对上仍在通告出口的对端，取它的 Tailscale IP；没有 IP 才用 MagicDNS 基名。对不上时用快照里的 `exit_node_cli`，再不行用 prefs 里的 ExitNodeIP。这些都不是 CLI 接受的形式时记 `exit_node_unrestorable`，不把 StableNodeID 发给 `tailscale set`。`tailscale set` 非零时，stderr 的一行写进私有回退结果的 `failures`（凭据形如 `tskey-` 会抹掉），进程输出的 JSON 也带这个 `failures`；这一步失败不会跳过 accept-dns、allow-lan 和后面的网卡 DNS。198.18 还在时报 `rollback_blocked_dirty_dns` 并且不恢复 exit node。快照里没有可读 prefs 时不动 exit node。某一块网卡失败不会跳过后面的网卡，结果是 `rollback_incomplete`。回退不删除 state 目录里的已有文件、pin 或快照。运行记录与心跳写入同一 state 目录（`takeover-*.json`、`watchdog-heartbeat`）。

```bash
sudo nmd macos takeover --inputs /path/to/inputs.json --minutes 10 \
  --state-dir DIR --geodata-dir DIR
sudo nmd macos rollback --state-dir DIR
```

`--help` 和 `-h` 在参数校验和提权之前处理。`takeover --help`、`rollback -h`、`accept --help` 以及带了其它参数的 `--help` 都只打印帮助。认不出的选项同样直接退出，不会被当成一次接管。

## 两分钟验收

`nmd macos accept` 是固定 2 分钟的短时入口。它不改变上面默认 10 分钟、最长 8 小时的 takeover，不加载、不安装 launchd，不改 `on_boot`，也不停止已经在跑的 run-user。`--state-dir` 必须指向这次的私有目录，不能是 `~/.local/state/nmd-monitor`。普通用户可以先准备 inputs 和这个目录；sudo 之前若地理数据还缺，会先按上面的 ensure 补齐，sudo 之后只复制普通文件，并核对所有者、权限、祖先符号链接和路径，不从 PATH 找 sudo 或解释器。这次生成的配置把 `geo-auto-update` 写成 false，避免这两分钟里自动联网更新；其它生成路径和示例配置仍是 true。

### 谁把网络装回去

一次 `accept` 里，能把网络装回切网前快照的有四个角色。它们都不是平时的网络维护者；平时的出口由 Tailscale 自己保持。长时 `takeover` 不拉起独立 watchdog 和 sentinel，回滚只写在那个前台进程的 `finally` 里，这个进程被 SIGKILL 后只剩下人。常驻 daemon 不使用这条链：launchd 重新拉起 supervisor，由 supervisor 回收残留，没有 sentinel。

- 控制器还在时自己回滚。停止、SIGINT、SIGTERM、到期，以及它发现 watchdog 消失，都调用现有 `rollback`。SIGKILL 跳过 `finally`，这条不会执行。
- watchdog 是切网前拉起的独立进程，不在控制器进程组里。它确认 pin 和快照可读之后等待，直到两分钟到期，或者控制器进程消失，然后用这份 pin 调用同一个 `rollback`。它不监视 sentinel，也不处理自己的死亡。
- sentinel 只监视这个 watchdog。watchdog 还活着，并且还没超过到期后的 45 秒时，sentinel 不改网络。watchdog 中途退出时，sentinel 用同一份 pin 回滚，`trigger` 为 `watchdog_dead`。到期后再过 45 秒，仍没有一份 pin、绝对截止和 watchdog pid 都对得上的 `rollback_restored` 时，sentinel 把 watchdog 当成卡住并回滚，`trigger` 为 `watchdog_stuck`。watchdog 已经恢复成功时，sentinel 只记下 `watchdog_restored`，steps 为空，不再改网络。控制器已经死了而 watchdog 仍在工作时，sentinel 不动。
- 人在这三个进程之外。产品不通知人，accept 也不安装 LaunchDaemon，没有进程会把死掉的 sentinel 拉起来。watchdog 和 sentinel 都没了、网络仍处于接管状态时，人执行 `nmd macos rollback --state-dir DIR`。这条命令不依赖那两个进程还活着：读 pin，只停止身份对得上的 mihomo，确认 scutil 里没有 198.18，再按快照恢复 exit node、allow-lan、accept-dns 和网卡 DNS。198.18 还在则结果是 `rollback_blocked_dirty_dns`，不改 exit node。官方回滚没有把出口装回去时，人再执行 `tailscale set --exit-node=<IP 或 MagicDNS 基名>`。

`guarantees_restore_if_watchdog_dies` 不参与分支，在代码里固定为 false，并写入 ready 和 result。`restore_sentinel_armed` 为 true 只表示 sentinel 的握手成功。只杀掉 watchdog 时 sentinel 会恢复，这个结果不能把字段改成 true。watchdog 和 sentinel 一起死掉时，产品里没有进程会恢复。`guarantees_restore_if_watchdog_and_sampler_die` 同样固定为 false。

2026-11-19 的一次 accept 中，watchdog 和 sentinel 被一起杀掉。随后的观察里两份 result 都没有写出，出口保持被清掉，198.18 仍在，mihomo 仍在跑。观察结束后，还活着的测试调用者执行了上面的 `rollback`，结果为 `rollback_restored`。产品自己没有恢复。

任何网络变更之前，一个已经是 root、且不在控制器进程组里的 deadline 进程必须写好 ready，并且 ready 里的 pin 就是变更前钉死的快照。同一个握手还要确认第二个独立进程 restore sentinel。watchdog 或 sentinel 起不来、握手失败、或 ready 不是明确的 true，就零网络变更退出。控制器被杀掉后，watchdog 仍按最初的 pin 调用现有 rollback。watchdog 在回退完成前退出（崩溃、被杀、异常退出，或过了宽限仍没有这一轮的 `rollback_restored`）时，sentinel 用同一份 pin 调用现有 rollback。上一轮留在同一目录里的 `rollback-watch-result.json` 和 `rollback-sentinel-result.json` 会在拉起子进程之前删掉；符号链接或不是普通文件就零变更。只有 pin、绝对截止和 watchdog pid 都对得上，才算这一轮已经恢复。控制器若还活着，发现 watchdog 消失也会走这条回退。回退一开始先记下 engaged；控制器若还想继续清 exit node 或启动 mihomo，会在变更前停住。完成前用现有 rollback 核对恢复。身份对不上的 mihomo 不发信号。重复 rollback 仍是幂等。exit node 仍只按官方 CLI 接受的形式恢复：对端 Tailscale IP、MagicDNS 基名、快照里的 `exit_node_cli`，再不行用 prefs 的 ExitNodeIP。StableNodeID、node key 和 `auto:any` 不会传给 `tailscale set`。

sentinel 自己也是一个普通进程。accept 不安装、不加载 LaunchDaemon，也没有进程外的 KeepAlive 会在 sentinel 死后把它拉起来。因此 watchdog 和 sentinel 一起死掉时恢复仍没有保证，`guarantees_restore_if_watchdog_dies` 保持 false，`guarantees_restore_if_watchdog_and_sampler_die` 也保持 false。冲突只看 root supervisor 的 `/var/run/nmd-daemon.sock`，以及这份 state 目录里仍在跑的 watchdog 或 sentinel。inode 存在或 `lstat` 失败就在改网络前退出。这个套接字由 root `supervise` 监听，不是 run-user 采集器创建的。只读的 user LaunchAgent、以及磁盘上有但未加载的 system plist，都不构成冲突，验收不会停它们。

验证：读私有 state 里的 `rollback-watch-ready.json`、`rollback-sentinel-ready.json`、`rollback-pin.json`、`rollback-watch-result.json`、`rollback-sentinel-result.json` 和 `takeover-*.json`。这些文件不包含 inputs。失败：进程非 0；握手没完成时没有 tailscale 或 networksetup 变更。取消：Ctrl-C，控制器回退，watchdog 发现父进程消失后再做一次幂等回退。回退：`nmd macos rollback --state-dir DIR`。清理：只删除这次的私有 state 目录。

```bash
sudo ./nmd macos accept --inputs /PATH/TO/inputs.json \
  --state-dir /PATH/TO/private-accept-state \
  --geodata-dir /PATH/TO/isolated-geodata-copy
```

`1b8cc38` 上的两分钟 accept 已在实机跑过。截止后的自动回退，以及随后的手动 rollback，都停在 `tailscale set --exit-node=<StableNodeID>`：官方 CLI 1.104.6 只接受 IP、基名或 `auto:any`，空字符串才是清除。清除本身在同一条 sudo 路径上成功过。当时 stderr 被丢掉，用户只看见 `mutation_failed`，后面的恢复步骤没有继续。上面的修正把参数改成对端 IP 或基名，并在失败时留下原因。这次修正还没有在实机复跑。离线测试覆盖握手前零变更、控制器消失、deadline、取消、部分失败、重复回退、身份不符、ready 未知、exit node 必须用 CLI 接受的参数恢复、watchdog 异常退出时 sentinel 回退，以及注入时钟下的唤醒复查。不启用常驻切网，不安装 launchd，不改 `on_boot`。睡眠唤醒有了离线行为。下面的实机记录不是通过：`sleep_wake_verified` 仍是 false，常驻 residency 没有测。

### 2026-11-18 实机记录（`b83d27a`）

已观察，不是假设：

- 23:38:55（Asia/Shanghai）杀掉 watchdog 和控制器之后，只剩 sentinel。结果 `trigger` 为 `watchdog_dead`，steps 非空，没有 `rollback-watch-result.json`。网络回到 `utun5` 上的 `vm-vmiss`，没有残留测试进程。`guarantees_restore_if_watchdog_dies` 仍是 false：watchdog 和 sentinel 一起死的情况没有覆盖。
- 23:54:18 开始 accept，绝对截止 23:56:18。`pmset -g log` 和 `log show` 的 powerd 记录：23:54:24 因 Software Sleep（pid 21904）进入睡眠，23:54:44 从 Deep Idle（rtc/HID）唤醒，这个窗口里没有 DarkWake。睡眠发生时 mihomo 已就绪（scutil DNS 里有 198.18）。23:54:59 控制器以 `wake_restore` / `rollback_restored` 退出，`wake.reasons` 只有 `proxy_drift`。随后网络回到 `utun5` / `vm-vmiss`，系统代理关闭，MagicDNS 在，测试进程清掉，生产 run-user 没有被动过。
- 快照 `pre-start-20261118T155418Z.json` 模式 0600。`proxy.status` 为 `observed`，`protocols` 为 `{}`，`bypass` 为 `[]`（空内容的 sha256 前 16 位是 `e3b0c44298fc1c14`）。顶层键是 bypass、protocols、reason、status。对应的 enabled 表是 `{}`。
- `takeover-20261118T155459Z.json` 的 `wake` 只有 `action=rollback` 和 `reasons=['proxy_drift']`，没有当时的 expected/live 表。`restore_sentinel_armed` 为 true。
- 23:59:26，也就是回退大约五分钟之后，再读 `scutil --proxy` 只有 `FTP passive : 1`，没有 `*Enable` 键，enabled 表是 `{}`。三个接口的 networksetup HTTP/HTTPS/SOCKS/自动代理都是 Enabled: No。这不是 23:54:59 那次判定用的读数。

代码能确定的只有这些：当时 `proxy_drift` 只在两边的表都不是未知、而且用整表 `!=` 比不相等时出现。快照的表是 `{}`，所以判定当时的现场表是另一个字典。现场表本身没有留下来。

未证实，不能当成原因：现场表可能是一组显式 `Enable : 0`（和缺键一样，没有协议在启用），也可能是一次短暂的 `Enable : 1`，到 23:59:26 已经消失，也可能是解析出了没有布尔标志的行。这三种都会在旧比较里走出不同的路，现有文件分不开。这次睡眠验收因此不算通过。

这次代码改的是比较本身，不是补写当时的现场表：成功读到的缺键和显式 false 都不当成启用变化；读失败或标志不可读仍是 `proxy_unknown` 并回退。新的 `wake.proxy` 会留下两边的布尔表。要在新的 head 上再做一次真睡眠才能验收，常驻 residency 也还没有测。

## 回退约束

Phase B 起，`scripts/macos_takeover.py` 把下面的清单实现为 sudo 前台控制器，`implemented_in_this_repository` 已为 true。清单本身不变，控制器同样未在实机运行：

- 先做快照，独立 watchdog 确认存活之后才切网。`accept` 还要 sentinel ready，否则零变更
- 绝对截止时间。短测 10 分钟，过夜最长 8 小时，到期不续期。截止按墙钟，睡眠不把会话延长
- STOP 或到期都回退。只结束自己的进程
- 清掉 native 动态 DNS 后，确认 scutil 里不再有 198.18，再恢复原来的 Tailscale exit node、allow-lan、accept-dns 和网卡 DNS
- 不改系统代理，也不改 bypass。比较的是已经启用的协议。一次成功的 `scutil --proxy` 里，缺键和显式 `Enable : 0` 都表示没有启用；读失败、输出不是 dictionary，或某一行没有布尔 `enabled`，记 `proxy_unknown` 并回退，不把它们当成 false。真正从关到开、或从开到关，仍是 `proxy_drift`。唤醒记录只留两边的 enabled 布尔表和 status/reason，不写服务器、端口或 bypass
- 连续 3 次关键故障才回退
- 不自愈循环，不安装 daemon 或自动启动，不改电源设置
- 睡眠唤醒之后仍按绝对截止时间计算。唤醒后重读 native DNS、IPv4 默认路由、exit node 和 scutil proxy；托管状态仍正确就继续，不对就按 pin 回退。`takeover-*.json` 的 `wake.proxy` 只含 enabled 布尔表和 status/reason
- 不保证 watchdog 自己死掉之后一定能恢复。sentinel 还活着时会回退；两个都死掉之后，产品里没有进程恢复，要由人执行 rollback。字段固定 false，见「谁把网络装回去」
- 不保证 watchdog 和采样进程都被杀掉之后还能恢复

## 合并前与之后

合并前至少要满足：静态测试和架构检查通过；证据矩阵仍把用户隔离配置、本 PR 静态/CI、本 PR 实机分成三列；示例 JSON 仍然不能被 mihomo 直接加载。本 PR 代码尚未在实机运行的范围见上文：共存实验、回退和这次的代理交叉读取都还没有实机复跑。是否合并由用户决定，CI 变绿不自动合并。

这些还没有完成，也不阻塞把上面的纯函数当作下一步的开发基线：

1. 在本仓库代码上再跑一次 Mac。用户隔离配置的结果不能代替它。App 实际发送仍没有由本 PR 观察。
2. 只读采集在 `4044472` 上做过一次部分验收。代理交叉读取已于 2026-11-19 复跑，缺键不再把关闭的代理盖成未知。同秒两次 restore 的幂等风险仍在；仓库实现尚未验证。
3. 睡眠唤醒的实机验收。2026-11-18 的那次睡眠是真的，但控制器因 `proxy_drift` 回退，而判定当时的代理表没有留下，所以不算通过。CI 仍只覆盖注入时钟。还要在写入 `wake.proxy` 的新 head 上，于 accept 会话中和常驻 residency 中再睡眠再唤醒，核对路由、DNS、系统代理（只观察、不写回）和 exit node。`sleep_wake_verified` 仍是 false。常驻 residency 还没有测。
4. 真实 IPv6。无 AAAA 不是故障，`curl -6` 的 IPv4 映射不算通过。
5. 过夜 23 秒 1080 窗口的根因。短测没有复现，也不等于修复。不启动 SSH。

Linux CI 通过不能标成 macOS 运行通过。这条 PR 保持 draft。
