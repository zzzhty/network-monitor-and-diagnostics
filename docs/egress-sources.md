# 可扩展出口通道（Channel）

通道管理复用原来的 source 注册表、缓存、控制器和部署流程；`nmd channel` 是
`nmd source` 的兼容别名，两者操作同一份私有数据，没有第二套代理引擎。

## 领域模型

- **Channel（通道）**：有稳定 ID 和可重命名显示名称的出口来源，可添加多个同类通道。
  持久字段仍名为 `sources`，Channel ID 就是原 source ID。
- **Node（节点）**：某个通道中可选择的实际代理出口，有稳定匿名 ID；当前出口显示到节点。
  手工通道包含一个 SOCKS5 节点，订阅通道包含显式刷新所得的节点集合。
- **Policy（策略）**：独立于通道类型的 2..8 个按优先级排序的明确候选及迟滞、恢复、冷却
  参数。可以混用订阅与手工代理，甚至同一通道内的多个不同节点；新通道不自动入选。

| 通道 kind | 节点协议 | 连接路径 |
|---|---|---|
| `subscription` | 沿用现有支持的订阅节点协议 | 普通路由，不导入订阅的网卡/路由覆盖 |
| `proxy` | SOCKS5 | 普通路由（例如公网 VPS），不绑定 tailscale0 |
| `tailnet` | SOCKS5 | 仅 Tailnet 字面 IP，强制绑定 tailscale0 |

Tailnet 通道不是 Tailscale exit-node 管理。新增普通路径不会放宽原 Tailnet 地址/接口
约束；普通手工代理也拒绝 Tailnet 地址、IPv4 映射的 Tailnet 地址和带作用域接口的 IPv6。
第一版手工通道使用 IP 字面地址，不解析主机名，不引入新 VPN 协议框架。

Linux 回环 GUI 可添加/重命名通道、显式更新订阅、选择已部署节点、单节点手动测速或显式
开启策略。**添加、刷新、部署、选择是四个独立动作**：保存配置不下载订阅、不测速、不部署，
也不切换或启用策略。订阅刷新在 GUI 通道行显式发起（等同 CLI `--confirm` 的真实 HTTPS
下载）或由 CLI 执行；连接定义更新/删除及网络部署仍由 CLI 显式执行。
macOS 与 demo 始终只读，不读取私有来源，也不允许 Channel 配置写入。

## 范围、依赖与私有数据

| 内容 | user | system |
|---|---|---|
| 私有来源注册表及节点缓存 | 安装时记录的 configDir/egress/sources.json，默认 ~/.config/nmd/egress/sources.json | /etc/nmd/egress/sources.json |
| 管理身份 | 安装所有者，不加 sudo | root，显式系统安装 |
| 实际网络配置 | 显式 apply 部署到 /etc/mihomo，与 monitor scope 分开 | 同左 |

未安装的源码使用绝对 `XDG_CONFIG_HOME/nmd/egress`，否则为 `~/.config/nmd/egress`。
安装后遵循已记录的 scope/configDir，后来更改 XDG 不会移动来源。代码更新和 monitor
卸载保留这些文件；不把它们放进 checkout，不能通过复制目录隐式切换 scope。
源码可在 `source` / `channel` 的操作子命令前用 `--sources-dir /绝对/私有目录` 隔离测试；管理安装
不注册此选项，分隔与等号形式均拒绝。所有来源参数要求完整拼写，不接受缩写。
路径不得含符号链接或 `..`；macOS 的临时路径先通过 `pwd -P` 取得实际路径。

订阅 YAML 解析及来源运行配置生成需要 **PyYAML 6.0.3**，声明在
`requirements-sources.txt`。缺少时返回 `yaml_dependency_missing_PyYAML_6_0_3`；程序不会
自动安装依赖。monitor 和没有来源注册表的旧配置流程继续仅使用标准库。

来源目录为 0700，注册表、导入定义和节点缓存为 0600，拒绝不安全权限、符号链接、
硬链接和不可信祖先。订阅 URL 仅在注册表内；命令只接受私有定义文件，不接受 URL
命令行参数，避免 shell history / 进程参数泄露。不要把真实定义、生成配置、缓存、
备份或核心原始日志提交到 Git。来源 ID 应使用公开安全的别名，不要包含凭据。

list / nodes / status / export 和 GUI 只返回固定字段：来源 ID、类型、缓存数量、节点
ID、刷新时间和控制器状态。URL 固定显示 `[redacted]`；不显示用户名、密码、服务器地址、
控制器密钥或原始错误。通道显示名称（`display_name`）与节点可读名称（`display`，导入时的原始标签）**仅**出现在回环 GUI
与本机 `nodes`/`status` 输出；`export`、`list`、部署产物（provider JSON、控制器与核心
日志）继续只含匿名 `nmd-<来源>-<摘要>` 名。摘要计算排除通道 `display_name`，并且节点 `display` 在摘要生成后附加；相同定义重新刷新不会改变
节点 ID；`render_runtime` 写入 provider 前剥离该字段。`source export` 是脱敏诊断 JSON，
不能恢复秘密。`nmd logs` 在来源模式不输出可能含凭据的核心原始日志。
首次写入注册表生成随机控制器密钥；只部署到回环控制器，不存入 Git 或系统钥匙串。
需要改变控制器端口时，只在私有注册表的 controller.url 中设置字面回环 HTTP 地址
（127.0.0.1 或 ::1）；密钥至少 32 字符，不能含换行。CLI 不跟随控制器重定向。

## 最小操作闭环

下列为功能用法，涉及真实网络的 apply/select --confirm/refresh --confirm 需在有权操作
的 Linux 主机执行；本次 Mac 开发验收只用临时目录和合成 fixture，没有执行这些真实操作。

先把 examples/sources/ 下两个模板复制到 checkout 外的私有位置，设为 0600，在本机
编辑器填写真实值。不要把 URL 贴进终端参数、聊天、Issue 或 PR。手工来源格式为：

```json
{"kind":"tailnet","server":"<YOUR_TAILNET_IPV4>","port":1080,"udp":true,"expected_egress_ip":"198.51.100.10"}
```

模板中的 `<YOUR_TAILNET_IPV4>` 必须先换成自己的地址，未填写的模板不能导入。
server 必须为 Tailnet IPv4 / IPv6 字面地址；可选 username/password，协议为 SOCKS5。
每个手工节点是一个来源，添加多个来源即可配置多个 VPS。只有这种来源添加
`interface-name: tailscale0`；订阅节点不继承该绑定。

普通路径的手工代理模板见 `examples/sources/proxy.json`：

```json
{"kind":"proxy","display_name":"公网 VPS","server":"192.0.2.20","port":1080}
```

普通代理不含 `interface-name`，拒绝回环、链路本地、组播、未指定地址及 Tailnet 地址；
支持可选 username/password/udp。表中 IP 是文档合成地址，不代表可用代理。
所有类型均可选 `display_name`（1..128 字符、无控制字符），缺省显示稳定 ID。

订阅定义为 `{"kind":"subscription","display_name":"订阅一","url":"https://..."}`，可选 expected_egress_ip。
只接受 HTTPS 443，不支持 URL userinfo、跳转、私有请求头和环境代理；单次显式刷新只
获取指定来源，20 秒总体读取预算、10 秒连接/闲置超时、响应最多 2 MiB。错误不输出 URL
和响应内容。Clash provider YAML 或完整 Clash YAML 都只提取 `proxies`，随后写入本地
JSON provider 缓存；订阅不能覆盖 DNS、TUN、规则、监听地址、控制器或分流组。

```bash
nmd source add tail-a --file /private/location/tail-a.json
nmd source add tail-b --file /private/location/tail-b.json
nmd source add sub-a --file /private/location/sub-a.json
nmd channel add proxy-a --file /private/location/proxy-a.json
nmd channel rename sub-a --name "订阅显示名称"    # 不改变 ID、缓存、选择或候选
nmd source list                            # 旧命令仍可用
nmd source refresh sub-a --fixture /path/to/synthetic-provider.yaml  # 离线 fixture
# 获授权后，真实订阅刷新使用：nmd source refresh sub-a --confirm
nmd source nodes
nmd source select nmd-tail-a-匿名摘要 --defer  # 使用 nodes 实际返回的完整 ID
nmd source status --offline
# 获授权的 Linux 主机：nmd apply
nmd source status                          # 仅 GET 本机 selector，不测速
# 已部署节点，显式改变运行中出口：
nmd source select nmd-sub-a-匿名摘要 --confirm
nmd source delay nmd-sub-a-匿名摘要        # 单节点手动测速（见下）
nmd channel auto enable --node "$PRIMARY_NODE" --node "$SECONDARY_NODE"  # 显式候选（可重复 --node），见下
nmd source export                          # 仅脱敏 JSON
```

通道重命名不改变节点 ID，既有无显示名称的配置继续使用原摘要输入。连接/凭据变化会改变
对应匿名节点 ID；只有同一来源和相同连接/节点定义才保留 ID，
不同来源的同名节点不会冲突。可读名称（display）只在回环 GUI 与本机 nodes/status 中
显示，不进入部署面；节点选择始终使用完整节点 ID。支持 socks5/http/ss/ssr/vmess/
vless/trojan/hysteria/hysteria2/tuic/snell/anytls 的常用节点字段；不导入文件证书、拨号代理链、
网卡/路由标记和未知顶层字段。具体核心协议支持仍由部署时 mihomo -t 校验。
YAML 重复键、别名、锚点、自定义标签、空节点列表或超出 256 个节点直接拒绝。
本版不支持 Base64 URI 订阅和自动订阅转换。

增删改、刷新和 `--defer` 只修改私有来源数据，不重启、重载或写系统网络配置。
所有已配置订阅必须先显式刷新，并显式选择一个缓存节点后，才允许 apply。
apply 在私有临时目录生成配置并校验实际部署字节；通过后部署无 URL 的 file providers，
health-check=false，无 interval。核心不会另行下载订阅或定时测速。节点文件使用内容
摘要命名；旧运行配置引用的文件不会被本次部署覆盖。config.yaml、provider 文件和
config.yaml.previous 都可能含凭据，必须私有；旧 provider 文件为回退证据保留，确认不再
被当前或 previous 配置引用后才能人工清理，update/uninstall 不负责删除。
核心校验输出只写入新建的 0700 临时目录内的 0600 文件，校验结束即清理，不使用安装
目录中的固定日志路径；原始错误被抑制，CLI 给出脱敏失败。生成运行配置是私有部署输入。

`--defer` 保存下一次 apply 的初始顺序；运行中实际选择以控制器 GET 为准。
`--confirm` 只向指定回环 selector PUT 所选缓存节点，并读取确认；不关闭现有连接、
不重启任何服务。PUT 后确认失败会报告结果不确定，先读取
status 再决定下一步，不自动重试或回退。新节点尚未部署时拒绝运行中选择。

## 单节点测速

`nmd source delay <节点ID>` 与 GUI 的测速按钮通过回环控制器调用核心对 provider 成员的
单节点测试路由（`GET /providers/proxies/{provider}/{节点}/healthcheck`；provider 成员不在
核心全局代理表中，`/proxies/{name}/delay` 对它们不可用）：
探测地址固定为 `https://www.gstatic.com/generate_204`，超时 5000 ms，均不可由客户端指定。
节点必须存在于缓存清单；测速结果只有毫秒数或固定失败码 `delay_test_failed`，不透传核心
错误文本。没有批量测速、没有后台定时测速；核心 provider 的 health-check 保持关闭。

## 一键分层排查（GUI）

Linux 出口控制 GUI 的「一键排查」按钮触发 `POST /api/egress/diagnose`（严格空体），
把 [诊断手册 3.3](diagnostics-runbook.md#33-候选失败控制器故障与自动策略停顿) 的手工
故障矩阵自动化为一次并行固定电池：四个固定公共目标的系统路径 HEAD 探测（curl，
`--proxy ''` 不走环境代理，各自 `--max-time 8s`，总预算约 15 秒）、每个自动策略候选的
单节点 healthcheck（与测速按钮同一控制器路径），以及对 Tailnet 通道 `server:port` 的
3 秒原始 TCP 连接（Tailnet 地址被路由排除在 TUN 之外，因此这是真正的绕行探测）。

| 层 | 目标（服务端常量） | 验证的路由层 |
|---|---|---|
| direct_foreign | connectivity-check.ubuntu.com | 本机直连外网（规则 DIRECT） |
| egress_cn | www.baidu.com | 国内直连（GEOSITE,cn → DIRECT） |
| egress_foreign | www.cloudflare.com | 真实出口链路（MATCH → 所选节点） |
| egress_exit_ip | 1.1.1.1（无 DNS） | 同一出口链路的出口侧判别 |
| candidate_health | 各候选节点 | 控制器单节点 healthcheck（毫秒或失败） |
| node_tcp | 仅 Tailnet 通道 server:port | 原始 TCP（ok/refused/timeout） |

非 Tailnet 通道的 server 本身经 TUN 路由，原始连接不能作为绕行证据，固定跳过并返回
原因码 `server_routed_through_tun`。结论由对结果字典的纯函数决策树计算（无网络参与，
可离线单测），固定码如下；GUI 为每个码显示一行中文提示：

| code | 触发条件 | 含义 |
|---|---|---|
| `egress_healthy` | 全部层成功 | 出口链路健康 |
| `local_internet_down` | direct_foreign 失败 | 本机直连外网故障，与节点无关 |
| `controller_unreachable` | 任一候选探测遇控制器故障 | 控制器问题，绝不记为节点失败（同自动评估语义） |
| `node_service_down` | 全候选失测 + Tailnet TCP 拒绝 | 节点服务疑似停机 |
| `node_network_unreachable` | 全候选失测 + Tailnet TCP 超时/不可达 | 到节点的网络路径不通 |
| `exit_dns_poisoned` | 候选失测 + 出口 IP 可达 + 域名层失败 | 疑似出口侧 DNS 污染 |
| `egress_degraded` | 全部成功但 egress_foreign > 3000 ms | 中继路径劣化 |
| `egress_anomaly` | 未命中上述组合的失败 | 转诊断手册 3.3 人工排查 |

限制：探测目标为固定公共常量，不接受任何客户端输入；响应只含固定字段、取整毫秒与
匿名节点 ID，不包含节点 IP、URL、原始 curl 输出或控制器错误文本；端点只读私有注册表、
从不写入，也不改变 selector。单次探测成功只代表该次观察；该电池是 3.3 矩阵的快速分诊
子集，GUI 或面板本身不可达、需要系统性取证时，仍按
[诊断手册 3.3](diagnostics-runbook.md#33-候选失败控制器故障与自动策略停顿) 人工排查。

## 自动故障切换（可选，需手动开启）

策略显式保存 2..8 个互不相同的完整节点 ID，按优先级排序，与通道 kind 无关；`source`
引用字段继续表示稳定 Channel ID。先通过 `nmd channel nodes` 取得实际 ID，再设置命令中
的变量：

```bash
nmd channel auto enable --node "$PRIMARY_NODE" --node "$SECONDARY_NODE" --node "$THIRD_NODE" \
  --fail-after 3 --recover-after 2 --cooldown 2
nmd channel auto enable --nodes "$PRIMARY_NODE,$SECONDARY_NODE"  # 逗号列表等价
nmd channel auto status
nmd channel auto set-candidates --node "$SECONDARY_NODE" --node "$PRIMARY_NODE"  # 启用后直接替换有序列表
nmd channel auto disable
nmd channel auto resume           # 仅清除手动暂停，不重新挑选节点
```

`fail_after` 默认 3、`recover_after` 默认 2、`cooldown` 默认 2，均为 2..10。
GUI 用候选行编辑器维护同一份有序列表（增删/上下移，上限 8），启用后保存即
`set-candidates`；保存通道不会调用自动策略接口。采集器启动/启用仍是独立操作，
配置策略不会启动 monitor 或安装服务。

评估器仍在已有监控采集周期内工作：每周期按优先级顺序探测全部候选（最坏情况约
N×6 秒，新鲜度窗口随候选数加宽），保留失败迟滞、恢复迟滞、切换冷却与全部不健康时
不动的行为。当前候选连续失败满 `fail_after` 且冷却已过时，切到最高优先的其他健康
候选；更高优先候选恢复满 `recover_after` 时回切上去（同一周期只对最高优先的健康
上游计数，避免多上游振荡）。控制器传输、鉴权、路由或响应格式故障不作为节点失败：
发出 controller_unreachable，本轮不推进失败/恢复/冷却计数，也不 PUT。全部候选有效
探测均失败时发出 all_unhealthy，保留 target 和失败/恢复计数，但冷却周期仍递增。
CLI delay_test_failed 是统一安全码，不能仅据此区分两类故障。
任何自动切换仍在实际 writer lock 内重验策略、
暂停状态、期望选择和完整候选清单，再走 PUT + 回读；过期决策不执行 PUT。
结果不确定时保持 pending_verify，先协调实际观察与保存选择，再按恢复规则回切。

手动选择任何节点（含 `--defer`）都会暂停已启用的策略，且**不替换候选**；明确
`auto resume` 后才继续。手动 PUT 结果不确定也先持久化暂停，再返回未知结果，
保留原 desired 供后续只读核查，避免自动策略抢回。节点从缓存消失时挂起，恢复后才继续。
没有全节点测速或负载均衡；备用深度上限为 8 个显式候选，新增通道/节点不会自动进入
探测集合。

策略只控制本机 mihomo 选择器，不代表整机所有流量或 AI 业务可用。系统级服务账户
仍无权读取 root 私有注册表，不放宽权限。事件写入 `auto_events`，GUI 展示实际节点、
候选序与暂停状态。评估器在持久化 runtime 上派生只读 `state`（paused / suspended /
pending_verify / all_unhealthy / engaging / active / failing / recovering）与
`cooldown_remaining`（距切换解禁的剩余周期数），随既有 `collector.auto_runtime`
整包导出，不新增平行字段；GUI 据此展示引擎状态与冷却进度。无健康数据或控制器不可用
时不能伪造成功。

### 旧配置与 CLI 兼容迁移

外层注册表继续为 `schema_version: 1`、`sources` 和 `cache`；新策略为 `auto.version: 3`，
`candidates` 为 2..8 个有序 `{"source": ChannelID, "node": NodeID}`。旧 `tailnet` /
`subscription`（v1）策略先按原 `primary` 顺序转换为 v2 主备，再映射为
`candidates[0..1]`；v2 `primary`/`secondary` 策略同样取前两位。enabled、paused、
selected 和阈值不变。list/status/export/GUI GET 只返回内存视图，不写盘；下一次显式
写操作才在同一 writer lock 内原子提交迁移。自动切换/确认仍可更新实际选择，但不借此
改写旧策略的存储格式。旧（v1/v2 时代）运行状态摘要也可识别：升级后首周期原地把
runtime 翻译为 v3 形态（target 转为候选序号、计数映射到 fails/recover），既不重置
计数，也不触发多余的接管 PUT，未决切换确认保留。

节点 ID 不因新增显示字段而变化；重命名保留缓存，显示字段从摘要输入排除，原摘要保持
兼容。同连接定义的 display-only update 也不清缓存。通道 ID 不提供重命名操作。

v3 移除旧主备专用载荷与动作：`--primary/--primary-node/--secondary-node/
--tailnet-node/--subscription-node`、`swap` 与 `set-primary` 一律拒绝并返回
`auto_legacy_payload_removed`；同类候选用显式 `--node/--nodes` 与 `set-candidates`。
持久迁移后，旧版程序不理解 v3 策略及新增通道字段；需要回退程序时，应使用已确认的
私有配置备份。

```bash
nmd source update sub-a --file /private/location/replacement.json  # 连接定义变化会清缓存；只改显示名则保留缓存
nmd source refresh sub-a --fixture /path/to/synthetic-provider.yaml
nmd source remove sub-a
```

当前保存的节点要消失时，刷新和删除来源会拒绝；先显式选择另一个节点。
更新定义可能使保存的选择失效，此时 apply 拒绝，必须重新选择。最后一个来源删除后
注册表仍保留，apply 会拒绝空来源；不会悄悄切回旧 VPS 或 DIRECT。
删除或改变一个自动候选来源的 kind 时，会在同一次注册表写入中清除整个自动策略，
不论策略当前是否启用；需要重新显式配置并开启。保存选中来源的删除仍会拒绝，
同 kind 的定义更新仍保留 pin，候选缓存缺失时自动模式挂起。注册表写入前验证引用。

自动评估的策略与期望选择在实际 PUT 所属 writer lock 内重新核对；探测期间完成的
停用、手动暂停、候选或策略变化使旧决策失效，不执行旧 PUT。不确定切换的实际出口
确认也在此锁内协调并持久化，避免旧期望状态覆盖新观察，随后按恢复迟滞正常回切。

来源管理与网络 apply 各自有锁；来源变化后仍需显式 apply。来源 status 的 desired 与
active 分别代表保存的选择和实时控制器选择，不能把“保存成功”当成“已经切换”。

## 验收与回退

国内、LAN、Tailnet、tailscaled、Tailscale 控制面、bootstrap DNS 和 MagicDNS 的原有
独立路径保留，LAN/链路本地地址也明确排除 TUN。订阅不能删除这些保护。
来源模式 verify 不要求旧的固定 VPS 在线，也不使用 NMD_VPS_PUB 作为所有出口期望值。
它在 HTTPS 出口探测前后读取当前 selector；选择未知、配置未应用、控制器失败或探测
期间选择变化时不能确认验收。配置 expected_egress_ip 时，只对当前来源比对；不匹配
失败。不配置时明确返回 `https_observed_identity_unpinned`，仅说明 HTTPS 探测观察，
不证明出口身份或整机所有流量均经过该节点。无论结果如何，AI 业务始终为 not_tested。
provider health check/delay 即使以后单独启用，也只能表示其测试目标的连通性。

- 手工 Tailnet 来源：故障时显式选择另一节点，或启用自动切换由其接管；不能假定所有
  SOCKS5 VPS 都是 exit node。若要恢复某个来源的 Tailscale exit node，需另行确认它
  提供 exit-node 能力并人工操作。
- 订阅来源：没有对应的 Tailscale exit-node 回退。手动选择已部署的其他来源，或由自动
  切换在候选之间接管，再验证；不将健康检查或其他来源 IP 视为该订阅的业务可用证明。
- 没有来源注册表：兼容原有单 VPS 配置、NMD_VPS_PUB、cutover/rollback 和 DERP 降级说明。
  一旦存在注册表，旧的固定 VPS cutover/rollback 拒绝执行，避免恢复错误的 exit node。

GUI `/api/sources` 复用同一后端（GET，含所属用户可读名称，仅回环）。固定 POST 路由为：

- `/api/channels`：严格 `{id, definition}`，只调用 source 保存；URL/凭据只进私有注册表。
- `/api/channels/rename`：严格 `{id, display_name}`，只更新显示元数据。
- `/api/channels/refresh`：严格 `{id}`，仅订阅通道；复用 CLI `--confirm` 后端，对已存
  私有 URL 做一次真实 HTTPS 下载并重写缓存，无 fixture/force/apply 等附加参数。
- `/api/egress/diagnose`：严格空体 `{}`（拒绝任何字段）；执行一次固定分层探测电池
  （见下节），只读私有注册表并只向固定公共目标发探测，不写任何配置或选择。
- `/api/egress/select`、`/api/egress/delay`、`/api/auto`：显式选择、单节点测速与策略配置。

请求体仍为 ≤4096 字节的严格字段 JSON；不接受任意文件、命令、接口覆盖或 apply/force
等附加参数。Host、Origin、Fetch-Site、固定路径和 macOS 平台拒绝均适用于新路由。公开响应不回显
订阅 URL、server、用户名、密码、控制器密钥或原始错误；节点/通道名称仅 owner-local。
`channel_management` 仅在配置了来源的 Linux GUI 为 true；`network_mutations` 仍为 false。
配置保存权限不是系统网络设置授权；订阅刷新是对固定私有 URL 的单次显式动作，保存
表单本身不触发下载、测速、切换、部署或自动策略。
system GUI 无权读取 root 私有来源时仍显示未知，不放宽权限。

## 开发验收

```bash
python3 -m unittest discover -s tests -p 'test_egress_sources.py' -v
python3 -m unittest discover -s tests -p 'test_*.py' -v  # Linux CI 全套
bash -n install.sh nmd fetch-assets.sh local-setup.sh vps-setup.sh
node --check web/app.js
```

新增测试只使用私有临时目录、合成 YAML/JSON、HTTPS 传输替身和 127.0.0.1 mock 控制器。
覆盖来源 CRUD、选择/刷新边界、脱敏、权限、模板直连保护、显式手动控制、自动切换状态机、
单节点测速和 GUI 受限写端点。
本次 Mac 不安装 NMD、不提权、不改真实 VPN/Tailscale/Clash/路由/DNS/系统服务/网络权限
或持久凭据，不访问真实订阅，不做外网测速。systemd、真实核心配置/协议、TUN、服务
生命周期和真实出口/AI 业务仍需在另行授权环境验收；离线 CI 不是这类实机证明。
