# NMD 诊断与切换运维 Runbook

本页面向 Linux 日常运维与 macOS 源码诊断，按当前代码说明观察、配置、运行动作和恢复。
安装与部署细节仍由 [主 runbook](../runbook.md)、[来源契约](egress-sources.md)、
[诊断 MVP](mvp.md) 和 [macOS 说明](macos.md) 管理。本文的实测范围见第 6 节；
出现命令不等于已做真实主机演练。

## 1. 动作、权限与副作用

| 标记 | 含义 | 边界 |
| --- | --- | --- |
| R：业务只读观察 | 不改变保存的业务配置或运行出口 | 可以联网、创建管理锁或校验临时文件，必须看下表；不等于文件系统零写入 |
| C：本地保存 | 写来源、策略、Git 元数据、安装文件或诊断历史 | 不等于即时切换；启用/恢复策略后，已经运行的采集器可能在后续周期切换 |
| N：运行/网络动作 | 启停服务、开本地监听、发探测，或改变真实出口/部署 | 下表区分“仅探测”“本地服务”“修改出口”，不能一概理解为部署 |
| B：恢复用途 | 对 C/N 的后果做有目标的恢复 | 是用途标记，不是互斥类别；再次保存、联网或切换的副作用仍存在 |

权限中的“管理者”指 user 安装的本人，或 system 安装的 root；system 管理使用
`sudo /opt/nmd/nmd ...` 的明确入口。读取 system 诊断 SQLite / GUI 则必须使用
`nmd-monitor` UID，不能以 root 替代该身份。不要给 user 安装加 sudo 来“切换 scope”。

以下管理命令以安装元数据完整为前提；旧安装缺失 scope 会被拒绝，需显式 adopt，
不会自动补记。未安装源码的快照/帮助可独立使用；读取快照时明确指定私有状态目录。

| 命令或入口 | 标记 / 本地写入 | 联网或运行影响 | 权限 / 恢复 |
| --- | --- | --- | --- |
| `nmd help`、`source --help`、`monitor --help` | R，帮助 | 不部署、不探测 | 源码帮助不需管理员；已安装 source/channel 帮助仍先校验管理者身份 |
| `nmd monitor status`、`nmd machine status --state-dir DIR` | R，只读已有 SQLite；不存在返回 no_data，不建目录 | 无探测 | 数据所属 UID；无需恢复 |
| `nmd monitor config-check --config FILE` | R，只校验配置 | 不探测 | 能读取配置的 UID |
| `nmd status`、`nmd version` | R；状态读取，要求有效安装记录 | status 读本机服务/Tailscale/DNS/路由；不做外网验证 | 管理者 |
| `nmd monitor service-status` / `logs` | R，但会创建/打开管理锁 | 查询 systemd / journal，不启停服务 | 管理者；不是诊断 SQLite 快照 |
| `nmd check` | R，但创建临时配置/provider/日志，可能含私有来源；正常退出清理 | 调用本地 mihomo 校验，不覆盖运行配置；需现有资产 | 管理者；不要传播临时原始内容 |
| `nmd verify`、可选 `nmd diagnostics` | R/N，仅探测 | 真实 DNS/HTTPS/出口或配置的设备探测；不部署、不 PUT selector | 管理者；仅在允许外网探测时使用 |
| `nmd source list` / `nodes` / `export`、`nmd channel auto status` | R，脱敏离线视图 | 不测速/切换 | 管理者；未安装源码可使用显式私有 sources-dir |
| `nmd source status [--offline]` | R | 默认 GET 回环 selector；offline 不查控制器，active 不能当实时值 | 管理者 |
| `nmd source delay <完整节点ID>` | R/N，仅测速 | 经本地控制器触发核心真实联网；固定 URL/超时，不改变 selector | 管理者；失败码不能单独证明节点故障 |
| `nmd update --check` | C，写管理锁、Git 对象与远端引用 | git fetch；不切换当前代码、不 apply | 管理者；不是零写入预览 |
| `nmd update` | C，同上并快进代码、记录 pendingApply | 不自动 apply 或重启 monitor | 管理者；无自动代码回滚 |
| `nmd source add/update/remove`、`nmd channel rename` | C，来源与缓存 | 不即时探测、部署或切换 | 管理者；删除/连接变化可能丢缓存，见第 3 节 |
| `nmd source refresh <id> --fixture <YAML>` / `--confirm` | C，成功写缓存 | fixture 离线；confirm 用 HTTPS，2 MiB / 20s 预算且不跟随重定向；Linux GUI「更新订阅」按钮走同一 confirm 后端 | 管理者；失败保留旧缓存与选择 |
| `nmd source select <节点ID> --defer` | C，保存期望，暂停已启用策略 | 不即时 PUT | 管理者；再选可覆盖保存值 |
| `nmd channel auto enable/disable/set-candidates/resume` | C，写策略 | 不即时 PUT；下一采集周期可能恢复探测与切换 | 管理者；disable 关闭，set-candidates 保留 enabled/paused 并重置评估 |
| `nmd install` / `monitor install` | C，安装/修复采集单元与配置 | 不 start/enable，不部署网络 | 管理者；uninstall 保留配置与历史 |
| `nmd monitor start/stop/restart/enable/disable` | N，本地采集服务 | start/restart 后会写历史，并按配置探测/自动评估；enable 不等于 start 或 lingering | 管理者；对应停止/启动操作仍需检查状态 |
| `nmd gui` | N，启动回环 HTTP 服务 | 不启动采集器；Linux 浏览页面会轮询 sources 并 GET 本地控制器；按钮另可保存通道/策略、更新订阅、测速或切换 | 诊断数据 UID；停止进程关闭面板，不撤销按钮已完成的动作 |
| `nmd demo --once` / `nmd demo --port 8765` | C，创建临时合成 SQLite；后者另有 N 本地监听 | 不采集本机、不读私有来源，正常退出清理 | 无 sudo；不是零文件写入 |
| `nmd monitor run --config FILE --state-dir DIR [--once]` | C/N，前台采集并写历史 | 读取本机元数据；主动探测由 config 决定；Linux 的 sources-dir 可启用自动评估 | 数据所属 UID；Ctrl-C 停止，已有历史保留 |
| `nmd source select <节点ID> --confirm` | C/N，保存并 PUT selector | 改变已部署节点的运行出口，回读确认；不重启服务 | 管理者；回切需重新确认原节点 |
| `nmd apply` / 顶层 `nmd refresh` | C/N，系统部署 | 可下载资产、更新配置/DNS/服务；与 source refresh 不同 | root；失败保留现场，见第 4 节 |
| 顶层 `start/stop/restart/enable/disable` | N，mihomo 生命周期 | 不等于 monitor 服务；启停可影响流量 | root；stop 保留 Tailscale |
| `nmd cutover/rollback/test-stop` | N/B，旧模式切换或停机演练 | 真实 exit node/服务影响；test-stop 尽力恢复但恢复可能失败 | root；有来源注册表时 cutover/rollback 拒绝 |

源码边界：[manager.py](../scripts/manager.py)、[local-setup.sh](../local-setup.sh)、
[egress_sources.py](../scripts/egress_sources.py)、[observability.py](../scripts/observability.py)。
`machine capabilities` 描述平台能力；实际面板还须看 `/api/capabilities` 的有效能力。
Linux GUI 有保存 Channel、重命名、更新订阅、策略、测速、选择六类 POST 路由；macOS 和 demo 拒绝这些写/控制请求。

## 2. 从已有证据开始

先确定 scope 和数据身份。以下是已安装 user 模式的常用读取入口，不包含部署或测速：

```bash
nmd monitor status
nmd source status --offline
nmd channel auto status
```

system 模式按第 1 节分别选择管理者和诊断数据 UID；不要把所有命令放进一个 sudo 会话。
需要本机服务/路由信息时读 `nmd status`；需要外网证据时再显式执行 verify 或单节点 delay。
打开 GUI 会启动本地服务，Linux 页面还可改变配置或出口，不属于上述严格读取序列。

解释原则：fresh 只说明采样新鲜，不代表目标健康；desired 是保存值，active 是控制器观测值。
连续 3 次 failure 确认 incident，连续 2 次 success 确认恢复。unknown/skipped 不计失败或恢复；
已有打开 incident 时会将片段以 `end_reason=observation_gap` 结束并写探测 gap。
主动探测 timeout 在采集器中属于 failure，不能与控制器测速故障的处理混为一谈。

## 3. 六类故障的处理路径

### 3.1 Tailnet 断连

1. R：先读 status、已有时间线，区分服务、DNS、尾网对端与出口节点；需要联网证据时再
   R/N 执行 verify，或在授权环境用 `tailscale ping <对端>`。直连/DERP 的证明边界见
   [对端验收](../runbook.md#对端路径的验收边界)。
2. 仅节点失败：核对 auto_events 与 active 是否已切到更低优先候选；未启用自动策略时，
   先确认接管候选已部署且可用，再 N 手动 select --confirm。回切也是新的显式选择。
3. 整个 Tailnet/DNS 不可达：不要通过清空路由/防火墙来试错；按 Tailscale 和本机网络
   排查。[独立 DNS/控制路径](../runbook.md#避免-tailscale-与-vps-循环依赖)是部署目标，
   须由实际观测确认，不能因配置存在就宣称正常。

`test-stop` 是真实停机演练，不是 Tailnet 修复命令；远程连接依赖该路径时不要试运行。

### 3.2 订阅刷新失败或来源变化

1. R：用 source list/nodes 确认来源、缓存和已保存选择。`subscription_source_not_found`
   表示不存在可刷新的订阅来源；核对 ID 与 kind。
2. `subscription_fetch_failed` / `subscription_timeout`：检查实际 DNS/路由和对端；刷新
   没有主动绑定 tailscale0，但仍依赖当前网络，不能保证 Tailnet 断连对其无影响。
3. `subscription_http_error_no_redirects`：非 200 或重定向；核对私有定义中的 HTTPS URL。
   `subscription_too_large`、YAML 结构/重复节点错误、缺 PyYAML 的固定错误分别按
   [来源契约](egress-sources.md#范围依赖与私有数据)处理，勿将原始订阅或凭据贴进日志。
4. `selected_node_would_disappear_choose_another_first`：刷新会删掉保存选中的节点，先明确
   另选再刷新。刷新失败不写缓存；刷新成功也不更新运行中的部署。
5. C：连接定义更新会重建/失效对应缓存；仅改 display_name 保留缓存。删除保存选中的
   来源会拒绝；删除非选中的自动候选来源，或改变候选来源 kind，会原子清除整个 auto
   策略，需重新配置。相同 kind 的更新保留 pin，缓存候选缺失时挂起。

删除与连接更新没有缓存撤销历史；先保留必要的私有定义，恢复需要 add/update 与刷新。

### 3.3 候选失败、控制器故障与自动策略停顿

先读 auto status、source status 与采集器 auto_events；CLI delay 可以补充一次主动测速，
但对外统一的 `delay_test_failed` **不能区分节点失败与控制器故障**。服务 active 也不能排除
控制器鉴权、路由或响应格式错误。每周期按优先级探测全部候选（2..8 个，最坏约 N×6 秒），
新鲜度窗口随候选数加宽。

| 观测 | 当前行为 | 后续处理 |
| --- | --- | --- |
| `controller_unreachable` | 当前评估无法获得有效控制器/测速证据；探测故障不推进失败、恢复或冷却计数，不发切换 PUT | 检查核心/控制器，不据此判候选失效；恢复后继续评估 |
| `all_unhealthy` | 全部有效候选探测均失败；同一连续窗口只首次发事件，不 PUT，保留 target 与失败/恢复计数；冷却周期计数仍每轮 +1 | 保持现状，检查共同通道/上游；恢复有效证据后按迟滞/冷却继续 |
| `auto_suspended` / `auto_resumed` | 候选从缓存消失时挂起，恢复后继续 | 核对刷新和节点身份；不会自动把新节点补成候选 |
| `paused=true` | 手动选择（含 defer）暂停已启用策略，不改候选 | 确认后 C 执行 auto resume；已有采集器下一轮可能切换 |
| `auto_switch_failed` | 切换失败，包含 PUT 前的节点未部署等拒绝 | 按事件 reason 定位；该事件本身不代表已经发出 PUT |
| pending_verify | 仅在 selection_outcome_unknown_read_status_before_retry 后记录待确认目标 | 先读实际出口；自动侧协调回读，不盲目重试或回退 |

内部当前按固定 mihomo 版本将节点失败/超时响应与传输、鉴权、协议/畸形响应分开；
实现与回归见 [Controller.delay / auto_evaluate](../scripts/egress_sources.py)、
[test_auto_state](../tests/test_auto_state.py)。这不改变 CLI 的安全错误码。
`controller_unreachable` / `auto_error` 连续同类同细节通常按 300 秒抑制重复记录；
正常周期后再次失败会立即记录，时钟倒退也不能靠“最多一条”推断没有新问题。

若确有其他可用且已部署的缓存节点，可 N 手动选择接管；它会暂停自动策略。
自动策略只控制本机 selector，不能证明整机所有流量或业务均可用。

Linux 回环 GUI 的「一键排查」按钮把本节矩阵自动化为一次固定分层探测电池并返回固定
结论码（分层目标、决策树与限制见[来源契约](egress-sources.md#一键分层排查gui)）；
它只覆盖固定公共目标，是对本节人工流程的快速分诊，不替代本节矩阵，GUI 本身不可达时
仍按本节 CLI 流程排查。

### 3.4 no_data、stale 与空窗

- no_data：读 monitor service-status/logs，确认是否安装并启动采集器。install 不 start；
  GUI 不启动采集。需要启动/重启时按 N 本地服务操作处理。
- stale：对照最后采样时间、预期周期和 gap，不直接判断网。周期变长、采集停止、休眠或
  时钟倒退都可能影响新鲜度；user 服务是否在退出登录后运行还取决于 lingering 等配置。
- `collector_restart` 是重启缺口；`sleep_or_clock_jump` 包括异常采样间隔或 wall/monotonic
  偏差；`probe_unknown:<id>` 是打开 incident 遇到 unknown/skipped 后的探测缺口。
  `observation_gap` 是 incident 的结束原因，**不是 gap reason**。
- fresh 但看不到某条历史：GUI/快照默认读取最近 100 行，另受 retention_hours 与
  max_samples 限制；每个探测和本机样本各占一行。空窗无历史补写命令，不能算成已确认
  断网或成功时段。

存储详情见 [保留与资源上限](mvp.md#保留与资源上限)。当前 samples 时间索引会在可写
Store 打开旧库时幂等创建；行数与时间窗口取交集，仍保留开口 incident 的例外。
索引增加磁盘占用和首次打开/整批过期成本，不会自动 VACUUM；旧 reader 仍可读取。
不要为排查 stale 直接删 SQLite、删索引或放宽目录权限。

### 3.5 user / system 范围混淆

`nmd status` 显示 scope、管理目录、版本与待应用状态，不保证输出 configDir/stateDir。
下表是默认值；user 路径可能受安装时 XDG 设置影响，实际以安装记录为准。

| 项 | user | system |
| --- | --- | --- |
| 管理 checkout / 命令 | `~/.nmd` / `~/.local/bin/nmd` | `/opt/nmd` / `/usr/local/bin/nmd` |
| 配置 / 历史 | `~/.config/nmd` / `~/.local/state/nmd-monitor` | `/etc/nmd` / `/var/lib/nmd-monitor` |
| 单元 | 用户 systemd | 系统 systemd，采集身份 nmd-monitor |

管理命令 system 用 root；读取历史/GUI 则以 `nmd-monitor` UID。GUI 不能读取 root 私有
来源时显示未配置/不可用，不放宽权限。需要迁移时按
[scope 迁移流程](../runbook.md#旧安装与-scope-迁移)处理：保留旧数据，不直接 mv checkout，
不跨 UID 复制或递归 chown 历史；卸载不会自动搬迁数据。

### 3.6 macOS 能力缺失

macOS 支持源码 help/version、demo、monitor config-check/run/status、gui 和 machine
capabilities/status；Linux 安装/更新、source/channel、网络管理、systemd 动作、desktop
均提前拒绝。这里“只读诊断”指不管理网络/系统服务，前台采集仍会写私有历史。

需要一次本机观测时，源码命令必须包括配置，例如
`./nmd monitor run --config examples/monitor-local.json --state-dir <私有目录> --once`。
该示例 probes 为空，不做主动目标探测，但会读取本机元数据并写 SQLite；不属于本次
文档校验的执行项目。完整前置条件见 [macOS 单次观测](macos.md#可选显式本机单次观测)。
服务字段 unsupported_platform、缺命令/不可观测字段应保持 unknown，不猜测健康。

## 4. 恢复与回滚边界

| 情况 | 处理方向与验证 |
| --- | --- |
| 误保存选择/策略 | C：再次保存、disable 或恢复原候选；resume 后已有采集器可能行动 |
| 误切出口 | B/N：确认原节点仍可用且已部署，再 select --confirm；回读 active 并按需要 verify |
| `node_not_deployed_apply_first` | 缓存节点未部署；先核对期望配置，再决定是否显式 apply，不能把 apply 当无条件重试 |
| `selection_outcome_unknown_read_status_before_retry` | 先 source status 读实际选择，再决定下一动作；不直接连发 PUT |
| apply 失败或中断 | 保留 pendingApply 和私有现场，按具体错误恢复；`.initial-deploy-pending` 的首次部署续接见 [README](../README.md#网络部署恢复与可选探测) |
| 错误部署配置 | 核对 root 私有 config.yaml.previous，修正来源期望后再显式校验/apply；备份可能含凭据，不公开 |
| 代码更新后异常 | 无自动代码回滚；人工 Git 处理前保存改动和明确版本。回退代码不回退已部署网络配置；P02 索引可残留，旧读取器兼容 |
| 卸载 monitor/desktop | 保留已有代码、配置、历史；只删除所属单元/链接或桌面产物，不撤销网络部署 |

旧单 VPS 模式的 cutover/rollback、test-stop、vps-setup.sh 和 live_proxy_failure.py
需要真实主机条件与独立授权，不能作为普通文档检查执行。远程操作应先有备用连接。
恢复验收依据应是实际状态、出口与所需探测结果，不仅是命令退出 0。

## 5. 事件与源码索引

- auto_switch、auto_switch_failed、auto_verify_adopted、candidate_changed、
  manual_engage：见 [自动评估](../scripts/egress_sources.py)。
- all_unhealthy、controller_unreachable、auto_suspended/resumed：处理路径见第 3.3 节。
- incident、gap、新鲜度与保留：见 [Store / read_snapshot](../scripts/nmd_monitor.py)、
  [时间线回归](../tests/test_timeline_metrics.py) 与 [monitor 回归](../tests/test_monitor.py)。
- 源码与管理安装的命令边界：见 [manager.py](../scripts/manager.py)、
  [安装/迁移说明](../runbook.md#管理安装与-monitor-范围)。

## 6. 已验证与未验证（2026-10-25）

集成提交 `bdfecdc` 包含 fixture 权限修正、控制器故障分类、T03/T04、P02 和参考模型修复。
其 [push CI](https://github.com/zzzhty/network-monitor-and-diagnostics/actions/runs/40171069256)
中，Ubuntu 24.04 全套、macOS 显式模块、三个平台的桌面壳静态/单元测试及 Chromium
合成页面均通过；Ubuntu 22.04 的 4 个断言失败揭示 P02 在 SQLite 3.37.2 上的保留回归。
该失败记录仍保留，不能用较新 SQLite 的通过结果替代。

本次兼容修复以该提交为起点：在同一写事务内先读取删除前第 N 新的样本 ID，再按固定
边界和时间窗口删除；不足 N 行时仅按时间清理。表、索引和 schema_version 均未改变。
已有回归增加“最新 N 行全部过期但更早行仍在时间窗口内”的场景，防止回填旧样本。
Linux 本地使用 Python 3.14.4 + 临时编译的真实 SQLite 3.37.2，以及 Python 3.13.15 +
SQLite 3.53.1，两个环境各自 **45 项 monitor/timeline 测试通过**，完整套件各自
**317 项：316 passed / 1 skipped**；Python 语法检查通过。默认跳过的浏览器项由单独
CI 作业负责。修复提交的远端验收应查看对应 SHA 的 Actions 结果；CI 现在打印实际
Python/SQLite 版本。macOS 的显式模块列表仍未包含 T03/T04 两个新模块。

性能沿用原合成 Store 测量：20,160 / 100,000 行，每个引擎六轮不同顺序比较 P02 前基线、
已推送版和修复版，各执行 128 个周期。每组单调时间回放的完整语义行/metadata 相同，
旧 reader 与重复打开检查通过；异常时间顺序的正确性另由上述回归验证。

| 10 万行，六轮中位数 | SQLite 3.37.2：已推送版→修复版 | SQLite 3.53.1：已推送版→修复版 |
| --- | --- | --- |
| Store.record | 3.20→1.61 ms | 2.84→1.26 ms |
| record p95 | 3.54→1.84 ms | 3.15→1.42 ms |
| 整批样本过期 | 43.7→45.2 ms | 37.6→45.1 ms |
| 首次打开旧库（含既有索引创建） | 10.8→10.7 ms | 10.1→9.8 ms |

两版合成库大小相同（17,752,064 B），仍比无索引基线大约 7.8%；reader 耗时接近。
P02 前基线 record 分别约 24.3 / 27.6 ms，修复保留稳态收益，但没有消除索引空间、
首次打开和大批过期成本；OFFSET 仍遍历最多 N 个 ID，不是常数复杂度。
只在各自相同运行时内比较，不能把两种 Python/SQLite 的绝对时间差归因于引擎版本，
也不能推导整机、GUI 或其他平台提速。

执行记录仍在仓库外 `.glm53-batch/integration-steps-0-2/RESULT.md`；本次日志使用
`logs/p02-fix-*`，测量输入和输出在 `p02-sqlite-fix/`。原 D02 报告、首次 CI 失败和此前
红灯/绿灯、step3 性能记录均保留。

未验证：真实 Tailnet/订阅/出口切换、apply/首次部署/停机或崩溃恢复、user/system 实机安装
与跨 UID 迁移、桌面壳原生 GUI 运行、macOS 实机观测与长期运行。Chromium 合成页面通过
不代表真实部署浏览器验收；跨平台桌面壳编译/单元测试不代表完整 NMD 网络管理支持。
