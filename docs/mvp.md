# Network Monitor & Diagnostics (NMD)：只读观测 MVP

命令入口仅为 `nmd`；旧版入口不再提供。
这是一层附加的诊断能力，不替换现有 mihomo / Tailscale 运维命令。持续诊断进程、
CLI 和 GUI 相互独立：关闭 GUI 不会停止监控；mihomo 停止时仍可收集本机信息。
当前 GUI 以本机浏览器界面为主；`apps/desktop/src-tauri` 提供实验性 Tauri 桌面壳
（窗口、托盘、自动切换系统通知，见 [desktop.md](desktop.md)），逻辑仍唯一由
Python 拥有。Windows 适配器与桌面打包属于后续工作，本版不宣称跨平台网络管理已经完成。

macOS 源码诊断、状态存储及只读面板已加入实验支持，见 [macOS 使用说明](macos.md)。
Linux 与 macOS 的本机信息通过 `scripts/nmd_platform.py` 隔离，采集周期、SQLite、事件、
空窗与 HTTP API 继续共用。下述 systemd 与网络管理部分仅适用于 Linux。
`./nmd demo` 提供自动清理的临时合成数据演示，始终显示模拟标识，不运行真实采集。

## 能力边界

- 默认只读收集 Linux 接口名称和 operstate、IPv4 路由表指纹及默认路由条数；
  固定查询 mihomo、tailscaled、systemd-resolved 三个服务的加载 / 活动 / 子状态。
  服务查询有 2 秒超时和输出大小限制，不主动联网，不启动、停止或重启服务。
  缺少 systemctl、权限不足或查询失败表示观测不可用，不等于网络故障。
  接口存在、路由表有默认路由或服务 active，都不能单独证明联网可用。
- 可显式启用指定目标的主动探测；每种探测只证明对应检查的结果。
- CLI 可独立读取监控快照；GUI 不需要持有生命周期管理权限。
- 不自动切换家庭 / 办公室 / 应用代理模式，不改 DNS、路由、TUN、系统代理、
  Tailscale exit node 或 mihomo 配置，不自动修复、重启服务。
- install / monitor install 现在安装独立 monitor 单元；update 只更新代码，不隐式部署网络。
  apply / refresh 是显式网络部署入口。顶层 start / stop / restart / enable / disable /
  logs 仍管理系统 mihomo，monitor 前缀才管理采集器。verify 与旧 diagnostics 可能主动
  联网，不能与默认本地采样混为一谈。见 [README](../README.md) 和 [runbook](../runbook.md)。

## 从源码目录使用

需要 Python 3.9+；本机信息收集支持 Linux 与实验性 macOS 适配器。下列命令直接使用源码中的入口，
不要求运行原有 install.sh，也不需要部署 mihomo 或修改系统网络。

```bash
./nmd monitor config-check --config examples/monitor-local.json
./nmd monitor run --config examples/monitor-local.json --state-dir /tmp/nmd-monitor-demo --once
./nmd monitor status --state-dir /tmp/nmd-monitor-demo
./nmd machine capabilities --state-dir /tmp/nmd-monitor-demo
./nmd machine status --state-dir /tmp/nmd-monitor-demo
```

持续采样在前台运行，Ctrl+C 结束；关闭读取快照的 CLI 或 GUI 不影响这个独立进程：

```bash
./nmd monitor run --config examples/monitor-local.json --state-dir "$HOME/.local/state/nmd-monitor"
```

在另一个终端打开本机界面：

```bash
./nmd gui --state-dir "$HOME/.local/state/nmd-monitor" --port 8765
```

GUI 仅绑定本机回环地址，不提供公网监听选项。不要通过反向代理、端口转发或共享
状态目录把诊断信息公开。无需运行 GUI 即可保留监控，也无需启动监控即可读取已有快照。
可选[出口来源](egress-sources.md)通过 `/api/sources` 显示脱敏来源、节点可读名称与控制器
所报选择；「出口节点」页提供节点切换、单节点手动测速与自动故障切换开关（受限 POST
端点，与 CLI 同一后端，键集固定且不接受客户端指定测速地址）。Linux 另有仅保存私有配置的通道添加/重命名表单；它不刷新、探测、部署或切换。
订阅刷新、删除/改连接与部署仍只在 CLI 中执行；其余路径的写方法继续拒绝。系统 GUI 无权读取 root 私有来源时
显示未知。监控采集器以 `--sources-dir` 启动（用户级 unit 由安装器自动附加）时，会在
每周期内评估自动切换并把事件写入 `auto_events`；采集器自身永远不因评估失败中断，
周期预算按评估耗时扩展以保持新鲜度判定准确。CAPABILITIES 的 `read_only_gui` 因此为
false，`local_egress_control` 与 `channel_management` 为 true，`network_mutations` 仍为 false
（网络部署不变）。macOS/demo 两项管理能力均关闭。主备为任意两个明确节点，手动选择
统一暂停策略，不自动替换候选；兼容迁移与稳定 ID 见出口通道文档。

## 场景配置不是网络模式

examples/monitor-*.json 是声明式诊断配置，而不是网络部署配置。

- monitor-local.json：默认本机采样，不含外部主动探测。
- monitor-home.json：家庭场景探测模板，主动探测默认禁用。
- monitor-office.json：办公场景探测模板，主动探测默认禁用。
- monitor-application-proxy.json：应用代理相关目标的诊断模板，主动探测默认禁用。

未填写 enabled 的主动探测默认启用；模板为每项明确写了 enabled=false。
application-proxy 中的 127.0.0.1:7890 也是待核实的本机端口示例，不会自动启用。

模板中的 192.0.2.0/24、198.51.100.0/24 和 203.0.113.0/24 地址仅作示例，
不是可用的服务地址。使用前先复制模板，替换成你有权测试的实际目标，再把需要检查项的 enabled 从 false 显式改成 true，并运行 config-check。不要把启用所有示例项当成部署步骤。

主动探测可包含 DNS 查询、TCP 连接、TLS 握手及 HTTP HEAD 请求，对端或 DNS 服务
都可能看到并记录请求。HTTP 检查不跟随重定向；不读取响应正文。
本地状态收集不会自行上传日志或诊断记录；启用探测并不代表整个过程完全离线。
接口、目标、错误信息可能包含私有网络信息，分享诊断文件前应先检查和脱敏。
应用代理端口可连接不证明代理协议、出口 IP、分流规则或所有应用都能正常工作。
path=system 表示遵循系统当前内核路由，可能仍经过 TUN；它不保证物理直连或绕过
mihomo。path=proxy 只用于 HTTP 探测且需要显式 proxy 地址，不继承环境代理设置。
DNS / TCP / TLS 只支持 system 路径。URL 不支持凭据、查询参数或片段；不要在配置中
放密码或令牌。HTTP 探测需要 /usr/bin/curl，其余探测使用 Python 标准库。

DNS / TCP / TLS 每次探测只调用一次系统解析；TCP 按解析结果顺序尝试多个地址，
共用 `timeout_seconds` 总预算，TLS 握手只使用剩余预算。系统解析调用无法由 socket
超时中断，仍由父进程在 `timeout_seconds + 0.5` 秒终止整个探测进程组。
成功时的 `dns`、`connect`、`tls`、`total` 都是从探测开始算起的累计秒数，与 HTTP
计时含义一致；`tls - connect` 才是 TLS 阶段耗时。DNS-only 保留单独的 `dns` 字段。
超时报告 `timeout`，证书校验失败报告 `tls_verify_error`，其他握手错误报告 `tls_error`；
错误结果不保存目标、底层异常文本或部分计时。

## 解释结果

不能把“未能观测”当成“网络断开”。缺少系统命令、权限不足、未配置的目标、禁用探测、
尚无样本或过期样本都应按具体状态理解，不能据此判断 VPS、Tailscale 或互联网故障。
一次成功也不是端到端可用性的保证。时间线只是采样证据，不是未经验证的根因判定。

### 状态、事件与时间缺口

本地接口枚举成功是 observed，不代表联网成功，也不代表其他本地查询全部成功。
需分别检查 interface_states、route_fingerprint 和 services / service_observation_error。
路由指纹只能辅助发现表内容变化，不包含完整路由明细；默认路由计数仅覆盖 IPv4。
主动探测分别为 success、failure
或 unknown；enabled=false 的项目显示 skipped / disabled，不执行探测。连续 3 次失败确认一个事件，连续 2 次成功确认恢复；确认时刻与首次失败 /
首次恢复时刻分别记录。unknown 不计为失败，也不能充当恢复证据；已有未结束事件
遇到 unknown / skipped 时按 observation_gap 结束片段，不记为恢复。采集器重启、休眠
或时钟跳变会记录观测缺口；缺口会结束旧事件片段，不能把未观测时段算作已确认断网。

collector.state 中的 no_data 表示尚无数据，stale 表示最近采样不够新，fresh 仅说明
采样时间足够新，不等于所有探测健康。CLI 与 GUI 默认显示各类最近最多 100 条记录，
不是全量历史导出。

### 保留与资源上限

配置默认每 30 秒采样、单探测超时 5 秒，最多 16 个主动探测。探测依次执行，因此
较多或较慢的目标会使实际采样周期变长。retention_hours 默认 168 小时，
max_samples 默认 100000。每次采样按时间窗口和各表的行数上限同时清理，先触发的
限制生效；尚未结束的事件保留到结束，不受此项清理影响。每个探测和本机样本各占一行，并非每轮只占一行。要保留完整 24 小时，
需按样本数配置上限并留余量，不应只看 retention_hours 的数值。
`auto_events` 同时受相同的时间窗口和每表行数上限限制；清理后新事件 ID 仍严格递增，
不回退桌面通知游标。相同 `controller_unreachable` / `auto_error` 故障最多每 5 分钟
记录一次；正常评估后再次故障会立即记录，不把重复周期当作新故障。

本机 SQLite 数据库保存在 --state-dir 下。目录必须属于当前运行账户且仅该账户
可访问，文件同样使用私有权限；读取快照的 CLI / GUI 必须以同一账户运行。未安装的源码默认路径
为绝对 XDG_STATE_HOME 下的 nmd-monitor，否则为 ~/.local/state/nmd-monitor。管理安装
使用安装时记录的路径：个人默认 `~/.local/state/nmd-monitor`，系统 `/var/lib/nmd-monitor`。
系统数据库属于专用 `nmd-monitor` UID，CLI / GUI 也必须以该 UID 运行，即便 root 也不
作为另一种读取身份。旧版 `mh-monitor` 数据库不自动迁移或删除；先备份旧状态目录，
在采集器停止后单独审核转移方案。不要盲目跨 UID 复制数据库或放宽权限，也不能假定新
路径已包含旧记录。
这些是记录条数和时间窗口限制，并非 SQLite 文件的硬字节上限。

状态目录采用逐级 no-follow 打开并保持目录描述符，采集锁与数据库使用同一已验证目录。
Linux SQLite 使用 `/proc/self/fd`；macOS 使用经过设备/文件 ID 验证的 Darwin 卷标识路径。
macOS 仅接受 root 所有、目标固定的 `/var`、`/tmp`、`/etc` 系统路径别名；其他符号链接仍拒绝。
文件系统不支持稳定身份路径时明确失败，不退回原路径或伪造空白健康状态。
目录祖先必须属于当前账户或 root，且不能允许组或其他用户写入；root 所有、带 sticky
位的共享临时目录是例外。叶目录仍须当前账户独占，拒绝符号链接、硬链接状态文件及
路径中的 `..` 组件。不符合条件时选择受信任的私有位置；程序不会自动放宽系统权限。
SQLite 会把描述符路径规范化为普通路径，因此可信祖先检查同样必要；恶意同 UID
进程或 root 的修改不属于这层隔离能够防御的范围。


## 安装范围与 systemd 持续运行

默认个人安装与显式系统安装均只安装 monitor，不启动、启用或重启服务，不配置用户
lingering，不下载代理资产、不改系统网络。Git 克隆/fetch 仍会连接远端仓库。

```bash
# 个人安装：代码 ~/.nmd，配置 ~/.config/nmd，状态 ~/.local/state/nmd-monitor
./install.sh
nmd monitor start
nmd monitor enable          # 单独的显式选择；不启动、不启用 lingering
nmd monitor service-status
nmd monitor logs
nmd monitor status
nmd gui
```

个人单元默认写入 `~/.config/systemd/user/nmd-monitor.service`，通过 `systemctl --user`
管理，采集器与 GUI 以当前用户运行。绝对 XDG_CONFIG_HOME / XDG_STATE_HOME 在安装时
决定配置/状态默认值。用户会话必须可用；enable 不保证登出后继续采集，也不保证登录前
启动。若需要系统级持续采集，选择明确的系统安装：

```bash
sudo ./install.sh --system
sudo /opt/nmd/nmd monitor start
sudo /opt/nmd/nmd monitor enable
sudo /opt/nmd/nmd monitor service-status
sudo /opt/nmd/nmd monitor logs
sudo -u nmd-monitor /opt/nmd/nmd monitor status
sudo -u nmd-monitor /opt/nmd/nmd gui
```

系统代码固定在 root 所有的 `/opt/nmd`，链接为 `/usr/local/bin/nmd`，配置为
`/etc/nmd/monitor.json`，状态为 `/var/lib/nmd-monitor`。安装创建或检查专用非 root
账户 `nmd-monitor`；单元位于 `/etc/systemd/system/nmd-monitor.service`。该 UID 只用于
采集与读取私有状态，代码、单元及配置由管理员维护。不要给系统状态增加公开读权限，
也不要把代码放到个人可写目录。系统 GUI 读取安装凭据不要求改变 root checkout 所有权
或全局放宽 Git 的所有权保护。个人日常 GUI 需求应优先选择个人安装。

`nmd install` 与 `nmd monitor install` 可安装/修复当前范围的单元；`--manager-only`
仅安装代码和命令，之后再显式安装单元。monitor start / stop / restart / enable /
disable / logs / service-status / uninstall 都使用持久化 scope。enable 不 start，
disable 不 stop；卸载才停止、取消启用并移除本安装的单元。

`nmd monitor uninstall` 保留命令链接；`nmd uninstall` 另移除确属本安装的链接。
两者都保留 checkout、配置、数据库与系统服务账户，不删除 mihomo 或 tailscaled。
`nmd update` 不会 apply 或重启；需要加载新采集代码时显式 monitor restart。

[systemd/nmd-monitor.service.example](../systemd/nmd-monitor.service.example) 仍是人工部署
参考模板，带有需替换的 User / Group 占位符；实际安装器生成带所属安装标记的单元。
不要用未修改的模板覆盖生成单元，也不要认为已有陌生单元可被自动接管。两种安装的单元
均不依赖 mihomo 的 Requires / PartOf，关闭 mihomo 或 GUI 不带走采集器。服务只在自身
异常退出时按 Restart=on-failure 重启，不因探测失败自动重启网络组件。

默认安装配置是本地采样；切换场景前审核实际目标和探测权限。没有 scope 的旧安装及
user/system 切换需按 [迁移 runbook](../runbook.md#旧安装与-scope-迁移) 显式处理。
不能直接移动 checkout 或自动跨 UID 迁移状态，不能用 sudo 暗中切换范围。

## 验证与尚未完成的验收

本地离线测试应只使用临时目录、假命令结果、假探测和本机测试服务；不要运行真实
网络故障演练来验证界面。本版不因离线测试通过就宣称实际部署成功。

`python3 -m unittest discover -s tests -p test_socket_probe.py -v` 运行真实隔离探测
子进程，但用 fixture 替换 DNS、socket 与 SSL 边界，不解析或连接外部目标；覆盖错误
分类、多地址回退、累计计时、共享预算及阻塞解析时的父进程终止。

浏览器 CI 使用官方 `mcr.microsoft.com/playwright:v1.57.0-noble` 预装浏览器及系统依赖，
与 npm 的 `playwright@1.57.0` 一起固定版本（升级需同步修改并验证）。安装依赖限时
3 分钟，预装浏览器检查限时 1 分钟，fixture 限时 3 分钟，整个 job 限时 15 分钟，
为容器启动和证据上传留出时间。`dashboard-browser-evidence` 保留安装、浏览器版本/
路径、测试日志和已生成的合成截图 7 天；失败不会因 `tee` 或上传步骤变成成功。
容器拉取失败发生在步骤开始前，需查看 Actions 自带的初始化日志。
本地可按 `tests/test_dashboard.py` 的说明安装相同版本并运行
`node web/tests/dashboard.spec.cjs`；fixture 只使用回环 HTTP 服务和合成数据。
本地通过不证明修改后的 GitHub Actions 已运行；未推送时远端 CI 仍待验证。

先前的 [CI 运行 39197765374](https://github.com/zzzhty/network-monitor-and-diagnostics/actions/runs/39197765374)
记录了原诊断 MVP 的 Linux 与 Chromium 检查；它不证明本次 scope 改动已完成真实系统安装
验收，也不代表真实主机 24 小时验收通过。

真实连续 24 小时运行验收仍待完成。后续需在获授权的 Linux 主机上确认：监控与 GUI
分开启停、mihomo 关闭后持续采样、机器休眠 / 重启后的时间缺口、服务异常重启、数据
保留上限、权限不足的呈现、显式探测失败及恢复。不要为了验收断开用户正在使用的远程
连接，也不要未经许可切换路由或停止生产服务。

### POC 验收清单

以下清单用于记录验收证据，不表示每项已经通过。离线结果不能替代最后一项。

- 配置检查：四个 JSON 模板均通过 config-check；本地配置无主动目标，其余目标均禁用。
- 无外联默认值：用替身拦截所有子进程，只允许固定 systemctl show 的假返回；断言模板
  不执行 curl、DNS、TCP 或 TLS 子进程。不要为这项测试查询真实 systemd。
- 假探测时间线：输入连续失败 / 成功序列，验证 3 次确认失败、2 次确认恢复，以及
  unknown / skipped 切断证据链；检查首次观察和确认时间分别保存。
- 记录恢复：临时状态目录重启采集器后验证 collector_restart 缺口；模拟休眠 / 时钟
  跳变验证缺口，不把缺口误算为断网。模拟旧记录及小行数上限验证保留清理。
- GUI：使用本机测试数据库与回环 HTTP 服务，验证无数据 / 过期 / 失败 / 禁用状态、
  API 快照、非本机 Host / 跨站 Origin 拒绝、未路由路径写方法拒绝；出口节点页的切换、
  单节点测速与自动模式开关经受限 POST 端点验证（严格键集、测速地址固定、CLI 同路径）；
  关闭 GUI 后采样继续。
- 独立进程：以假服务状态模拟 mihomo 停止，确认采集器仍记录；生成单元与参考模板保持无
  Requires / PartOf=mihomo 依赖。实际两种 scope 的 systemd 安装、启停、自启和异常重启需另外授权验收。
- 真实 24 小时稳定性：尚未通过，需在授权主机上连续运行并审阅完整时段证据。
  该阶段还需检查磁盘增长、权限、真实休眠 / 重启及运维恢复；测试通过前不可宣称完成。
