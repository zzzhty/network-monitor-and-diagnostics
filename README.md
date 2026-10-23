# Network Monitor & Diagnostics (NMD)

家庭网络分流：国内和私网直连，其余经 Tailscale 内的 VPS SOCKS5 出海。
Tailscale 登录、控制服务、DERP 和 MagicDNS 独立于 VPS 代理。

可选的[出口通道 Channel](docs/egress-sources.md)复用已有 source 注册表：可添加多个订阅、
手工普通路径 SOCKS5 VPS 和 Tailnet SOCKS5 通道，并重命名显示名称而不改变节点 ID。
Channel 管理连接来源，Node 表示实际出口，Policy 只引用两个明确主备节点，可选任意通道
中的节点，不再要求“一条订阅 + 一条 Tailnet”。`nmd channel` 与旧 `nmd source` 共用后端。
Linux GUI 可添加/重命名并管理明确主备；保存只写私有配置，不自动刷新、探测、部署或切换。
添加、订阅刷新、网络 apply、节点选择仍是独立动作。macOS 与 demo 继续仅只读。

## macOS 实验性只读诊断

源码 CLI 与浏览器面板现支持 macOS；需要已有的 Python 3.9+ 与 Bash，无原生 `.app` 包装。
本节不安装服务、不配置代理，也不接管系统流量。先用安全演示查看现有面板：

```bash
cd ~/Projects/network-monitor-and-diagnostics
./nmd machine capabilities
./nmd demo --once          # 临时合成快照 JSON；不运行真实采集或 HTTP 服务
./nmd demo --port 8765     # 前台只读演示，浏览器访问 http://127.0.0.1:8765/
```

演示只使用自动清理的临时数据库；页面明确标记模拟样本，不读取真实出口来源或网络工具配置。
CLI、SQLite 历史、事件/空窗逻辑及只读 GUI 复用现有实现。macOS 的本机适配器只提供接口名称、
可用的链路状态、IPv4 路由指纹与默认路由条数；缺失信息明确为未知，systemd 服务不可用。
真实本机采样需另行显式运行前台 `monitor run`；本次验证仅用 fixtures 与回环服务。
使用方式、状态目录限制和实验边界见 [macOS 使用说明](docs/macos.md)。
下文的安装、后台服务和网络管理流程仍仅针对 Linux；macOS CLI 会提前拒绝这些命令。

## 安装范围与目录分工

开发源码与日常管理安装是独立的 Git checkout；安装后可移动开发仓库，不能直接移动
管理安装。产品名称为 Network Monitor & Diagnostics，简称 NMD；唯一命令入口为 `nmd`。
GitHub 仓库为 `zzzhty/network-monitor-and-diagnostics`。

| 位置 | 默认个人安装（user） | 显式系统安装（system） |
|---|---|---|
| 管理代码 | `~/.nmd`，当前用户拥有 | `/opt/nmd`，root 拥有 |
| 命令链接 | `~/.local/bin/nmd` | `/usr/local/bin/nmd` |
| 监控配置 | `~/.config/nmd/monitor.json` | `/etc/nmd/monitor.json` |
| 私有出口来源 | `~/.config/nmd/egress/sources.json` | `/etc/nmd/egress/sources.json` |
| 诊断状态 | `~/.local/state/nmd-monitor` | `/var/lib/nmd-monitor` |
| monitor 单元 | `~/.config/systemd/user/nmd-monitor.service` | `/etc/systemd/system/nmd-monitor.service` |
| 采集身份 | 当前用户 | 专用非 root 账户 `nmd-monitor` |

个人安装遵循绝对的 `XDG_CONFIG_HOME` / `XDG_STATE_HOME`；配置和状态路径在安装时记录。
系统安装位置固定，代码与父目录不能由普通用户写入。系统 mihomo 的 `/usr/bin/mihomo`、
`/etc/mihomo` 和 tailscaled 不属于 monitor 安装范围，也不会随 monitor 卸载而删除。

## 安装监控

Linux 监控安装需要 Git、Python 3 和 systemd；个人服务还需要可用的 systemd 用户会话。
不要求先部署 mihomo、登录 Tailscale 或配置网络。私有仓库访问需要已有 Git 认证；
个人安装使用 GitHub CLI 时可先完成 `gh auth login` 和 `gh auth setup-git`。

在源码仓库选择一种范围：

```bash
./install.sh                    # 默认个人安装，不加 sudo
sudo ./install.sh --system      # 显式系统安装，需管理员权限
```

两种安装都会独立克隆远端 `main`、安装命令链接、本地采样配置与 monitor 单元。
安装不会启动、启用或重启采集器，不会启用用户 lingering，不会下载代理资产、部署
mihomo、修改 DNS/路由/TUN/Tailscale 或执行网络验收。Git 克隆仍会访问远端仓库。
已有配置与诊断历史保留。首次个人安装后，如当前终端未包含命令目录，按输出设置 PATH
或打开新终端。系统安装的 Git 认证必须在管理员执行上下文可用，不要把访问令牌写入地址。

个人安装也可通过已认证的 GitHub CLI 从任意目录运行：

```bash
set -o pipefail
gh api repos/zzzhty/network-monitor-and-diagnostics/contents/install.sh --jq .content | base64 --decode | bash
```

私有仓库不使用匿名 Raw 下载链接。SSH 用户可设置
`NMD_REPOSITORY=git@github.com:zzzhty/network-monitor-and-diagnostics.git`。
`--manager-only` 仅安装管理代码与命令，稍后用 `nmd install` 或 `nmd monitor install`
安装 monitor 单元。个人安装可用 `--home PATH` / `--bin-dir PATH` 改变代码和命令位置；
它们不改变已记录的配置与状态路径。系统安装不接受自定义代码或命令目录。
运行 `./install.sh --help` 查看选项。已有安装不会被普通初始化调用自动拉取更新。

## 日常使用

以下以个人安装为例。系统安装的管理操作用 `sudo /opt/nmd/nmd ...`，由 root 管理代码
和单元；不要给个人安装命令加 sudo，也不能靠 sudo 将个人安装变成系统安装。

```bash
nmd version
nmd update --check          # fetch main 并查看更新，不切换版本
nmd update                  # 校验候选代码并快进，不下载资产、不 apply、不重启服务
nmd install                 # 安装/修复已记录 scope 的 monitor 单元，不启动
nmd monitor start           # 只启动采集器
nmd monitor stop
nmd monitor restart
nmd monitor enable          # 仅启用，既不启动也不配置 lingering
nmd monitor disable         # 仅取消启用，不停止正在运行的采集器
nmd monitor service-status  # systemd 服务状态
nmd monitor logs
nmd monitor status          # 读取诊断快照，与 service-status 不同
nmd gui                     # 个人模式 GUI，默认 127.0.0.1:8765，含出口节点页
# 需要卸载时二选一：
nmd monitor uninstall       # 停止、取消启用并移除本安装的 monitor 单元
nmd uninstall               # 卸载 monitor 及所属 nmd 链接；保留代码、配置、历史
```

所有 monitor 服务操作使用安装时记录的 scope，不根据当前是否使用 sudo 来猜测。
个人服务依赖用户 systemd 会话；启用服务不等于退出登录后持续运行，也不保证登录前启动。
需要系统级持续采集时选择显式系统安装。更新后如需采集器加载新代码，另行执行
`nmd monitor restart`。GUI 与采集器独立，关闭 GUI 不停止采集。

系统诊断数据只允许 `nmd-monitor` UID 读取；管理员可运行：

```bash
sudo -u nmd-monitor /opt/nmd/nmd monitor status
sudo -u nmd-monitor /opt/nmd/nmd gui
```

不要为了 GUI 放宽状态目录权限；需要个人账户直接读取时使用个人安装。
更新拒绝未提交修改、分叉历史和陌生命令覆盖，不执行强制 reset。

## 显式网络管理（与 monitor 分开）

原有顶层命令仍管理系统 mihomo / Tailscale 网络，`nmd start` 不是启动监控。
运行前需满足 Ubuntu/systemd-resolved、已登录的 Tailscale、curl、系统权限与 VPS 配置等
原有条件，并理解这些命令会影响真实网络；安装 scope 不会把它们变成用户级网络服务。

```bash
nmd status           # 安装 scope、版本、网络待应用状态及服务/Tailscale/DNS/路由
nmd apply            # 显式下载缺少的代理资产、部署当前网络配置并验证；refresh 为同义命令
nmd check            # 校验网络配置
nmd verify           # 主动联网检查 Tailscale 和分流
nmd start            # 以下顶层启停命令仍针对 mihomo
nmd stop
nmd restart
nmd enable
nmd disable
nmd logs
nmd test-stop        # 临时停 mihomo 验证 Tailscale，结束时恢复原运行状态
```

`nmd update` 不再隐式部署网络，即使显示待应用也不会自动重试 apply。
`nmd status` 的“待应用”表示当前代码尚未完成显式网络部署，不表示 monitor 安装失败；
只使用诊断时无需为了清除该状态而运行 apply。网络部署失败后，修复问题并显式重试
`nmd apply`。个人安装的显式网络操作仍可能通过 sudo 执行该 checkout 中的辅助脚本，
必须信任整个 checkout；scope 不改变网络操作的系统权限。系统安装与更新检查整个
checkout 及其祖先为 root 所有、不可由其他用户写入且无符号链接。

没有来源注册表的旧 VPS 出口仍需先部署 `vps-setup.sh`。仓库内服务地址与公网出口均为文档占位符；
先按 [本机端点配置](runbook.md#旧-vps-端点的本机配置) 在 checkout 外填写
`NMD_VPS_TS_IP` / `NMD_VPS_PUB`，再部署。默认不会探测或部署到旧的个人目标。
若原先选择了 Tailscale exit node，使用
`nmd cutover` 显式迁移；`nmd rollback` 则恢复 VPS exit node，仍依赖 VPS。
详细行为、故障恢复和验证边界见 [runbook.md](runbook.md)。
多来源模式按当前选择来源验证，不使用全局 NMD_VPS_PUB，也不推断订阅的 exit-node 回退。


## 旧安装与 scope 迁移

没有 scope 记录的旧管理安装需要显式采纳，不能根据 sudo 或目录名自动推断。
不要调用旧版 `nmd update` 来完成首次迁移，它可能仍隐式部署网络。
在确认新版已发布到该安装的 origin/main 后，从已审阅的新版源码目录执行：

```bash
./nmd adopt --home "$HOME/.nmd" --user
./nmd update --home "$HOME/.nmd"    # 使用新版的 code-only 更新逻辑
"$HOME/.nmd/nmd" monitor install   # 仍不启动或启用
```

版本升级、旧命令链接清理和 user/system 切换步骤见 [迁移 runbook](runbook.md#旧安装与-scope-迁移)。
切换 scope 必须先卸载旧 monitor，再在目标范围全新安装，不能直接 `mv` checkout。
旧代码、配置和数据库默认保留；跨 UID 的历史数据不自动复制或放宽权限。


## 网络部署恢复与可选探测

首次显式网络部署会在安装系统包之前创建并保留 `/etc/mihomo/.initial-deploy-pending`，直到 DNS、服务就绪、开机自启和
必要网络验证全部成功。任一步失败后，再次显式运行 `nmd apply` 会继续完成
首次启动目标，不会因为已写入 config.yaml 就把停机误报为成功。已存在且没有此标记的
安装仍保留原启停状态。旧版本留下的半安装没有可靠标记，需人工确认后显式 `nmd start`
及 `nmd enable`，不要自动猜测用户是否主动停机。

`nmd verify` 不再依赖固定的个人设备、局域网网关或个人 MagicDNS 名称。
可选设备诊断单独运行，失败不会影响日常部署：

```bash
NMD_TAILNET_HOST='your-device.invalid' NMD_LAN_HOST='192.0.2.1' nmd diagnostics
```

VPS 安装先下载到私有临时目录并验证配置，随后替换并重启服务；重复运行也会加载新配置。
HTTPS SOCKS5 就绪检查最多 10 次，每次总超时 5 秒（间隔 1 秒）；下载总超时 120 秒。
验证失败返回非零并尝试恢复此前的二进制、配置、unit 和启停/自启状态。退出成功仅说明
通过该出口检查，实际公网绑定/访问控制仍应在 VPS 上人工验证。恢复失败时保留私有临时目录
中的原文件备份并打印位置，需查看系统日志并人工恢复后清理。安装器拒绝替换符号链接或
其他非普通文件，包括 masked unit，避免破坏操作员管理的配置。

离线回归测试（仅临时目录、假服务命令和假网络探测）：

```bash
python3 -m unittest discover -s tests -v
for script in install.sh nmd local-setup.sh vps-setup.sh; do bash -n "$script"; done
```

测试覆盖首次部署 DNS/就绪/enable/verify 失败后的重试、主动停机保留、可选诊断、
VPS 校验失败不激活、探测失败恢复以及已运行服务重启。不自动运行 `tests/live_proxy_failure.py`，
该脚本属于实际网络故障演练，需要单独授权和可恢复的真实主机环境。

## 诊断与 GUI MVP（Linux / macOS，可独立使用）

新增诊断组件不要求先部署 mihomo，也不会修改现有 DNS、路由、TUN 或 Tailscale 偏好。
CLI、持续采集与本机浏览器面板分别运行；关闭面板不停止采集。面板提供出口节点
切换、单节点测速、通道保存/重命名与双候选策略配置（仅 Linux；详见诊断 MVP 文档）。`apps/desktop` 另有实验性
Tauri 桌面壳（托盘、自动切换系统通知；逻辑仍唯一由 Python 拥有），Linux 上
`nmd desktop install` 一条命令用户级安装（需 Rust 工具链，见
[docs/desktop.md](docs/desktop.md)）。

```bash
# 先验证本地观测配置；不会发出主动网络探测
./nmd monitor config-check --config examples/monitor-local.json
# 前台运行；Ctrl-C 停止。网络探测必须在配置中显式添加/启用
./nmd monitor run --config examples/monitor-local.json
# 另一个终端：历史 JSON 与本地面板（默认 127.0.0.1:8765）
./nmd monitor status
./nmd gui
./nmd machine capabilities
```

首版 GUI 提供总览、探测记录、故障/监测空白时间线与出口节点管理页；场景配置只定义诊断目标，
不自动切换出网方式。原有系统管理仍使用上面的 CLI 命令。
详细配置、后台服务示例、存储保留及验收边界见 [诊断 MVP 文档](docs/mvp.md)。
真实主机连续 24 小时和故障演练需要单独部署验收；离线测试与 GUI 测试不构成此项证明。
