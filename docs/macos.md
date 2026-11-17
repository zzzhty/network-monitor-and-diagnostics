# NMD macOS 实验性只读诊断

macOS 是桌面机。NMD 在这里的定位是监控（monitor）和诊断（diagnostics）。与 Clash Verge Rev 共同使用时，流量由 Clash Verge Rev 管理。桌面端长期客户端仍在调研（具体软件调研中，待定）。
NMD 不部署 mihomo，不改 DNS、路由、TUN 或系统代理。
平台分工见 [跨平台分工](platforms.md)。

开发位置：`~/Projects/network-monitor-and-diagnostics`，分支 `feat/macos-support`。
需要机器上已有的 Python 3.9+ 与 Bash；诊断、SQLite 和 HTTP 使用 Python 标准库。
不要求安装 PyYAML、Node 或其他运行时；来源管理的既有可选依赖只用于 Linux 功能。
当前界面是浏览器面板；可选的用户级 Tauri 桌面壳（需 Rust 工具链）提供
`~/Applications/NMD.app` 包装，见 [desktop.md](desktop.md)。

## 先运行安全演示

```bash
cd ~/Projects/network-monitor-and-diagnostics
./nmd machine capabilities
./nmd demo --once
./nmd demo --port 8765
```

`--once` 输出合成快照 JSON 后退出，不启动 HTTP 服务。普通 demo 在前台绑定
`127.0.0.1:8765`，浏览器手动访问 `http://127.0.0.1:8765/`；Ctrl+C 关闭并自动清理
临时状态目录。所有样本带 `synthetic: true`，快照标记 `collector.data_origin: demo`，
页面始终显示“模拟演示”，采集器卡片显示“模拟样本”。未启动真实采集器、没有主动探测，
也不读取 HOME 下的出口来源、代理、VPN 或其他网络工具配置。
演示记录只生成一次，稍后显示过期属于预期行为，不会后台刷新假数据。

只读面板与采集器独立。启动普通 `gui` 或刷新页面不会启动采集；`monitor status` 只读取
已有 SQLite，状态不存在时返回 `no_data` 且不创建目录。Linux 的新出口控制界面与自动故障切换保留。macOS 和 demo 的出口控制按钮禁用，
macOS 拒绝通道保存/重命名、策略、测速和选择等五类出口 POST 端点及 `monitor run --sources-dir`，不会执行来源自动评估。
macOS 的 `/api/sources` 固定为
未配置状态，不读取私有来源注册表或查询控制器。

macOS 面板唯一的写能力是「设置与帮助」页的监控配置编辑（`/api/config`，`gui` 默认指向
`~/.config/nmd/monitor.json`，管理安装指向安装时记录的配置路径）：读取与保存采样周期、
超时、保留时长、样本上限和最多 16 个探测项，复用 `nmd monitor config-check` 的同一套
严格校验后原子写入（新建目录 0700、文件 0600）。保存不启动、重启或探测任何东西，
改动在下次显式 `nmd monitor run --config` 时生效；Linux 的监控配置仍由 nmd CLI 与
systemd 安装管理，面板不提供编辑。

## Clash Verge Rev 配置校验（规划）

与 Clash Verge Rev 共同使用时，NMD 只做监控（monitor）和诊断（diagnostics），流量由 Clash Verge Rev 管理。后续以只读方式校验它的配置，确认当前方案能跑通，并把结果和时间戳记在 NMD 自己的状态里。不调用 external-controller，不修改它的配置。设计和验收标准见 [跨平台分工](platforms.md)。本 PR 不实现校验器。

## 能力与边界

| 能力 | macOS 行为 |
|---|---|
| CLI、私有 SQLite、历史、事件、空窗 | 共用既有实现；重启/休眠缺口保留为证据缺口 |
| 接口名称与链路状态 | 显式采样时只读执行 `/sbin/ifconfig -a`；无 link status 时为 unknown |
| IPv4 路由 | 只读执行 `/usr/sbin/netstat -rn -f inet`；只保存指纹与默认路由条数 |
| 命令失败、超时、无有效输出 | unknown / 对应字段不可观测，保留脱敏错误原因 |
| systemd 服务 | 不支持；`services` 为空，`service_observation_error` 为 `unsupported_platform` |
| DNS/TCP/TLS/HTTP 探测 | 复用显式配置的既有探测逻辑；默认 `probes: []`；本次未访问真实外部目标 |
| 浏览器面板 | 诊断只读、仅回环、相同账户读取私有状态；静态首页允许顶层导航，数据 API 拒绝跨站请求、写方法与陌生 Host；macOS 额外仅开放 `/api/config` 编辑自己的 monitor 配置（不启动采集） |
| 用户级桌面壳 | 可选；`nmd desktop install` 本机构建 `~/Applications/NMD.app`（无需证书），登录自启为可选 LaunchAgent，仅启动 GUI 壳本身 |
| 后台采集/网络服务安装、来源控制、网络管理 | 常驻守护可选（`nmd macos daemon install`，默认关，含采集监督与面板服务）；来源控制、网络部署与 systemd 仍仅 Linux，CLI 在执行动作前拒绝 |
| 实验性自管接管（单次） | `sudo nmd macos takeover`：sudo 前台运行 mihomo 接管出口，绝对截止（默认 10 分钟、上限 8 小时），STOP/到期/连续 3 个故障周期幂等回退；仅显式运行，无常驻组件，未实机验证。见 [macos-mihomo-tailscale.md](macos-mihomo-tailscale.md) |
| 实验性自管接管（常驻 daemon） | `nmd macos daemon install`：root 管理器（launchd KeepAlive）常驻监督接管——无绝对截止，健康故障（默认连续 3 周期）或 mihomo 退出即自动回退，手动停止走 CLI 或面板；开机策略 `daemon.json` 的 `on_boot`（默认关）。面板归属 daemon，桌面壳自动复用。未实机验证。策略见 `DAEMON_POLICY`。 |

两个本机元数据命令分别有 2 秒超时；超过 64 KiB 的命令输出明确视为不可观测。
不持久化接口 IP、MAC 地址、网关明细或命令原文。接口/路由存在、快照新鲜、单次探测成功
都不能证明整体联网、VPN 路径或实际代理出口可用。

适配不会修改系统代理、路由、DNS、VPN、Tailscale、防火墙或网络工具配置，不抓包，
不启动后台常驻，不自动测速、修复或切换网络。唯一例外是显式 `nmd desktop autostart on`
写入的用户级登录 LaunchAgent：它只在登录时启动 GUI 壳本身，不是后台采集或网络服务。
macOS 支持 `bootstrap --manager-only`、`update` 与 `desktop` 生命周期；`install`
（monitor）、`adopt`、`source`、顶层网络命令及 `monitor start/enable/install/...`
仍是 Linux 管理能力，在 macOS 明确报不支持。请勿通过直接运行 Linux 脚本尝试这些操作。

## 可选：显式本机单次观测

以下是另行选择的真实本机元数据观测入口，**不是安全演示**；本次实现与验证没有执行它。
读取接口及路由元数据是生成真实本机观测的必要输入。先审阅配置，保持 `probes: []`，
再显式运行单次前台采样；不需要 sudo，不启动任何后台服务：

```bash
cd ~/Projects/network-monitor-and-diagnostics
nmd_state=$(mktemp -d "${TMPDIR:-/tmp}/nmd-local.XXXXXX")
./nmd monitor config-check --config examples/monitor-local.json
./nmd monitor run --config examples/monitor-local.json --state-dir "$nmd_state" --once
./nmd monitor status --state-dir "$nmd_state"
./nmd gui --state-dir "$nmd_state" --port 8765
```

去掉 `--once` 才会持续前台采样，Ctrl+C 结束；关闭 GUI 不会停止这个独立采集器。
`--state-dir` 必须由当前账户独占且目录为 0700、文件为 0600；读取者必须同 UID。
未指定路径时仍遵循绝对 `XDG_STATE_HOME/nmd-monitor` 或 `~/.local/state/nmd-monitor`。
不要使用现有真实网络配置/密钥作为测试输入，也不要为本次验证启用外部目标。

## 平台实现与验证范围

`nmd` 通过 Python 标准库解析源码/命令链接路径，保留参数与 stdin，无 GNU readlink 依赖。
`nmd_platform.py` 隔离 Linux 的 `/sys`、`/proc`、systemctl 与 Darwin 的只读元数据命令。
共享状态目录仍逐级 no-follow 校验所有权、私有权限、链接和目录身份；Linux 使用 procfs
描述符路径，macOS 使用 `/.vol/<device>/<inode>` 并先验证身份，保持目录改名后指向原对象。
Apple 将此路径机制定义为兼容行为，未来 OS 或部分文件系统可能不支持；此时失败关闭，
不静默改用可被重定向的原路径。机制来源见
[Apple XNU 路径解析](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_lookup.c)。
同 UID 的恶意进程和 root 仍不在现有信任隔离边界内；不为适配放宽权限。

可在仓库运行以下标准库测试；只读元数据全部使用 fixture，真实 HTTP 只访问回环测试服务：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests:scripts python3 -m unittest \
  test_macos test_monitor test_observability test_dashboard test_review_regressions -v
node --check web/app.js
bash -n nmd
```

可选 Chromium 浏览器 fixture 仍使用原有 Playwright 工具链；没有现成依赖时跳过，不自动安装。
测试不能代替真实本机采样、真实外部探测、连续 24 小时、休眠唤醒或 Linux 实机部署验收。
本次不承诺 IPv6 路由观测、macOS 服务生命周期、实际 VPN/代理归因或原生桌面集成。

Channel 扩展仍不开放 macOS 来源配置：`nmd channel` 与 `nmd source` 均提前拒绝，
GUI 的 `channel_management` 为 false，新建/重命名接口在读取私有来源前拒绝。
安全 demo 不读取真实通道，也不会因为新通道模型开始自动探测或切换。
