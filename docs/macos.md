# NMD macOS 实验性只读诊断

开发位置：`~/Projects/network-monitor-and-diagnostics`，分支 `feat/macos-support`。
需要机器上已有的 Python 3.9+ 与 Bash；诊断、SQLite 和 HTTP 使用 Python 标准库。
不要求安装 PyYAML、Node、Tauri 或其他运行时；来源管理的既有可选依赖只用于 Linux 功能。
当前界面是浏览器面板，没有原生 `.app` 包装。

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
已有 SQLite，状态不存在时返回 `no_data` 且不创建目录。Linux 的新出口控制界面与自动故障切换保留。macOS 和 demo 的控制按钮禁用，
macOS 拒绝三个控制 POST 端点及 `monitor run --sources-dir`，不会执行来源自动评估。
macOS 的 `/api/sources` 固定为
未配置状态，不读取私有来源注册表或查询控制器。

## 能力与边界

| 能力 | macOS 行为 |
|---|---|
| CLI、私有 SQLite、历史、事件、空窗 | 共用既有实现；重启/休眠缺口保留为证据缺口 |
| 接口名称与链路状态 | 显式采样时只读执行 `/sbin/ifconfig -a`；无 link status 时为 unknown |
| IPv4 路由 | 只读执行 `/usr/sbin/netstat -rn -f inet`；只保存指纹与默认路由条数 |
| 命令失败、超时、无有效输出 | unknown / 对应字段不可观测，保留脱敏错误原因 |
| systemd 服务 | 不支持；`services` 为空，`service_observation_error` 为 `unsupported_platform` |
| DNS/TCP/TLS/HTTP 探测 | 复用显式配置的既有探测逻辑；默认 `probes: []`；本次未访问真实外部目标 |
| 浏览器面板 | 只读、仅回环、相同账户读取私有状态；静态首页允许顶层导航，数据 API 拒绝跨站请求、写方法与陌生 Host |
| 后台安装/LaunchAgent、来源控制、网络管理 | 不支持；CLI 在读取安装状态或执行动作前拒绝 |

两个本机元数据命令分别有 2 秒超时；超过 64 KiB 的命令输出明确视为不可观测。
不持久化接口 IP、MAC 地址、网关明细或命令原文。接口/路由存在、快照新鲜、单次探测成功
都不能证明整体联网、VPN 路径或实际代理出口可用。

适配不会修改系统代理、路由、DNS、VPN、Tailscale、防火墙或网络工具配置，不抓包，
不安装/启用 LaunchAgent，不启动后台常驻，不自动测速、修复或切换网络。
`install`、`update`、`adopt`、`source`、顶层网络命令及 `monitor start/enable/install/...`
是 Linux 管理能力，在 macOS 明确报不支持。请勿通过直接运行 Linux 脚本尝试这些操作。

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
