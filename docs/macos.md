# NMD macOS 实验性只读诊断

macOS 是桌面机。NMD 在这里的定位是监控（monitor）和诊断（diagnostics）。与 Clash Verge Rev 共同使用时，流量由 Clash Verge Rev 管理。桌面端长期客户端仍在调研（具体软件调研中，待定）。
默认的监控和诊断不部署 mihomo，不改 DNS、路由、TUN 或系统代理。显式实验接管，以及重载一个正在接管的常驻守护，会改变网络；见下文的预检和 `apply`。
在一台新的 Mac 上把实验性常驻守护装起来的命令顺序，见下文「新机器：实验性常驻守护」。那不是与 Clash Verge Rev 一起用时的默认路径。
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
./nmd monitor status --dry-run
./nmd gui --dry-run --port 8765
```

`monitor status --dry-run` 输出合成快照 JSON 后退出，不启动 HTTP 服务。
`gui --dry-run` 在前台绑定 `127.0.0.1:8765`，浏览器手动访问 `http://127.0.0.1:8765/`；
Ctrl+C 关闭并自动清理临时状态目录。所有样本带 `synthetic: true`，快照标记
`collector.data_origin: demo`，页面始终显示“模拟演示”，采集器卡片显示“模拟样本”。
未启动真实采集器、没有主动探测，也不读取 HOME 下的出口来源、代理、VPN 或其他网络工具配置。
合成记录只生成一次，稍后显示过期属于预期行为，不会后台刷新假数据。

只读面板与采集器独立。启动普通 `gui` 或刷新页面不会启动采集；`monitor status` 只读取
已有 SQLite，状态不存在时返回 `no_data` 且不创建目录。Linux 的新出口控制界面与自动故障切换保留。macOS 和 `--dry-run` 的出口控制按钮禁用，
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
| 后台采集/网络服务安装、来源控制、网络管理 | 常驻守护可选（`nmd macos daemon install`，默认关，含采集监督与面板服务）。`nmd apply` / `refresh` 在已安装守护时，若这次重载需要地理数据，先补齐缺少的文件，再做只读预检，通过后才执行 `nmd macos daemon restart`（先 stop 再 start）。下载或预检失败不 stop、不 sudo。进行中的接管会被这次 stop 回退；`on_boot` 为 true 时，新的一次开机可能开始接管。来源控制、Linux 网络部署与 systemd 仍在执行动作前拒绝 |
| 实验性自管接管（单次） | `sudo nmd macos takeover`：sudo 前台运行 mihomo 接管出口，绝对截止（默认 10 分钟、上限 8 小时，按墙钟），STOP/到期/连续 3 个故障周期幂等回退；唤醒后复查或回退。仅显式运行，无常驻组件。accept 的 sentinel 有一次实机恢复记录；睡眠唤醒尚未验收。见 [macos-mihomo-tailscale.md](macos-mihomo-tailscale.md) |
| 实验性自管接管（常驻 daemon） | `nmd macos daemon install`：root 管理器（launchd KeepAlive）常驻监督接管——无绝对截止，健康故障（默认连续 3 周期）或 mihomo 退出即自动回退，唤醒后复查托管状态且不因此启动接管，手动停止走 CLI 或面板。开机策略用 `nmd macos daemon on-boot` 读写 `daemon.json` 的 `on_boot`（JSON 布尔，默认关）；这条命令不加载守护，也不开始接管。`install`、`start`、`apply` 不改这个字段。面板归属 daemon，桌面壳自动复用。未实机验证。策略见 `DAEMON_POLICY`。 |

两个本机元数据命令分别有 2 秒超时；超过 64 KiB 的命令输出明确视为不可观测。
不持久化接口 IP、MAC 地址、网关明细或命令原文。接口/路由存在、快照新鲜、单次探测成功
都不能证明整体联网、VPN 路径或实际代理出口可用。

适配不会修改系统代理、路由、DNS、VPN、Tailscale、防火墙或网络工具配置，不抓包，
不启动后台常驻，不自动测速、修复或切换网络。唯一例外是显式 `nmd desktop autostart on`
写入的用户级登录 LaunchAgent：它只在登录时启动 GUI 壳本身，不是后台采集或网络服务。
macOS 支持 `bootstrap --manager-only`、`update`、`apply` / `refresh` 与 `desktop` 生命周期。
`apply` 记录当前版本；已安装常驻守护时，若这次重载会用到接管规则，先运行与 `nmd macos geodata ensure` 相同的补齐，再做只读预检，通过后才重载 root 管理器（`daemon restart` 等于先 stop 再 start）。
它不下载 Linux 的 mihomo 安装包，也不调用 `takeover-start`。下载失败或预检失败时不会 stop，也不会 sudo，待应用状态保留。
若当时有进行中的接管，stop 会先按快照回退，路由、DNS 或 Tailscale exit node 会变。
回退没有完成时，`nmd macos daemon stop` 和 `takeover-stop` 失败，并且不会 bootout 仍在恢复的管理器。
`on_boot` 只由 `nmd macos daemon on-boot` 修改。`apply` 不改这个字段。若它已经是 true，且这次启动被管理器当成新的一次开机，它可能开始接管。
会话若停在 `active`、`starting` 或 `needs_rollback`，启动会先把那次回退做完。
`start` 在任务未加载时会 bootstrap，所以未加载的 root 管理器会被 `apply` 拉起。
用户 LaunchAgent 不在这次重载里。`install`（monitor）、`adopt`、`source`、顶层网络命令
及 `monitor start/enable/install/...` 仍是 Linux 管理能力，在 macOS 明确报不支持。
请勿通过直接运行 Linux 脚本尝试这些操作。

## 只读预检

三档分开，打开面板不要求接管才用得到的组件：

```bash
./nmd macos preflight
./nmd macos preflight --tier readonly
./nmd macos preflight --tier daemon
./nmd macos preflight --tier takeover
```

| 档 | 什么时候用 | 查什么 |
| --- | --- | --- |
| `readonly` | 面板、只读诊断。默认就是这一档 | 当前用户能不能用采集目录；已安装守护时面板端口是否被占用。不查 mihomo、Tailscale、geodata |
| `daemon` | `daemon start` / `restart`，以及已安装守护时的 `apply` / `refresh` | mihomo 是否可执行、官方 Tailscale 命令行、`daemon.json`、状态目录权限。`on_boot` 为 true，或看不清守护是否正在接管时，同时要求下一档。守护自己正在接管时，它占用的 mihomo、198.18 和 DNS 端口不算另一份实例；缺组件或 Tailscale 没在运行仍然会拦住 |
| `takeover` | `accept`、`takeover`、`daemon takeover-start` 改网络之前 | 上一档之外，还有版本能力、离线配置、geodata、Tailscale 是否在运行、198.18 / 已有 mihomo / DNS 端口 |

`tun.dns-mode: native` 需要 mihomo 1.19.33 或更新。这是文档里 native 模式的要求，不是把曾经观测到的 1.19.34 当成最低版本。`dns-mode: disabled` 没有这道下限。

输出是一份 JSON：`result` 为 `pass`、`fail` 或 `unknown`。`unknown` 是探测没有得到结果，不会当成通过。退出码分别是 0、1、3。`fail` 和 `unknown` 都不会 sudo、stop、start 或改网络。失败项带一句中文的下一步，例如把官方 mihomo 或官方 Tailscale 装到哪。缺地理数据时，下一步是下面的 `nmd macos geodata ensure`。预检本身不会安装或下载，也不会打印配置正文、地址或密钥。

这些检查在本仓库里用替身和离线用例验证。它们不是实机验收，也不表示睡眠唤醒或 watchdog 恢复已经在真机上通过。

## 地理数据

生成配置不写 `geodata-mode`。mihomo 1.19 因此用 MMDB 做 `GEOIP`，用 `geosite.dat` 做 `GEOSITE`。`geoip.dat` 是打开 `geodata-mode` 才读的另一种格式，这条路径不下载它。目录里已有、并且带 MaxMind 标记的 `Country.mmdb` 或 `geoip.db` 算作 MMDB，不会再下一份 `geoip.metadb`。空文件、网页或截断内容不算已有数据；下载失败时原文件保持不变。`GeoSite.dat` 和 `geosite.dat` 按大小写不敏感认作同一个文件。

来源与 Linux `fetch-assets.sh` 相同，都是 MetaCubeX `meta-rules-dat` 的 `latest`：`geosite.dat` 和 `geoip.metadb`。macOS 还会核对同一发布旁的 `.sha256sum`。体积不能代替这份校验。Linux 脚本的行为不变，它仍不核对校验和，也仍把站点库存成 `GeoSite.dat`。

```bash
nmd macos geodata ensure
nmd macos geodata ensure --geodata-dir /path/to/dir --inputs inputs.json
```

不带 `--geodata-dir` 时写到当前账户的 `~/.config/mihomo`。这个目录也是 sudo 前台（`SUDO_USER` 的家目录）和 launchd（daemon 配置所有者的家目录）复制地理数据的地方。不要用 sudo 跑这条命令：它不会把文件写进 `/var/root`，也不会改 root 拥有的权限。显式 `--geodata-dir` 只写该目录，规则来自 `--inputs` 或已安装的 `daemon.json` 时都一样。规则里没有 `GEOSITE` 就不下 `geosite.dat`，没有 `GEOIP` 就不下 `geoip.metadb`。文件已经是合法的 MMDB 或 geosite 时不访问网络。下载或格式校验失败时，原来的字节留在原地；目录里剩下一个非空但无效的文件也不会 sudo、stop，或把这次 apply 记成已应用。复制进 mihomo 工作目录时包含 `geoip.db`，因为这个名字和 `geoip.metadb`、`Country.mmdb` 一样被 mihomo 1.19 认作 MMDB。

`accept`、`takeover`，以及需要接管检查的 `daemon start` / `restart` / `takeover-start`（含已安装守护上的 `apply`），会在 sudo、stop、start 之前做同一步。下载或校验失败则不继续，不改路由、DNS、代理或 Tailscale，也不把版本记成已应用。`preflight`、`help`、`status` 和只读面板不会下载。

这一步在仓库里用替身验证，不是实机下载验收。

## 新机器：实验性常驻守护

这是显式选择的实验路径，不是与 Clash Verge Rev 共同使用时的默认监控。默认路径不部署 mihomo，不改 DNS、路由或系统代理。下面的顺序没有在本仓库的实机上跑过。入口是 `nmd onboard`。它不能从零装完一台 Mac：官方 Tailscale 仍要自己安装，Tailnet SOCKS 地址也要自己提供。mihomo 只有在已经存在当前用户可写的目录时才会被放进去；放不进去就停，不写 `daemon.json`，也不开始接管。

`install`、`start`、`restart` 和 `apply` 都不改 `takeover.on_boot`。`DAEMON_POLICY` 里 `takeover_on_boot_default` 仍是 false。同一次开机里的 KeepAlive 重启，以及睡眠唤醒，都不会因为这个标志再开一轮接管。

### nmd 装不了的前提

- 机器上已有 Python 3.9+、Git 和 Bash。`./install.sh --manager-only` 会再用 Git 克隆一份独立的 `main` 到 `~/.nmd`。凭证用你已经配好的 Git，命令行里不放 token。
- 官方 Tailscale。`onboard` 不下载、不安装、不登录，也不执行 `tailscale set`。命令需要已经出现在下面之一：`/Applications/Tailscale.app/Contents/MacOS/Tailscale`、`/usr/local/bin/tailscale`、`/opt/homebrew/bin/tailscale`、`/usr/bin/tailscale`。缺了或不可执行时命令停止，并说明要自己安装官方客户端。真正接管之前，客户端要已经连上。
- 官方 mihomo。已经在 `/usr/local/bin/mihomo`、`/opt/homebrew/bin/mihomo` 或 `/usr/local/sbin/mihomo` 且可执行时，`onboard` 直接用它，不再下载。否则只在当前用户拥有、且组和其他人不可写的目录里放一份：先看已经存在的 `/opt/homebrew/bin`、`/usr/local/bin`，再看 `~/.local/bin`（没有就建成 0700）。二进制来自单独固定的 MetaCubeX Darwin 发布（当前 `v1.19.34`），资源名是 `mihomo-darwin-<arch>-<VER>.gz`。`fetch-assets.sh` 本身只下 Linux deb，macOS 不跑它，也不调用 `brew`，也不使用 sudo。下载失败、解开后不是 Mach-O，或没有这样的目录，命令停止，不写配置。这一步只检查 gzip 和 Mach-O 文件头，发布页没有校验和文件，`fetch-assets.sh` 也不核对 deb。实验 profile 的 `tun.dns-mode` 是 `native`，接管预检仍要求 mihomo 1.19.33 或更新；Linux 安装包仍沿用原版本，Darwin 固定版本不得低于这一下限。发现已有可执行文件时，不会覆盖或替换它；若版本过旧或无法确认，则请先更新该文件，再运行 `onboard`。完整接管预检仍须单独运行。
- 一份你自己的 SOCKS 输入。`server` 必须是 Tailnet 地址（`100.64.0.0/10` 或 `fd7a:115c:a1e0::/48`），`port` 是 1–65535 且不能是 22。`examples/macos-daemon.json` 和 `examples/macos-mihomo-takeover.inputs.example.json` 里的 `203.0.113.20` 是文档占位，`onboard`、`init` 和 `install` 都拒绝它，也不会拿它生成一份新配置。

### 1. 管理安装

在源码目录执行，不要 sudo：

```bash
./install.sh --manager-only
```

macOS 拒绝不带 `--manager-only` 的 bootstrap，也不部署 Linux 网络或采集服务。结束后按它打印的方式把 `~/.local/bin` 放进 PATH，然后用 PATH 里的 `nmd`。源码目录里的 `./nmd macos daemon install` 会在安装检查时被拒绝。

### 2. 用 onboard 记下地址

不要 sudo。下面的地址只说明形状，不要原样复制。`onboard` 只检查它落在 Tailnet 前缀里，不会分辨这是不是你的机器：

在交互终端里直接运行即可。地址没有默认值，macOS 上端口也没有默认值。代理名直接回车是 `VPS`。不要照抄下面会话里的形状地址。确认之前不下载、不写 `daemon.json`。直接回车、EOF 或 Ctrl-C 退出，不留下文件。

```text
nmd onboard
逐项填写 Tailnet SOCKS。确认之前不会下载，也不会写配置。
Tailnet 地址: fd7a:115c:a1e0::abcd
端口: 1081
代理名称 [VPS]:
请核对：
  地址  fd7a:115c:a1e0::abcd
  端口  1081
  代理  VPS
确认后才会检查 Tailscale 和 mihomo，并可能下载 mihomo。不会安装 Tailscale，也不会开始接管。
确认并继续？输入“是”继续，直接回车取消: 是
```

`nmd onboard --interactive` 是同一引导。不是交互终端时，这两条都会立刻失败，不会等待输入。脚本用下面的非交互写法：

```bash
nmd onboard --server fd7a:115c:a1e0::abcd --port 1081 --proxy-name VPS
nmd onboard --inputs /path/to/inputs.json
```

inputs 文件只有当前用户可读写，形状与 `init` 相同：

```json
{
  "proxy_name": "VPS",
  "server": "fd7a:115c:a1e0::abcd",
  "port": 1081
}
```

顺序是固定的。地址先在本地校验；交互模式还要等确认。占位地址 `203.0.113.20`、非 Tailnet 地址、端口 22 或不是整数，都在探测组件之前失败。校验通过（交互模式则还要确认）之后才找官方 Tailscale；没有或不可用就停，不下载 mihomo，也不写 `daemon.json`。Tailscale 可用而 mihomo 不在候选路径上时，才按上一节放到用户可写目录。放好或已经存在之后，才把地址写入管理安装记录的 `configDir/daemon.json`（默认 `~/.config/nmd/daemon.json`）。新建的父目录是 0700，文件是 0600。新建时 `on_boot` 是 JSON 布尔 `false`，`profile` 留空。已有合法文件只更新 `inputs`，原来的 `on_boot` 保持不动，包括已经是 `true` 的情况；这条命令不会因此加载守护或开始接管。二进制不在候选目录里时，把它的绝对路径写进 `takeover.mihomo_path`。失败、符号链接、组或其他人可写的目录，都不改这份文件。root 会被拒绝，避免写进 `/var/root`。成功时的 JSON 不重复打印地址，也不把 `loaded_daemon`、`takeover_started`、`apply_ran` 写成 true。

`nmd macos daemon init` 仍是只写配置、不检查 Tailscale、不下载 mihomo 的下一层命令。已有文件或符号链接时它不覆盖。相对的 `--mihomo` 会失败且不创建文件。

```bash
nmd macos daemon init --inputs /path/to/inputs.json
nmd macos daemon init --inputs /path/to/inputs.json --mihomo /absolute/path/to/mihomo
nmd macos daemon on-boot
```

`on-boot` 不带参数时只打印当前值。刚由 `onboard` 或 `init` 新建的文件应是 `false`。

### 3. 地理数据和预检

```bash
nmd macos geodata ensure
nmd macos preflight
nmd macos preflight --tier daemon
nmd macos preflight --tier takeover
```

`geodata ensure` 不带 `--inputs` 时读刚才的 `daemon.json`，把缺少的 `geosite.dat` / `geoip.metadb` 下载到当前账户的 `~/.config/mihomo`。不要 sudo。`preflight` 默认是 `readonly`，不要求 mihomo。`daemon` 档检查 mihomo 能否执行、官方 Tailscale 命令行、`daemon.json` 和状态目录；`on_boot` 仍是 false 且看得到守护没在接管时，这一档不要求 Tailscale 已连接，也不要求地理数据。`takeover` 档才要求地理数据、Tailscale 正在运行，以及 198.18 / 端口没有被别人占用。`fail` 和 `unknown` 都不会 sudo，也不会改网络。

### 4. 安装并加载

```bash
nmd macos daemon install
```

这一步会调用 `sudo`，写入 `/Library/LaunchDaemons` 并 `launchctl bootstrap` 系统任务。它不改 `on_boot`。因为上一步把标志留在 false，这次加载会启动 root 管理器，但不会开始接管。用户 LaunchAgent 写好后下次登录才生效，这次不启动它。`install` 自己不做上面的预检，所以先跑预检再安装。缺配置或仍是占位地址时，install 直接拒绝。

已经 `stop` 过、需要再加载时：

```bash
nmd macos daemon start
```

`start` 也要 sudo。它会先按需补齐地理数据，再做只读预检，通过后才加载。它同样不改 `on_boot`。

### 5. 开机是否接管

```bash
nmd macos daemon on-boot status
nmd macos daemon on-boot off
nmd macos daemon on-boot on
```

这三条只读或只写 `daemon.json` 里的 JSON 布尔值。`on` 写成 `true`，`off` 写成 `false`，不带参数或 `status` 只打印。字符串 `"true"` / `"false"` 不会被接受。配置缺失、不是合法 JSON、字段类型不对、属主不是当前用户、组或其他人可写、或路径上有符号链接时，命令失败并且不另造一份配置。不要用 sudo 或 root 跑。

把标志改成 true 不会加载 LaunchDaemon，也不会开始接管，不改路由、DNS、代理或 Tailscale。之后的 `nmd macos daemon start` 或 `nmd apply`，只有在管理器把这次启动当成新的一次开机时，才可能马上开始接管。同一次开机里已经跑过管理器时，再 `start` 或 `apply` 通常不会因此接管；下一次真正开机，且上次结果不在抑制名单里，才会按 `on_boot` 开始。若在第一次 `install` 或 `start` 之前就把标志设成 true，那次启动没有旧的开机记录，会被当成新的一次开机，可能马上接管。不想这样，就保持默认 false，等管理器已经起来再改。

### 6. 记录版本

```bash
nmd apply
```

`refresh` 同义。它记录当前版本，不改 `on_boot`。还没安装守护时不执行 sudo。已经安装时，若这次重载需要地理数据，先补齐，再做只读预检，通过后才 `nmd macos daemon restart`（先 stop 再 start）。下载或预检失败则不 stop、不 sudo。进行中的接管会被这次 stop 回退。`on_boot` 已是 true，且这次启动被当成新的一次开机时，可能开始接管。

Linux 的 `apply` / `refresh` 仍是原来的资源下载和网络部署，不受这些 macOS 子命令影响。

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
`gui --dry-run` 与 `monitor status --dry-run` 不读取真实通道，也不会因为新通道模型开始自动探测或切换。
