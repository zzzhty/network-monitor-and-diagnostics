# Network Monitor & Diagnostics (NMD) 运维

本机分流模板为本仓库 `config.yaml`，Ubuntu 使用 systemd 和 systemd-resolved。
故障排查与出口切换的操作者决策树（按只读观察/配置保存/显式网络修改/回滚分类）见
[诊断与切换运维 Runbook](docs/diagnostics-runbook.md)。
可选[多出口来源管理](docs/egress-sources.md)在已记录 scope 的 configDir/egress 中保留
私有来源与缓存，通过 CLI 显式管理；订阅只导入节点，不接管本机配置。GUI 提供本机出口
切换、单节点测速、自动模式以及通道添加/重命名；订阅刷新、连接定义更新/删除与部署仍只在 CLI 中显式执行。
未启用来源时，兼容原来的 VPS SOCKS5 `203.0.113.20:1080` 与 `NMD_VPS_PUB` 注入。

## 管理安装与 monitor 范围

源码仓库通常位于 `~/Projects/network-monitor-and-diagnostics`，日常管理使用安装器独立
克隆的 checkout。唯一入口是 `nmd`；安装 scope 写入安装凭据，后续命令不会根据 sudo 猜测。

| 项目 | user（默认） | system（显式） |
|---|---|---|
| 安装命令 | `./install.sh` | `sudo ./install.sh --system` |
| 管理代码 / 所有者 | `~/.nmd` / 当前用户 | `/opt/nmd` / root |
| 命令链接 | `~/.local/bin/nmd` | `/usr/local/bin/nmd` |
| 监控配置 | `~/.config/nmd/monitor.json` | `/etc/nmd/monitor.json` |
| 诊断状态 / 采集身份 | `~/.local/state/nmd-monitor` / 当前用户 | `/var/lib/nmd-monitor` / `nmd-monitor` |
| systemd 单元 | `~/.config/systemd/user/nmd-monitor.service` | `/etc/systemd/system/nmd-monitor.service` |
| systemd 目标 | 用户 `default.target` | 系统 `multi-user.target` |

个人配置与状态默认值遵循绝对 XDG 路径，实际路径在安装时记录。`--home` 和 `--bin-dir`
仅供个人安装指定代码与命令位置；系统位置固定，不支持个人可写代码。system 采集器使用
专用非 root、不可交互登录的 `nmd-monitor` 账户，管理员负责代码和单元。

普通 bootstrap 和 `nmd install` / `nmd monitor install` 只安装本地监控配置及单元，
保留已有配置，不下载代理资产、不部署 mihomo、不改 DNS/路由/TUN/Tailscale、不做网络
验收，也不会 start、enable、restart 或启用 lingering。Git 克隆/fetch 仍需访问仓库。
`--manager-only` 暂不安装 monitor 单元。已有安装不会被普通 bootstrap 自动更新。
Git 认证由执行安装/更新的账户现有配置负责，不把令牌写入仓库地址；系统安装需管理员
上下文具备私有仓库访问权限。个人管理命令不加 sudo；系统管理使用绝对入口
`sudo /opt/nmd/nmd ...`，避免 PATH 同时存在两个安装时选错范围。

### monitor 生命周期

```bash
nmd install                 # 与 nmd monitor install 相同，不自动启动
nmd monitor start
nmd monitor stop
nmd monitor restart
nmd monitor enable          # 不启动，不启用 lingering
nmd monitor disable         # 不停止
nmd monitor service-status  # systemd 状态，不是诊断快照
nmd monitor logs
nmd monitor status          # 本账户的诊断快照
nmd gui
```

以上为个人模式示例；系统模式的单元管理用 `sudo /opt/nmd/nmd monitor ...`。
个人单元依赖可用的用户 systemd 会话，enable 不保证登出后继续运行或登录前启动。
需要系统级持续运行时应显式选择 system。安装不会替你决定 start、enable 或 lingering。
两种单元均无 mihomo 的 Requires / PartOf 依赖，关闭 mihomo 或 GUI 不停止采集器。

状态目录必须由采集账户独占，不允许为了方便读取而改成共享目录。系统快照和 GUI 由
同一服务 UID 运行，例如 `sudo -u nmd-monitor /opt/nmd/nmd gui` 与
`sudo -u nmd-monitor /opt/nmd/nmd monitor status`；不要以 root 或个人账户读取系统数据库。
系统 GUI 只读安装凭据，不需要把 root 的 Git checkout 设为服务账户可写。

`nmd monitor uninstall` 停止、取消启用并删除确属此安装的 monitor 单元；
`nmd uninstall` 另外只移除确实指向此 checkout 的 `nmd` 符号链接。二者都保留代码、
配置、诊断历史与系统服务账户，不删除或更改 mihomo / tailscaled。陌生链接、其他安装的
单元或不安全权限应先人工检查，不能强制覆盖。安装与卸载不会主动删除旧诊断数据库。

## 旧安装与 scope 迁移

旧管理安装没有 scope 时必须显式采纳；仅记录范围和默认配置/状态位置，不搬迁、不改
所有权、不修改网络。旧版本可能没有 adopt 命令，先确认新版已发布到该安装的
origin/main，再从已审阅的新版源码目录执行：

```bash
./nmd adopt --home "$HOME/.nmd" --user
./nmd update --home "$HOME/.nmd"
"$HOME/.nmd/nmd" monitor install
```

第二步使用当前新版实现进行 code-only 校验和快进，不调用旧安装的 update 入口。
第三步安装监控单元，但仍不启动/启用。若远端未发布新版，先等待发布，不能假定 adoption
已经替换旧代码；若存在未提交修改或分叉，保存并处理后再继续，不强制 reset。

原有安装凭据中的 home 必须与当前路径一致，操作账户必须是 checkout 的所有者。
`--system` 仅接受 root 所有的 `/opt/nmd`，不能把家目录 checkout 直接改为系统模式。
旧 `nmd update` 可能仍会隐式 apply，不要用它完成这一步升级。
确实位于 `/opt/nmd` 的旧 root 安装需管理员从新版源码对应执行
`sudo ./nmd adopt --home /opt/nmd --system`、`sudo ./nmd update --home /opt/nmd`，
然后 `sudo /opt/nmd/nmd monitor install`；这不是将旧个人目录转换为系统安装的办法。

旧命名安装可用显式 `--migrate-from "$HOME/.mh-ts"` 安装新版入口。它只清理确实指向
指定旧 Git 目录的 `mh` / `mihomoctl` 链接，保留旧 checkout 与数据；如果旧链接指向
其他源码目录，应使用实际路径。此选项不是 user/system 数据或服务迁移器。

切换 user/system 使用人工明确的顺序：

1. 确认旧范围、代码和数据位置，备份配置与历史；旧版本必要时先完成显式采纳和代码升级。
2. 以旧安装的所有者通过绝对入口执行 `nmd uninstall`，停止、取消启用并卸载旧 monitor
   及所属命令链接。配置、数据库和 checkout 保留，mihomo / tailscaled 不受影响。
3. 从新版源码在目标范围全新安装：个人用 `./install.sh`，系统用 `sudo ./install.sh --system`。
   保留旧 checkout，不能直接 `mv`，因为安装凭据和单元记录绝对路径，状态绑定采集 UID。
4. 审阅目标安装的配置与探测目标；默认从空的私有状态目录开始。不要盲目复制不同 UID
   的 SQLite 数据库、锁文件，或递归 chown/chmod 旧数据来绕过校验。历史转移需在采集器
   停止后单独审核、备份并确认目标账户和安全权限，系统不会自动迁移。
5. 显式 `nmd monitor start`，按需要另行 `nmd monitor enable`；检查
   `nmd monitor service-status`、同 UID 的诊断快照及 GUI。
   确认目标安装正常前保留旧数据。验收只证明实际检查到的项目，不代替真实长期运行证据。

如果目标路径已有其他安装，不覆盖它；先检查它的凭据、所有者和数据，再决定处理方式。

## 显式系统网络管理

scope 只决定 NMD monitor 的安装与服务范围，顶层 start / stop / restart / enable /
disable / logs 仍针对系统 mihomo，不能用它们代替 `monitor ...`。网络操作仍依赖
Ubuntu/systemd-resolved、Tailscale、VPS 与系统权限。个人安装显式执行 apply/start 等
网络命令时，旧辅助脚本仍会请求 sudo 并以系统权限运行该用户 checkout 内的代码；这是
对整个 checkout 的信任，不能把代码留给不可信进程或其他账户修改。拒绝 sudo 时停止
对应系统操作，不影响已经安装的独立 monitor。系统安装和更新则检查整个 checkout 与
祖先均由 root 拥有、不可由组/其他用户写入，拒绝符号链接。

这些检查不把用户级 monitor 变成用户级网络控制，也不免除管理员审阅网络脚本和配置。
纯诊断使用无需调用 apply/start 等顶层网络操作。

### 旧 VPS 端点的本机配置

本节仅适用于没有来源注册表的旧单 VPS 模式。多来源仍按当前 selector 和来源的可选
expected_egress_ip 验收；来源模式不会读取本机旧 VPS 覆盖值，cutover/rollback 也不会
推断多来源的 exit-node 回退。

仓库里的 SOCKS5 服务地址 `203.0.113.20` 和公网出口 `203.0.113.10` 均为文档占位符，
不能作为部署目标。把 `examples/nmd-local.env.example` 复制到 checkout 外的私有位置，
用自己的地址填写 `NMD_VPS_TS_IP` 与 `NMD_VPS_PUB`，再由管理员保存到
`/etc/mihomo/nmd-local.env`。文件需让该安装的操作账户可读：个人安装可由该账户
拥有并设为 0600，系统安装可用 root:root、0600；管理员也能读取该文件。
也可通过同名环境变量配置；文件可读时以文件为准。非 root 的 verify 可使用仅当前账户可读的
`NMD_LOCAL_ENV` 文件或显式变量；经过
sudo 时以该私有文件为准，不能假定 sudo 保留环境变量。部署不会改写这份本机数据。

文件只接受这两个变量的字面 IPv4 赋值（可带单/双引号）、空行和独立注释，不执行
shell、export、变量替换或命令替换。旧 VPS 的部署、verify/cutover/rollback/test-stop
在地址未填写时会在 sudo、探测或系统变更之前失败。`status` 仍只读，未配置时跳过
旧 VPS 的目标路由查询；帮助、停止和已部署服务的启停边界不因此改变。

部署/源配置校验会把两个占位值替换成私有配置中的值；缺少对应占位字段时拒绝生成
未注入的配置。文档中的手工来源模板同样需要先填写自己的 Tailnet 地址。真实配置、
来源、缓存和运维事故记录不应提交到 Git。更新当前文件不会清除旧 commit、PR diff、
Actions 日志或产物中的旧值；公开前需要单独处理这些表面。

| 命令 | 行为 |
|---|---|
| `install` / `monitor install` | 安装当前 scope 的 monitor 单元，不自动启动/启用，不部署网络 |
| `update --check` | fetch origin/main，显示更新；不改 checkout 或运行配置 |
| `update` | 拒绝脏目录/分叉 → fetch → 临时候选代码语法校验 → Git 快进；不下载资产、不 apply、不重启 |
| `apply` / `refresh` | 显式下载缺少的代理资产、部署当前网络版本并验证，不拉取远端 |
| `version` | 管理安装的完整 Git 提交号 |
| `status` | 安装 scope、目录、远端、提交、网络待应用状态及服务/Tailscale/DNS/路由 |
| `install-cli` | 修复已记录安装的命令链接；个人范围按需注册 PATH |
| `check` | 在临时目录校验网络配置和 geodata，不改运行配置 |
| `verify` | 主动检查真实 DNS、登录/控制 HTTPS、MagicDNS、尾网、直连路由、出口和 fake-ip；出口探测有界重试 |
| `start` / `restart` | 校验已部署配置后启动/重启 mihomo；不切换 exit node 或自启 |
| `stop` | 停止 mihomo、清 DNS 缓存并确认 TUN 消失；保留 Tailscale |
| `enable` / `disable` | 仅更改 mihomo 开机自启 |
| `logs` | 最近 50 条 mihomo 日志；实时日志为 `journalctl -u mihomo -f` |
| `setup` | 兼容网络部署命令，只部署系统文件，不启动；与新版 install 的 monitor 安装不同 |
| `cutover` | 检查 VPS → 清除 exit node → 应用、启动并自启 mihomo → 验证 |
| `rollback` | 停止 mihomo 并取消自启，显式选择 VPS exit node，仍依赖 VPS |
| `test-stop` | 临时停止 mihomo 检查 Tailscale，退出时尝试恢复原状态 |
| `uninstall` | 卸载 monitor 及所属命令链接，保留代码/配置/历史和 mihomo/tailscaled |

### 对端路径的验收边界

`peer_probe` 仅按当前 `tailscale ping` 是否收到 pong 报告可达，输出会区分直连和
DERP 中继。收到 pong 不代表已建立直连，也不保证延迟或业务可用性。中继问题需要在
有权操作的两端自行排查；真实主机标识、地区、延迟和故障时间应留在私有运维记录中。

## 更新状态与失败续接

Git 是版本记录；安装 checkout 的 `.git/config` 中 `nmd` 段记录 home、scope、命令目录、
配置/状态目录，以及上次成功网络部署提交与 `pendingApply`。无需手改凭据。安装/更新
操作有互斥锁，不并发切换 checkout 或部署配置；路径与所有权检查不是自动迁移工具。

`nmd update` 只更新代码。候选语法校验失败时不切换版本；快进后标记待网络应用，但不会
自动下载资产、执行网络校验或触碰任何服务。已有采集器需显式 `nmd monitor restart`
才能加载新进程中的代码；需要刷新 monitor 单元时显式运行 `nmd monitor install`。
安装和代码更新都不会自动启动或重启采集器。

`pendingApply` 只对应旧网络部署，不能解释成 monitor 尚未安装或采集失败。纯监控使用
可以一直不 apply。显式 `nmd apply` 的 sudo、服务或验证失败会保留待应用状态；修复问题
后再次显式 `nmd apply`。重复 `nmd update` 不会重试网络部署，已经最新时也不重启服务。

更新拒绝覆盖管理克隆的未提交修改；开发工作保存在源码仓库并推送，再从管理命令更新。
误改管理安装时先检查和保存修改，不要盲目 reset。更新只跟随本项目 main；mihomo 核心
版本由 `fetch-assets.sh` 固定，不会因 Git 快进自动换版。显式网络部署首次缺少核心时
才安装下载的 deb；核心升级需单独验证后执行。

以下系统文件只属于显式网络部署，不由 monitor install / uninstall 管理：

| 系统文件 | 来源/用途 |
|---|---|
| `/etc/mihomo/config.yaml` | 管理安装里的 config.yaml |
| `/etc/mihomo/config.yaml.previous` | 上次 apply 前的配置 |
| `/etc/mihomo/geoip.metadb`, `GeoSite.dat` | 管理安装下载的资产 |
| `/etc/systemd/system/mihomo.service.d/10-tailscale.conf` | 启动前校验、退出后清 DNS 缓存 |
| `/etc/systemd/resolved.conf.d/mihomo-tailscale.conf` | 独立 Tailscale 公网域 DNS |
| `/etc/mihomo/nmd-local.env` | 本机真实 VPS 端点（NMD_VPS_TS_IP / NMD_VPS_PUB）；不由部署改写 |

旧的 `tailnet-search.conf` 会移为 `.previous`，搜索域由 tailscaled 维护。
部署会重启 resolved，不会注销或重启 tailscaled。系统部署不是跨服务事务，中途失败
会停止后续步骤并保留现场，不自动切换 exit node 或恢复旧的不安全配置。

## 避免 Tailscale 与 VPS 循环依赖

1. Tailscale 的 5210–5270 规则先于 mihomo 的 9000 规则执行。带 `0x80000`
   标记的 tailscaled 传输走主路由表；尾网互访走表 52；mihomo 使用表 2022。
2. `100.64.0.0/10`、尾网 IPv6、VPS 公网端点排除 TUN；VPS SOCKS5 显式绑定 tailscale0。
3. `tailscale.com` / `tailscale.io` 不返回 fake-ip，且优先 DIRECT。进程规则也让
   `tailscaled` 直连，但不把进程识别当成唯一保护。
4. resolved 的 `~tailscale.com ~tailscale.io` 比 TUN 的 `~.` 更具体；使用
   `223.5.5.5` / `119.29.29.29`。这两个 DNS IP 同时排除 TUN，避免 mihomo
   挂起时登录域名查询仍被劫持。公共 DNS 与物理网络本身必须可达。
5. 官方控制/登录网段 `192.200.0.0/24`、日志网段 `199.165.136.0/24` 及其
   IPv6 网段也排除 TUN。DERP IP 会变化，tailscaled 的标记路由覆盖其传输。
6. MagicDNS 由 tailscaled 独立管理。mihomo 停止时仍可解析尾网设备名。
   exit node 必须为空，否则停止分流后整机仍会依赖 VPS。

范围依据：[Tailscale 官方网络要求](https://tailscale.com/docs/reference/faq/firewall-ports)。
配置字段依据：[mihomo TUN](https://wiki.metacubex.one/config/inbound/tun/) 和
[DNS](https://wiki.metacubex.one/config/dns/) 文档；resolved 域路由语义见本机
`man resolved.conf` / `man systemd-resolved.service`。
若以后更换 DNS、VPS 或 Tailscale 官方地址段，应同步修改排除项并重新验证。

## 故障处理与验收

Ubuntu 的 NetworkManager 使用 `connectivity-check.ubuntu.com` 检测互联网连通性，
并将请求绑定物理网卡。该域名必须返回真实 IP 并直连；fake-ip 会导致实际联网正常时
仍显示 `limited`，并使默认路由 metric 增加 20000。应用配置后可运行
`sudo nmcli networking connectivity check`，预期为 `full`；用
`nmcli -t -f STATE,CONNECTIVITY general` 和 `ip -4 route show default` 查看状态。

VPS 不可用时，海外代理流量会失败；国内直连及 Tailscale 的基础连接应独立工作。
mihomo 正常停止或崩溃时，内核会移除其非持久 TUN 设备及设备路由；resolved
随设备移除丢弃该链路 DNS，服务退出钩子清理缓存。策略规则可能残留，不能仅凭
规则列表判断黑洞，应检查实际 `ip route get` 和联网探测。不要清空整个路由表或防火墙。

```bash
nmd stop
nmd status
nmd verify          # 停止时跳过海外出口；Tailscale 项应通过
nmd start
```

自动恢复原启停状态的停机演练：`nmd test-stop`。
此命令不进行 logout/login，不启动浏览器 SSO，也不重启 tailscaled。
若恢复失败会返回非零并明确报告；用 status/logs 排查。
要长期保持直连，另执行 `nmd disable`。

崩溃与挂起属于不同的实机验收场景；只在本地控制台或具备备用连接时执行：

```bash
# 崩溃：包自带 Restart=on-failure，默认约 10 秒后重启
sudo systemctl kill --kill-whom=main --signal=SIGKILL mihomo
nmd verify
nmd status

# 挂起：独立 DNS/控制路由应可用；执行后必须恢复进程
sudo systemctl kill --kill-whom=main --signal=SIGSTOP mihomo
# 测试登录和尾网（verify 中海外代理测试预期失败）
nmd verify
sudo systemctl kill --kill-whom=main --signal=SIGCONT mihomo
```

进程挂起时普通代理业务依然可能卡住；这里保护的是 Tailscale 管理连接。
外网、Tailscale 官方服务、第三方身份提供商或设备认证自身故障不属于本配置能保证的范围。
浏览器旧 DNS 缓存可能需刷新；不通过注销当前设备来验证，以免影响已有远程会话。

## 仓库验证

```bash
for script in install.sh nmd local-setup.sh vps-setup.sh; do bash -n "$script"; done
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

以上为离线检查，不运行真实系统服务或网络故障演练。下列原有网络验收需要实际 mihomo
资产与主机环境，必须另行明确授权，不是 monitor 安装或日常代码更新的一部分：

```bash
bash local-setup.sh check
python3 tests/live_proxy_failure.py
```

最后一项启动临时 mihomo 实例，关闭 TUN、更换端口，模拟一个无法连接的 VPS。
它验证四个 Tailscale 域名返回真实 IP、登录与控制服务 HTTPS 可达，并确认普通海外
请求确实失败；同时检查 NetworkManager 检测域名返回真实 IP，绑定物理网卡及通过
故障代理实例请求均能得到联网成功响应。需要物理网络能直连官方服务；不覆盖系统
DNS 集成或 TUN 崩溃清理。

生命周期测试使用临时真实 Git 仓库，覆盖源码与管理安装隔离、流式安装、更新预览、
候选代码校验/远端失败、未提交工作保护、分叉拒绝、并发锁，以及显式 apply 失败后的重试。
特权系统动作由测试替身记录；这些测试不代替实机停机、崩溃和挂起验收。
实际安装和待应用状态以 `nmd status` 为准。

## 其他限制

- IPv6 仍不经代理；硬编码 IPv6 的应用可直连绕过分流。
- 普通应用旧 fake-ip 缓存可能在停止后短期失效，系统缓存会清理，应用缓存由应用管理。
- 硬编码 IP / DoH 的应用主要靠 sniffer 和 GEOIP 分流。
- VPS 1080 仅绑定尾网地址；ACL 与 VPS 部署继续由原有 `vps-setup.sh` 管理。


## 部署恢复（更新）

- 首次部署完成凭据与 config.yaml 分离：`.initial-deploy-pending` 存在时重试必须恢复启动、自启和必要验证。
- 标记只在全部步骤成功后删除；失败时先修复报错，再显式运行 `nmd apply`；install/update 不会续接网络部署。
- 没有标记的已有停机安装继续保留停机状态；历史版本半安装请确认意图后手动 start / enable。
- 真实设备的名称、接口、DNS、路由与出口观测由操作者在获授权环境中核验，保存在仓库外的私有运维记录中；公开验收说明只保留通用步骤与合成样例。
- VPS 安装失败会尝试恢复旧文件和服务状态；这是尽力恢复，并非 systemd / 文件系统原子事务。恢复失败时不删除备份，按错误输出中的私有目录恢复旧文件并检查服务后再手动清理。主机崩溃、断电和 SIGKILL 不受 shell trap 保护。
- 实机验收仍需确认 systemd 启停、自启、TUN、DNS、直连隔离、VPS 重启后 1080 仅绑定 tailnet，以及故障恢复后旧代理可用。

- VPS 安装器拒绝覆盖符号链接、masked unit 和非普通文件；请先人工确认这些路径的管理意图。
- 离线 CI 仅运行 `test_*.py`、shell 语法和 Python 编译检查，不运行真实网络故障演练。
