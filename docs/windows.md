# NMD Windows 本机采集

Windows 是桌面机。NMD 在这里的定位是监控（monitor）和诊断（diagnostics）。与 Clash Verge Rev 共同使用时，流量由 Clash Verge Rev 管理。桌面端长期客户端仍在调研（具体软件调研中，待定）。
NMD 在这里做只读监控和诊断：当前用户的 CLI、SQLite 历史，以及可编辑监控配置的浏览器面板。
不部署 mihomo，不改 DNS、路由、TUN 或系统代理，也不安装桌面壳。服务器侧部署仍是 Linux。
平台分工见 [跨平台分工](platforms.md)。

后台用当前用户的计划任务，任务文件夹 `\NMD\`，任务名 `Monitor`。不使用 Windows 服务：状态在用户配置里，
不需要管理员，也不额外安装 NSSM 或其他运行时。任务只在该用户已登录时运行，登录前不会采集。

## Clash Verge Rev 配置校验（规划）

与 Clash Verge Rev 共同使用时，NMD 只做监控（monitor）和诊断（diagnostics），流量由 Clash Verge Rev 管理。后续以只读方式校验它的配置，确认当前方案能跑通，并把结果和时间戳记在 NMD 自己的状态里。不调用 external-controller，不修改它的配置。设计和验收标准见 [跨平台分工](platforms.md)。本 PR 不实现校验器。

## Python 与智能应用控制

安装和采集需要 Python 3.9 或更新的 CPython。文档不假设 `python` 已经在 PATH 里。
没有可用解释器时，用 python.org 安装包，或：

```powershell
winget install -e --id Python.Python.3.13
```

装到默认位置（`%LOCALAPPDATA%\Programs\Python` 或 `Program Files`）。不要装到 `%USERPROFILE%\.local\bin`。
也可以把可用 `python.exe` 的绝对路径设为 `NMD_PYTHON`。

Town 上如果 `python` 已是 uv 管理的真实 CPython（例如 3.13.12），并且 `sys.executable` 不在被拦路径里，可以直接用。
先确认：

```powershell
python -c "import sys; print(sys.version); print(sys.executable)"
```

`sys.executable` 不能落在 `.local\bin`，也不能是 `uv venv` 建出的 `.venv\Scripts\python.exe`。

Town 开着智能应用控制（Smart App Control）。它会拦截 uv 生成的 `python.exe` 跳板，包括：

- `%USERPROFILE%\.local\bin\python.exe`
- `uv venv` 建出的 `.venv\Scripts\python.exe`

安装脚本不会调用 `uv venv`，也不会把计划任务指到这些跳板。搜索解释器时会跳过 `.local\bin`、`Microsoft\WindowsApps`，以及 `pyvenv.cfg` 里带 `uv =` 的虚拟环境，并且不会启动已经被判定为拦截的文件。
uv 安装目录里的真实 CPython（`%APPDATA%\uv\python` 或 `%LOCALAPPDATA%\uv\python` 下的 `python.exe`）可以用。
`py -3` 不作为入口，避免它再转到被拦的跳板。

采集器只用标准库，安装不会创建虚拟环境。若自己需要虚拟环境，用已经能运行的 python：

```powershell
python -m venv --without-pip .venv
```

然后 `uv pip install`、`uv sync` 或 `uv run` 会复用这个环境。

## 执行策略与权限

用户安装和计划任务都不需要管理员。执行策略用这一次进程的 Bypass，不改机器策略：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

仓库里的 `nmd.ps1` 同样带这一次的 Bypass。安装后的 `nmd.cmd` 也只对自己启动的 PowerShell 使用 Bypass。

## 安装、运行、卸载

在已克隆的仓库里：

```powershell
cd D:\Projects\network-monitor-and-diagnostics
pwsh -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

安装会另克隆一份管理代码，写入当前用户的命令目录，并登记计划任务。它不启动任务，也不加登录触发。
装完后打开一个新终端，使用户 PATH 带上命令目录。

| 位置 | 路径 |
| --- | --- |
| 管理代码 | `%LOCALAPPDATA%\nmd` |
| 命令 | `%LOCALAPPDATA%\nmd-bin`（`nmd.cmd`、`nmd-entry.ps1`、`nmd-monitor-task.ps1`） |
| 监控配置 | `%APPDATA%\nmd\monitor.json` |
| 状态与日志 | `%LOCALAPPDATA%\nmd-monitor`，日志为 `monitor.log` |

命令目录在 git 检出之外，避免 `nmd update` 把入口脚本算进工作区。不要把命令放到 `~\.local\bin`。

```powershell
nmd version
nmd monitor enable          # 只加登录触发，不立即采集
nmd monitor start           # 启动采集
nmd monitor service-status
nmd monitor logs            # 读 monitor.log，不读事件日志
nmd monitor status
nmd gui                     # 127.0.0.1:8765；「设置与帮助」可编辑监控配置
nmd monitor stop
nmd monitor disable         # 去掉登录触发，不停止正在运行的采集
nmd monitor uninstall       # 删除计划任务；保留配置、日志与历史
nmd uninstall               # 再去掉 nmd.cmd 和用户 PATH 中的命令目录；保留代码、配置与历史
```

`install`、`enable`、`start` 是分开的。重新安装会保留已有触发器。计划任务的说明里带有本安装的路径；说明对不上的任务不会被修改。

隐私边界是用户配置文件的 ACL。这不是 POSIX 的 `0700`。同一用户下的其他程序不在这条边界里。

面板会写明：计划任务在登录后采集，不管理系统网络或出口来源。Linux 的出口控制、`apply`、`source` / `channel`、`adopt` 和桌面壳安装在 Windows 上会直接拒绝。

## 在 Town 上核对

仓库若已在 `D:\Projects\network-monitor-and-diagnostics`，用下面的命令看解释器、能力和一次前台采集。安装前的命令都走仓库里的 `nmd.ps1`。

```powershell
cd D:\Projects\network-monitor-and-diagnostics
python -c "import sys; print(sys.version); print(sys.executable)"
pwsh -NoProfile -ExecutionPolicy Bypass -File .\nmd.ps1 machine capabilities
pwsh -NoProfile -ExecutionPolicy Bypass -File .\nmd.ps1 demo --once
pwsh -NoProfile -ExecutionPolicy Bypass -File .\nmd.ps1 monitor config-check --config .\examples\monitor-local.json
$state = Join-Path $env:LOCALAPPDATA 'nmd-monitor-preview'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\nmd.ps1 monitor run --config .\examples\monitor-local.json --state-dir $state --once
pwsh -NoProfile -ExecutionPolicy Bypass -File .\nmd.ps1 monitor status --state-dir $state
pwsh -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

打开新终端后再核对已安装的命令：

```powershell
nmd version
nmd monitor start
nmd monitor service-status
nmd monitor logs
nmd gui
nmd monitor stop
nmd monitor uninstall
```

要连命令入口一起去掉时，用 `nmd uninstall`。
