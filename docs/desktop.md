# 桌面壳（Tauri，Phase 1）

`apps/desktop/src-tauri` 是 NMD dashboard 的桌面外壳：窗口、托盘与自动切换的
系统通知。它**不是第二个实现**——出口切换、测速、自动模式的全部逻辑仍由
Python（`nmd gui` / `nmd source` / 采集器）唯一拥有，所有写操作保持走回环
HTTP 路径，壳只是只读消费者加一个子进程的管理者。

## 壳做什么、不做什么

| 壳做 | 壳不做 |
|---|---|
| 窗口加载 `http://127.0.0.1:<port>/` | 不重实现任何来源/出口逻辑 |
| 启动时复用已有的 dashboard；没有才 spawn `nmd gui`（固定 argv、无 shell、stdin 关闭） | 绝不杀非自己启动的服务 |
| 托盘：显示/隐藏、退出；tooltip 显示当前出口显示名（10s 只读轮询 `/api/sources`） | 不绕过 Host/Origin/键集等任何后端防护 |
| 系统通知：`auto_events` 的新事件（去重、启动静默窗，10s 只读轮询 `/api/snapshot`） | 不打包/不接入 install.sh（Phase 2 再议） |
| 退出（含 SIGTERM/SIGINT）时只回收自己启动的子进程 | 不新增写端点 |

启动失败会打开随程序提供的本地错误页，窗口标题显示固定错误类别，提供重试与退出；
此页不加载远端内容，重试仅再次尝试本地 dashboard，不启用监控或网络接管。
CLI 优先从桌面二进制同目录查找（支持自定义 `binDir`），再查 PATH 和
`~/.local/bin/nmd`。

轮询失败不会轰炸：dashboard 不在时托盘保持「出口未知」，连续 6 个周期无响应
才会尝试重启自己 spawn 的子进程；外部启动的服务永远不受影响。
重试/重启在 spawn 时就把子进程登记到共享归属槽；退出先取消启动，再持同一把锁
回收子进程，不等待 readiness 返回，也不会在退出后接受迟到的 readiness 成功。

## 运行（Linux）

前置：`libwebkit2gtk-4.1-dev`、`libayatana-appindicator3-dev`（托盘）与 GTK3 开发
文件；Rust stable 与已安装的 `nmd` 命令。

```bash
cd apps/desktop/src-tauri
cargo run --release
```

macOS/Windows 上壳代码由 CI 编译验证（`desktop-shell` job 三平台矩阵），但本机
安装流程仅支持 Linux；macOS 上 dashboard 自身按 `/api/capabilities` 显示
只读诊断（见 `nmd_platform.py`），壳无需平台分支。

## 安装与自启（用户级）

管理安装内一条命令完成构建与安装（无 root、无 deb；构建需要 Rust 工具链）：

```bash
nmd desktop install            # cargo build --release --locked → ~/.local
nmd desktop autostart on       # 写 ~/.config/autostart/nmd-desktop.desktop（默认关）
nmd desktop status
nmd desktop uninstall          # 移除二进制、图标、桌面入口与自启条目
```

- 二进制装到已记录的 `binDir`（默认 `~/.local/bin/nmd-desktop`），图标与桌面入口
  写入 XDG data 目录；全部文件可检查、可手动删除
- `autostart` 是 XDG 自启条目，默认关闭，显式开启；`uninstall` 一并清除
- 四个实际安装路径和各产物的大小/摘要保存在安装目录 `.git/config` 的
  `nmd.desktopReceipt` 中；之后 XDG 或 `binDir` 环境变化不会重定向重装、自启与卸载。
  归属校验仅涉及这四个文件，不扫描源码、构建缓存、来源配置或用户数据。
- 未知同名文件、被修改的产物、硬链接、符号链接及链接父目录均拒绝覆盖/删除；
  卸载先检查全部路径，冲突时保留已有安装。只删除凭据内且内容仍匹配的文件。
- 旧版本只有 `desktopInstalled=true` 的布尔记录，不能证明文件归属：不会自动认领或删除。
  遇到 `desktop_file_not_owned` 时，先自行确认并备份/移走旧文件或外来文件，再显式重装。
  未安装且目标不存在时，卸载与关闭自启可重复执行，不触碰其他数据。
- 升级桌面壳：`nmd update` 拉取新代码后重跑 `nmd desktop install`
- 与 `cargo run` 的关系：同一份源码，install 只是构建后复制；日常调试用
  `cargo run`，日常使用走安装入口

## 与 `nmd gui` 的关系

两者可独立使用：`nmd gui` 单独跑时壳复用它；壳退出不影响外部启动的服务。
常驻采集器（systemd user unit）与壳完全无关，关闭壳不停止监控。

## 测试与 CI

首次成功读取空事件列表也会建立通知游标，随后出现的新事件正常通知；
启动时已有事件保持静默，列表清理或乱序不使游标回退。

Rust 侧单元测试只覆盖壳自身逻辑（回环 HTTP 探测、端口/能力判定、事件去重、
子进程回收），全部使用 loopback mock，不启动真实 GUI；CI 在 `desktop-shell`
job 中执行 `cargo fmt --check`、`cargo clippy --locked -- -D warnings`、
`cargo test --locked`。

浏览器 fixture 还渲染无脚本的本地错误页，纯 Rust 测试验证 URL 白名单和自定义安装路径。
这些检查不启动真实 Tauri 窗口，也不证明操作系统托盘/通知权限可用。
