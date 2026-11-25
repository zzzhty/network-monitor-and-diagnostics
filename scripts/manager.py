#!/usr/bin/env python3
"""Own the managed Git checkout, command links and update/apply lifecycle.

Git owns source revisions; .git/config's nmd section owns installation state.
The privileged local-setup.sh remains the owner of systemd and /etc/mihomo.
"""
import argparse
from contextlib import contextmanager
import errno
try:
    import fcntl
except ImportError:  # Windows lock uses msvcrt; Unix installs still flock.
    fcntl = None
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys
import sqlite3
import stat
import tempfile

import install_scope
import nmd_platform

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/zzzhty/network-monitor-and-diagnostics.git"
ASSETS = ("mihomo.deb", "geoip.metadb", "GeoSite.dat")
SERVICE_COMMANDS = {"status", "check", "verify", "logs", "start", "stop",
                    "diagnostics", "restart", "enable", "disable", "setup", "cutover",
                    "rollback", "test-stop"}
MUTATING_COMMANDS = SERVICE_COMMANDS - {"status", "check", "verify", "logs", "diagnostics"}


class ManagerError(Exception):
    pass


def _euid():
    """POSIX effective uid. None on Windows, where those checks do not run."""
    geteuid = getattr(os, "geteuid", None)
    return None if geteuid is None else geteuid()


def run(*args, cwd=None, capture=False):
    kwargs = {}
    if sys.platform == "win32":
        kwargs["encoding"] = "utf-8"
        kwargs["errors"] = "replace"
    result = subprocess.run([str(a) for a in args], cwd=cwd, check=True,
                            text=True, stdout=subprocess.PIPE if capture else None, **kwargs)
    return result.stdout.strip() if capture else None


def git(root, *args):
    return run("git", "-C", root, *args, capture=True)


def setting(root, key, value=None):
    if value is not None:
        run("git", "config", "--file", root / ".git/config", "nmd." + key, str(value))
        return value
    kwargs = {}
    if sys.platform == "win32":
        # Git stores the value as UTF-8. text=True alone follows the ANSI code
        # page, so a profile path such as José is misread before UTF-8 mode.
        kwargs["encoding"] = "utf-8"
        kwargs["errors"] = "replace"
    result = subprocess.run(["git", "config", "--file", str(root / ".git/config"),
                             "--get", "nmd." + key], capture_output=True, text=True, **kwargs)
    if result.returncode not in (0, 1):
        raise ManagerError(f"无法读取安装状态: {root}")
    return result.stdout.strip()


def scope_of(root):
    scope = setting(root, "scope")
    if scope not in {"user", "system"}:
        raise ManagerError("旧安装未记录 scope；请显式运行 nmd adopt --user 或 --system，不能通过 sudo 推断。")
    defaults = install_scope.paths(scope)
    if scope == "system" and root != defaults["home"]:
        raise ManagerError("系统安装必须位于 /opt/nmd；不能通过移动目录或改 scope 切换。")
    for key, default_key in (("configDir", "config_dir"), ("stateDir", "state_dir")):
        value = setting(root, key)
        if not value or not Path(value).is_absolute():
            raise ManagerError("安装路径记录不完整；请显式 adopt 修复，不能猜测新位置。")
        if scope == "system" and Path(value) != defaults[default_key]:
            raise ManagerError("系统安装配置/状态路径必须为 /etc/nmd 和 /var/lib/nmd-monitor。")
    return scope


def trusted_system_checkout(root, ancestors=True):
    for path in (root, *(root.parents if ancestors else ()), *root.rglob("*")):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ManagerError(f"系统安装必须完全由 root 拥有且不可由其他用户写入或链接: {path}")


def managed(root):
    if not (root / ".git").is_dir() or setting(root, "home") != str(root):
        if sys.platform == "win32":
            raise ManagerError("当前是源码仓库。请先运行 install.ps1，再通过新终端里的 nmd 管理安装。")
        raise ManagerError("当前是源码仓库。请先运行 ./install.sh，再通过 PATH 中的 nmd 管理安装。")
    scope = scope_of(root)
    if scope == "system" and root.stat().st_uid != 0:
        raise ManagerError("系统安装代码必须由 root 拥有。")
    if scope == "system":
        trusted_system_checkout(root)
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and root.stat().st_uid != geteuid():
        if scope == "system":
            raise ManagerError("系统安装管理需管理员显式运行 sudo /opt/nmd/nmd；个人安装不加 sudo。")
        raise ManagerError("请以个人安装目录的所属用户运行 nmd，不要在外层加 sudo。")


def clean(root):
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ManagerError("管理安装中存在未提交的修改；请先保存并处理这些修改，更新不会覆盖它们。")
    if git(root, "branch", "--show-current") != "main":
        raise ManagerError("管理安装必须位于 main 分支；请先检查本地分支状态。")


def _lock_handle(handle):
    if fcntl is not None:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ManagerError("另一个安装/更新/管理操作正在运行，请稍后重试。") from exc
        return
    import msvcrt
    handle.seek(0, os.SEEK_END)
    if handle.tell() < 1:
        handle.write("\0")
        handle.flush()
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        if getattr(exc, "winerror", None) in (32, 33) or exc.errno in (
                errno.EACCES, errno.EDEADLK, errno.EAGAIN):
            raise ManagerError("另一个安装/更新/管理操作正在运行，请稍后重试。") from exc
        raise


@contextmanager
def lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        _lock_handle(handle)
        yield


def link_target(path):
    """Compare the immediate target, never follow a foreign symlink chain."""
    return Path(os.path.abspath(path.parent / os.readlink(path)))


def preflight_windows_links(root, bindir):
    import nmd_windows
    if nmd_windows.command_inside_checkout(root, bindir) or nmd_windows.command_dir_blocked(bindir):
        raise ManagerError("命令目录必须在安装仓库之外，且不能放在 .local\\bin。智能应用控制会拦截那里的可执行文件。")
    path = Path(bindir) / "nmd.cmd"
    entry = Path(bindir) / "nmd-entry.ps1"
    if not path.exists() and not entry.exists():
        return
    try:
        text = entry.read_text(encoding="utf-8-sig", errors="replace") if entry.exists() else ""
    except OSError as exc:
        raise ManagerError(f"命令路径已被占用，未覆盖: {path}") from exc
    if "Managed by NMD install_scope:" not in text or str(root) not in text:
        raise ManagerError(f"命令路径已被占用，未覆盖: {path}")


def _windows_user_path(value=None):
    import winreg
    access = winreg.KEY_READ | (winreg.KEY_SET_VALUE if value is not None else 0)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, access) as key:
        if value is None:
            try:
                current, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                return ""
            return current
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, value)
    import ctypes
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 2, 5000, None)
    return value


def install_windows_links(root, bindir, register_path=True):
    import nmd_windows
    preflight_windows_links(root, bindir)
    bindir = Path(bindir)
    try:
        nmd_windows.require_interpreter(sys.executable)
    except nmd_windows.InterpreterError as exc:
        raise ManagerError(str(exc)) from exc
    bindir.mkdir(parents=True, exist_ok=True)
    path = bindir / "nmd.cmd"
    path.write_bytes(nmd_windows.render_cmd().encode("ascii"))
    entry = bindir / "nmd-entry.ps1"
    entry.write_bytes(b"\xef\xbb\xbf" + nmd_windows.render_entry_ps1(sys.executable, root).encode("utf-8"))
    if register_path:
        current = _windows_user_path()
        merged = nmd_windows.merge_user_path(current, bindir)
        if merged is not None:
            _windows_user_path(merged)
            print(f"已写入用户 PATH: {bindir}。请打开新的终端后再运行 nmd。", flush=True)
    setting(root, "binDir", bindir)
    setting(root, "python", sys.executable)
    print(f"命令入口: {path}", flush=True)


def remove_windows_links(root, bindir):
    import nmd_windows
    path = Path(bindir) / "nmd.cmd"
    entry = Path(bindir) / "nmd-entry.ps1"
    owned = False
    if entry.is_file():
        text = entry.read_text(encoding="utf-8-sig", errors="replace")
        owned = "Managed by NMD install_scope:" in text and str(root) in text
        if owned:
            entry.unlink()
            if path.is_file():
                path.unlink()
    task = Path(bindir) / "nmd-monitor-task.ps1"
    if task.is_file():
        text = task.read_text(encoding="utf-8", errors="replace")
        if str(root) in text and "Managed by NMD install_scope:" in text:
            task.unlink()
    if sys.platform == "win32":
        current = _windows_user_path()
        removed = nmd_windows.remove_user_path(current, bindir)
        if removed is not None:
            _windows_user_path(removed)


def preflight_links(root, bindir):
    if sys.platform == "win32":
        return preflight_windows_links(root, bindir)
    allowed = {root / "nmd"}
    path = bindir / "nmd"
    if path.exists() or path.is_symlink():
        if not path.is_symlink() or link_target(path) not in allowed:
            raise ManagerError(f"命令路径已被占用，未覆盖: {path}")


def install_links(root, bindir, register_path=True):
    if sys.platform == "win32":
        return install_windows_links(root, bindir, register_path=register_path)
    preflight_links(root, bindir)
    bindir.mkdir(parents=True, exist_ok=True)
    path = bindir / "nmd"
    if path.is_symlink() and link_target(path) != root / "nmd":
        path.unlink()
    if not path.is_symlink():
        path.symlink_to(root / "nmd")
    if not path.is_file() or not os.access(path, os.X_OK) or path.resolve() != root / "nmd":
        raise ManagerError(f"新命令入口校验失败，未清理旧命令: {path}")
    # Legacy mh/mihomoctl command links are never touched: the migration
    # option was retired after the old generation was fully cleaned up.
    if register_path and str(bindir) not in os.environ.get("PATH", "").split(os.pathsep):
        shell = Path(os.environ.get("SHELL", "/bin/sh")).name
        profile = Path.home() / {"zsh": ".zshrc", "bash": ".bashrc"}.get(shell, ".profile")
        line = f'export PATH={shlex.quote(str(bindir))}:"$PATH"'
        previous = profile.read_text() if profile.exists() else ""
        if line not in previous.splitlines():
            with profile.open("a") as stream:
                stream.write("\n# NMD commands\n" + line + "\n")
        print(f"已注册 PATH: {profile}；当前终端执行：{line}", flush=True)
    setting(root, "binDir", bindir)
    print(f"命令入口: {bindir}/nmd -> {root}/nmd", flush=True)


def validate_code(root):
    if sys.platform == "win32":
        for name in ("install.ps1", "nmd.ps1", "nmd.cmd", "scripts/nmd_windows.ps1"):
            if not (root / name).is_file():
                raise ManagerError(f"缺少 Windows 入口: {name}")
        for path in (root / "scripts").glob("*.py"):
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        return
    for name in ("install.sh", "nmd", "local-setup.sh"):
        run("bash", "-n", root / name)
    for path in (root / "scripts").glob("*.py"):
        compile(path.read_text(), str(path), "exec")


def ensure_assets(root):
    if any(not (root / name).is_file() for name in ASSETS):
        run("bash", root / "fetch-assets.sh")


def source_directory(root):
    # Installed scope uses its recorded location, never today's XDG environment.
    if (root / ".git").is_dir() and setting(root, "home") == str(root):
        scope_of(root)
        return Path(setting(root, "configDir")) / "egress"
    return install_scope.paths("user")["config_dir"] / "egress"


def network_command(root, command):
    run("bash", root / "local-setup.sh", command, "--sources-dir", source_directory(root))


def apply(root):
    """Make this checkout the running revision. One transaction on every platform.

    Pending is written before activation. A failed activation stays pending
    and does not record a revision. The only platform difference is
    ``activate``: Linux deploys mihomo and verifies it; macOS reloads an
    installed daemon and does not deploy the network.
    """
    # Pending is written before privileged work. A failed download, sudo,
    # validation, or service operation remains visible and retryable.
    setting(root, "pendingApply", "true")
    lines = activate(root)
    setting(root, "appliedRevision", git(root, "rev-parse", "HEAD"))
    setting(root, "pendingApply", "false")
    for line in lines:
        print(line, flush=True)


def activate(root):
    """Bring the installed runtime in line with this revision.

    Returns lines to print after the revision is recorded. Raising leaves
    pending set.
    """
    if nmd_platform.name() == "macos":
        return _activate_macos_daemon(root)
    ensure_assets(root)
    network_command(root, "apply")
    network_command(root, "verify")
    return ()


def _activate_macos_daemon(root):
    """Reload the installed daemon after geodata ensure and a read-only preflight.

    ``restart`` is stop then start, and start bootstraps a root job that is
    not loaded. The user LaunchAgent is not restarted and ``on_boot`` is not
    edited. Stopping an active takeover rolls the network back. A start that
    the supervisor treats as a new boot can begin a takeover when ``on_boot``
    is true, and a pending rollback session is finished on start.
    """
    from nmd_daemon import DaemonError, cli_daemon, daemon_receipt
    try:
        installed = daemon_receipt(root) is not None
    except DaemonError as exc:
        raise ManagerError("常驻守护收据无法读取；待应用状态保留。再次运行 nmd apply 重试。") from exc
    if not installed:
        return ("未安装常驻守护，没有执行 sudo，也没有重载进程。",
                "没有改路由、DNS、系统代理或 Tailscale。")
    try:
        code = cli_daemon(["restart"])
    except DaemonError as exc:
        raise ManagerError("常驻守护重载失败；待应用状态保留。再次运行 nmd apply 重试。") from exc
    if code != 0:
        raise ManagerError("常驻守护重载失败；待应用状态保留。再次运行 nmd apply 重试。")
    return ("常驻守护已重载（先 stop 再 start）。用户 LaunchAgent 未重载。",)


def bootstrap(args):
    scope = "system" if args.system else "user"
    if nmd_platform.name() == "windows" and scope == "system":
        raise ManagerError("Windows 只支持当前用户安装，不支持 --system。网络部署与系统服务仍仅限 Linux。")
    if nmd_platform.name() == "macos" and (scope == "system" or not args.manager_only):
        # macOS owns the desktop shell and read-only diagnostics only; the monitor
        # unit and network deployment stay Linux-only.
        raise ManagerError("macOS 仅支持个人范围 --manager-only 安装；网络部署与采集服务仍仅限 Linux。")
    if scope == "user" and os.environ.get("SUDO_USER"):
        raise ManagerError("个人安装请去掉 sudo；sudo 不会选择系统模式。系统安装需显式 --system。")
    if scope == "system" and _euid() != 0:
        raise ManagerError("--system 需要管理员显式以 root 运行安装器。")
    defaults = install_scope.paths(scope)
    args.home = args.home or defaults["home"]
    args.bin_dir = args.bin_dir or defaults["bin_dir"]
    if scope == "system" and (args.home != defaults["home"] or args.bin_dir != defaults["bin_dir"]):
        raise ManagerError("系统安装固定使用 /opt/nmd 和 /usr/local/bin，不能指向个人可写路径。")
    home_arg = args.home.expanduser()
    if home_arg.is_symlink():
        raise ManagerError(f"安装目录必须是独立克隆，不能是符号链接: {home_arg}")
    root = home_arg.resolve()
    if root == ROOT or ROOT in root.parents:
        raise ManagerError("安装目录必须独立于当前源码仓库。")
    bindir = args.bin_dir.expanduser().resolve()
    if scope == "system":
        for path in (root.parent, *root.parent.parents, bindir, *bindir.parents):
            if path.exists():
                info = path.lstat()
                if path.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                    raise ManagerError(f"系统安装父目录不可信: {path}")
    preflight_links(root, bindir)
    # A parent lock also covers first creation; it is not an installation receipt.
    with lock(root.parent / ("." + root.name.lstrip(".") + ".install.lock")):
        if root.exists():
            managed(root)
            if scope_of(root) != scope:
                raise ManagerError("不能原地切换 scope；先卸载旧 monitor，再显式迁移到新安装。")
            clean(root)
            if git(root, "remote", "get-url", "origin") != args.repository:
                raise ManagerError("安装目录的 origin 与请求仓库不同；未修改。")
            print("已有管理安装，保留当前版本；拉取新版本请使用 nmd update。", flush=True)
        else:
            root.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".nmd-clone-", dir=root.parent) as temp:
                stage = Path(temp) / "repo"
                run("git", "clone", "--branch", "main", "--single-branch", "--",
                    args.repository, stage)
                validate_code(stage)
                stage.rename(root)
            setting(root, "home", root)
            setting(root, "scope", scope)
            setting(root, "configDir", defaults["config_dir"])
            setting(root, "stateDir", defaults["state_dir"])
            setting(root, "pendingApply", "true")
        if scope == "system":
            trusted_system_checkout(root)
        with lock(root / ".git" / "nmd.lock"):
            install_links(root, bindir, scope == "user" and not args.no_path)
            if args.manager_only:
                if nmd_platform.name() == "macos":
                    print("管理安装已就绪。常驻守护要先写入真实地址的 daemon.json，"
                          "顺序见 docs/macos.md。可选：nmd desktop install 安装桌面壳。"
                          "不部署网络。", flush=True)
                else:
                    print("管理安装已就绪；运行 nmd monitor install 安装采集服务。网络配置仅由 nmd apply 显式应用。", flush=True)
            else:
                monitor_install(root)


def _restore_pending(root, previous):
    """Put pendingApply back when the fast-forward did not change HEAD.

    An unset value stays unset. Writing ``false`` over an absent key would
    make ``nmd status`` report a pending state the installation did not have.
    """
    if previous:
        setting(root, "pendingApply", previous)
        return
    subprocess.run(["git", "config", "--file", str(root / ".git/config"),
                    "--unset", "nmd.pendingApply"], check=False)


def update(root, check_only):
    managed(root)
    with lock(root / ".git" / "nmd.lock"):
        clean(root)
        git(root, "fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main")
        previous = git(root, "rev-parse", "HEAD")
        target = git(root, "rev-parse", "origin/main")
        if subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor",
                           previous, target]).returncode != 0:
            raise ManagerError("本地与远端历史分叉或远端回退；未切换版本，禁止自动 reset。")
        print(f"当前版本: {previous}\n远端版本: {target}", flush=True)
        if check_only:
            print("有更新" if previous != target else "已是最新版本", flush=True)
            if setting(root, "pendingApply") == "true":
                if nmd_platform.name() == "macos":
                    print("当前安装仍待应用；运行 nmd apply。已安装常驻守护时，会先做只读预检，"
                      "通过后才执行 daemon restart。", flush=True)
                else:
                    print("当前安装仍待系统部署；运行 nmd apply 显式应用。", flush=True)
            return
        if previous != target:
            # Validate a candidate without replacing the working installation.
            with tempfile.TemporaryDirectory(prefix="nmd-update-") as temp:
                candidate = Path(temp) / "candidate"
                git(root, "worktree", "add", "--detach", str(candidate), target)
                try:
                    validate_code(candidate)
                    if scope_of(root) == "system":
                        trusted_system_checkout(candidate, ancestors=False)
                finally:
                    git(root, "worktree", "remove", "--force", str(candidate))
            clean(root)
            if git(root, "rev-parse", "HEAD") != previous:
                raise ManagerError("校验期间安装版本被其他程序修改；未更新。")
            previous_pending = setting(root, "pendingApply")
            setting(root, "pendingApply", "true")
            try:
                git(root, "merge", "--ff-only", target)
            except subprocess.CalledProcessError:
                _restore_pending(root, previous_pending)
                raise
        print("代码更新完成；没有应用网络配置或重启服务。需要时运行 nmd apply。", flush=True)
        if nmd_platform.name() == "macos" and setting(root, "desktopInstalled") == "true":
            print("桌面壳仍是已安装的那一份；这次更新没有重装 ~/Applications 里的应用，"
                  "菜单名和目录大小写也不会变。需要时运行 nmd desktop install"
                  "（无 sudo，会构建）。", flush=True)
        if nmd_platform.name() == "macos":
            # launchd keeps running the old code until the daemon restarts.
            try:
                from nmd_daemon import daemon_receipt
                installed = daemon_receipt(root) is not None
            except Exception:
                installed = False
            if installed:
                print("常驻守护仍在运行旧代码；执行 nmd apply 会先做只读预检，通过后才重载"
                      "（即 nmd macos daemon restart，先 stop 再 start）。"
                      "若当时有接管，stop 会回退网络；on_boot 为 true 时，"
                      "新的一次开机可能开始接管。", flush=True)


def monitor_install(root):
    if nmd_platform.name() == "windows":
        python = Path(sys.executable)
        import nmd_windows
        try:
            nmd_windows.require_interpreter(python)
        except nmd_windows.InterpreterError as exc:
            raise ManagerError(str(exc)) from exc
        install_scope.install_windows_monitor(
            root, Path(setting(root, "configDir")), Path(setting(root, "stateDir")),
            Path(setting(root, "binDir")), python)
        setting(root, "python", python)
        setting(root, "monitorInstalled", "true")
        print("已登记计划任务；未启动，也未设置登录时运行。需要时再执行 nmd monitor enable 或 nmd monitor start。", flush=True)
        return
    install_scope.install_monitor(root, scope_of(root),
                                  Path(setting(root, "configDir")), Path(setting(root, "stateDir")))
    setting(root, "monitorInstalled", "true")


# --- Desktop shell (Tauri) user-level lifecycle; Linux and macOS, logic stays in Rust/Python split. ---

DESKTOP_BIN_NAME = "nmd-desktop"
DESKTOP_CRATE = Path("apps/desktop/src-tauri")
DESKTOP_BUILD_TIMEOUT = 900
DESKTOP_PATH_KEYS = {"linux": frozenset({"binary", "icon", "entry", "autostart"}),
                     "darwin": frozenset({"binary", "info", "icon", "autostart"})}


def _desktop_entry(binary_path):
    escaped = str(binary_path).replace("\\", "\\\\").replace('"', '\\"')
    return ("[Desktop Entry]\nType=Application\nVersion=1.0\n"
            "Name=NMD\nComment=网络监控与诊断 · 出口节点面板\n"
            f'Exec="{escaped}"\nIcon=nmd-desktop\n'
            "Categories=Network;Utility;\nTerminal=false\n")


def _desktop_homes():
    home = Path.home()
    data = os.environ.get("XDG_DATA_HOME", "")
    config = os.environ.get("XDG_CONFIG_HOME", "")
    data = Path(data) if data and Path(data).is_absolute() else home / ".local/share"
    config = Path(config) if config and Path(config).is_absolute() else home / ".config"
    return data, config


def _desktop_metadata(crate):
    """The bundle identity mirrors tauri.conf.json; no second source of truth."""
    try:
        data = json.loads((crate / "tauri.conf.json").read_text(encoding="utf-8"))
        identifier, version, product = data["identifier"], str(data["version"]), data["productName"]
        if not all(isinstance(value, str) and value for value in (identifier, version, product)):
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        raise ManagerError(
            "desktop_config_invalid:tauri.conf.json 缺少有效的 identifier/version/productName;未安装") from None
    return identifier, version, product


def _xml(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _macos_info_plist(executable, identifier, version, name):
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n'
            '\t<key>CFBundleDevelopmentRegion</key><string>zh_CN</string>\n'
            f'\t<key>CFBundleExecutable</key><string>{_xml(executable)}</string>\n'
            f'\t<key>CFBundleIdentifier</key><string>{_xml(identifier)}</string>\n'
            '\t<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\n'
            f'\t<key>CFBundleName</key><string>{_xml(name)}</string>\n'
            f'\t<key>CFBundleDisplayName</key><string>{_xml(name)}</string>\n'
            '\t<key>CFBundlePackageType</key><string>APPL</string>\n'
            '\t<key>CFBundleIconFile</key><string>AppIcon</string>\n'
            f'\t<key>CFBundleShortVersionString</key><string>{_xml(version)}</string>\n'
            f'\t<key>CFBundleVersion</key><string>{_xml(version)}</string>\n'
            '\t<key>LSMinimumSystemVersion</key><string>10.13</string>\n'
            '\t<key>NSHighResolutionCapable</key><true/>\n'
            '</dict>\n</plist>\n')


def _macos_launchagent_plist(executable, label):
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n'
            f'\t<key>Label</key><string>{_xml(label)}</string>\n'
            '\t<key>ProgramArguments</key>\n\t<array>\n'
            f'\t\t<string>{_xml(executable)}</string>\n'
            '\t</array>\n'
            '\t<key>RunAtLoad</key><true/>\n'
            '</dict>\n</plist>\n')


def _macos_paths(root):
    identifier, _, product = _desktop_metadata(root / DESKTOP_CRATE)
    app = Path.home() / "Applications" / f"{product}.app"
    return {"binary": app / "Contents/MacOS" / DESKTOP_BIN_NAME,
            "info": app / "Contents/Info.plist",
            "icon": app / "Contents/Resources/AppIcon.icns",
            "autostart": Path.home() / "Library/LaunchAgents" / f"{identifier}.plist"}


def _macos_bundle_root(paths):
    # paths["binary"] lives at <product>.app/Contents/MacOS/nmd-desktop.
    return paths["binary"].parents[2]


def _macos_check_bundle(paths, receipt):
    """The bundle directory itself must be absent or receipt-proven, not only its files."""
    app = _macos_bundle_root(paths)
    install_scope._plain_path(app)
    if not app.exists():
        return
    if not app.is_dir():
        raise ManagerError(f"desktop_file_not_owned:应用包路径被非目录文件占用;未修改: {app}")
    if not receipt:
        raise ManagerError(f"desktop_file_not_owned:存在无归属记录的应用包;未覆盖/删除: {app}")


def _desktop_receipt(root):
    raw = setting(root, "desktopReceipt")
    if not raw:
        return None
    try:
        receipt = json.loads(raw)
        if (receipt["version"] != 1 or receipt["root"] != str(root)
                or set(receipt["paths"]) != DESKTOP_PATH_KEYS.get(sys.platform, frozenset())
                or not isinstance(receipt["files"], dict)
                or set(receipt["files"]) - set(receipt["paths"])):
            raise ValueError()
        for path in receipt["paths"].values():
            install_scope._absolute(path)
        for fingerprint in receipt["files"].values():
            if (set(fingerprint) != {"size", "sha256"}
                    or type(fingerprint["size"]) is not int or fingerprint["size"] < 0
                    or not isinstance(fingerprint["sha256"], str)
                    or len(fingerprint["sha256"]) != 64):
                raise ValueError()
        return receipt
    except (ValueError, KeyError, TypeError, install_scope.ScopeError):
        raise ManagerError("desktop_invalid_receipt:安装归属记录无效;未修改文件") from None


def _save_desktop_receipt(root, receipt):
    setting(root, "desktopReceipt", json.dumps(receipt, sort_keys=True))


def desktop_paths(root):
    receipt = _desktop_receipt(root)
    if receipt:
        return {key: Path(path) for key, path in receipt["paths"].items()}
    if sys.platform == "darwin":
        return _macos_paths(root)
    data, config = _desktop_homes()
    return {"binary": Path(setting(root, "binDir")) / DESKTOP_BIN_NAME,
            "icon": data / "icons/hicolor/32x32/apps/nmd-desktop.png",
            "entry": data / "applications/nmd-desktop.desktop",
            "autostart": config / "autostart/nmd-desktop.desktop"}


def _desktop_fingerprint(path):
    # Only the four installed artifacts, never the checkout/build cache or data.
    return {"size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _desktop_check(path, key, receipt):
    install_scope._plain_path(path)
    if not path.exists():
        return
    info = path.stat()
    owned = receipt["files"].get(key) if receipt else None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != _euid() or info.st_mode & 0o022
            or not owned or owned["size"] != info.st_size
            or _desktop_fingerprint(path) != owned):
        raise ManagerError(f"desktop_file_not_owned:文件不属于此安装或已被修改;未覆盖/删除: {path}")


def _desktop_copy(source, destination, mode, check):
    check()
    destination.parent.mkdir(parents=True, exist_ok=True)
    install_scope._plain_path(destination)
    fd, temporary = tempfile.mkstemp(prefix="." + destination.name + ".", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream, source.open("rb") as original:
            shutil.copyfileobj(original, stream)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        check()
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _desktop_remember(root, receipt, key, path):
    receipt["files"][key] = _desktop_fingerprint(path)
    _save_desktop_receipt(root, receipt)


def _desktop_write_file(root, receipt, key, path, content):
    _desktop_check(path, key, receipt)
    path.parent.mkdir(parents=True, exist_ok=True)
    install_scope._atomic_write(path, content, 0o644)
    _desktop_remember(root, receipt, key, path)


def _desktop_write_entry(root, receipt, key, paths):
    _desktop_write_file(root, receipt, key, paths[key], _desktop_entry(paths["binary"]))


def desktop_main(root, args):
    if sys.platform not in DESKTOP_PATH_KEYS:
        raise ManagerError("desktop_requires_unix:桌面壳仅在 Linux/macOS 上安装与验证")
    if args and args[0] == "autostart":
        if len(args) != 2 or args[1] not in {"on", "off"}:
            raise ManagerError("用法: nmd desktop autostart on|off")
    elif len(args) != 1 or args[0] not in {"install", "uninstall", "status"}:
        raise ManagerError("用法: nmd desktop install|uninstall|status 或 nmd desktop autostart on|off")
    paths = desktop_paths(root)
    if args[0] == "install":
        _desktop_install(root, paths)
    elif args[0] == "uninstall":
        _desktop_uninstall(root, paths)
    elif args[0] == "autostart":
        _desktop_autostart(root, paths, args[1])
    else:
        _desktop_status(root, paths)


def _dir_identity(path):
    """Device and inode via lstat, so a symlink is not the directory it names."""
    info = os.lstat(path)
    return (info.st_dev, info.st_ino)


def _stored_dir_entry(path):
    """The directory entry as stored, not the case requested by ``path``.

    Returns the entry, ``None`` when nothing matches, or ``"ambiguous"`` when
    more than one case variant exists. An exact name wins over a folded one.
    """
    parent = path.parent
    try:
        names = [entry.name for entry in parent.iterdir()]
    except OSError:
        return None
    if path.name in names:
        return parent / path.name
    folded = [name for name in names if name.casefold() == path.name.casefold()]
    if len(folded) == 1:
        return parent / folded[0]
    if folded:
        return "ambiguous"
    return None


def _desired_occupied(stored, desired):
    """``absent``, ``same`` inode, or ``other``. Existence alone is not enough."""
    try:
        exists = desired.exists()
    except OSError as exc:
        raise ManagerError(
            "desktop_bundle_case_failed:无法确认目标目录;未改名、未删除") from exc
    if not exists:
        return "absent"
    try:
        same = _dir_identity(stored) == _dir_identity(desired)
    except OSError as exc:
        raise ManagerError(
            "desktop_bundle_case_failed:无法确认目标目录;未改名、未删除") from exc
    return "same" if same else "other"


def _two_step_case_rename(stored, desired):
    """Change only the stored case of one directory. Never unlinks it."""
    try:
        stored_id = _dir_identity(stored)
    except OSError as exc:
        raise ManagerError(
            "desktop_bundle_case_failed:无法确认应用包;未改名、未删除") from exc
    temp = stored.parent / f".nmd-bundle-case-{os.getpid()}-{stored_id[1]}"
    try:
        if temp.exists():
            raise ManagerError(
                "desktop_bundle_case_busy:临时改名路径已存在;未改名、未删除")
    except ManagerError:
        raise
    except OSError as exc:
        raise ManagerError(
            "desktop_bundle_case_failed:无法确认临时路径;未改名、未删除") from exc
    try:
        os.rename(stored, temp)
        try:
            os.rename(temp, desired)
        except OSError:
            try:
                os.rename(temp, stored)
            except OSError:
                pass
            raise
    except ManagerError:
        raise
    except OSError as exc:
        raise ManagerError(
            "desktop_bundle_case_failed:应用包大小写未能改好;未删除原目录") from exc
    after = _stored_dir_entry(desired)
    ok = isinstance(after, Path) and after.name == desired.name
    if ok:
        try:
            ok = _dir_identity(after) == stored_id
        except OSError:
            ok = False
    if not ok:
        try:
            if (not stored.exists() and desired.exists() and not desired.is_symlink()
                    and _dir_identity(desired) == stored_id):
                os.rename(desired, stored)
        except OSError:
            pass
        raise ManagerError(
            "desktop_bundle_case_failed:应用包大小写未能改好;未删除原目录")
    return after


def _align_bundle_directory(current, desired):
    """Point a receipt bundle at the product name when only case differs.

    ``exists(NMD.app)`` is true for ``nmd.app`` on a case-insensitive volume,
    and both names are one inode. This renames that entry. It does not treat
    the two spellings as different apps and does not delete either.
    """
    stored = _stored_dir_entry(current)
    if stored is None:
        return current
    if stored == "ambiguous":
        raise ManagerError(
            "desktop_bundle_case_conflict:目标目录大小写不唯一;未改名、未删除")
    if stored.is_symlink() or not stored.is_dir():
        raise ManagerError(
            "desktop_bundle_case_failed:应用包不是普通目录;未改名、未删除")
    if stored.name == desired.name:
        return stored
    if stored.parent != desired.parent or stored.name.casefold() != desired.name.casefold():
        return current
    if desired.is_symlink():
        raise ManagerError(
            "desktop_bundle_case_failed:目标路径是符号链接;未改名、未删除")
    if _desired_occupied(stored, desired) == "other":
        raise ManagerError(
            "desktop_bundle_case_conflict:目标目录已被另一份应用占用;未改名、未删除")
    return _two_step_case_rename(stored, desired)


def _retarget_paths(paths, old_app, new_app):
    old, new = str(old_app), str(new_app)
    updated = {}
    for key, path in paths.items():
        text = str(path)
        if text == old or text.startswith(old + os.sep):
            updated[key] = Path(new + text[len(old):])
        else:
            updated[key] = path
    return updated


def _rewrite_autostart_binary(root, receipt, paths, old_binary, new_binary):
    """Point an existing login item at the renamed bundle.

    The plist stores the path as XML, so a home directory containing ``&``,
    ``<``, ``>`` or quotes is not the raw string on disk. Parse the values and
    replace only an argument equal to the old path. Other keys stay. This does
    not create a login item and does not turn RunAtLoad on.
    """
    path = paths.get("autostart")
    if path is None or str(old_binary) == str(new_binary):
        return
    if "autostart" not in (receipt.get("files") or {}) or not path.is_file():
        return
    old, new = str(old_binary), str(new_binary)
    try:
        data = plistlib.loads(path.read_bytes())
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException) as exc:
        raise ManagerError(
            "desktop_autostart_unreadable:登录项不是可解析的 plist;未改写、未删除") from exc
    if not isinstance(data, dict):
        raise ManagerError(
            "desktop_autostart_unreadable:登录项不是可解析的 plist;未改写、未删除")
    arguments = data.get("ProgramArguments")
    if (not isinstance(arguments, list)
            or any(not isinstance(item, str) for item in arguments)):
        raise ManagerError(
            "desktop_autostart_unreadable:登录项没有程序参数;未改写、未删除")
    if old not in arguments:
        return
    updated = dict(data)
    updated["ProgramArguments"] = [new if item == old else item for item in arguments]
    text = plistlib.dumps(updated, sort_keys=False).decode("utf-8")
    _desktop_write_file(root, receipt, "autostart", path, text)


def _macos_refresh_bundle_case(root, receipt, paths):
    """Rename nmd.app to NMD.app when the product name changed only by case."""
    _, _, product = _desktop_metadata(root / DESKTOP_CRATE)
    desired = Path.home() / "Applications" / f"{product}.app"
    current = _macos_bundle_root(paths)
    if (current.parent != desired.parent
            or current.name.casefold() != desired.name.casefold()
            or not current.exists()):
        return paths
    install_scope._plain_path(current)
    new_app = _align_bundle_directory(current, desired)
    if new_app.name == current.name and str(new_app) == str(current):
        return paths
    new_paths = _retarget_paths(paths, current, new_app)
    previous = dict(receipt["paths"])
    receipt["paths"] = {key: str(path) for key, path in new_paths.items()}
    try:
        _save_desktop_receipt(root, receipt)
    except Exception:
        receipt["paths"] = previous
        try:
            if not current.exists() and new_app.exists() and not new_app.is_symlink():
                os.rename(new_app, current)
        except OSError:
            pass
        raise
    try:
        _rewrite_autostart_binary(
            root, receipt, new_paths, paths["binary"], new_paths["binary"])
    except Exception:
        # The directory and the receipt already agree. Leave both; do not delete.
        raise
    return new_paths


def _plist_visible_name(info_path):
    try:
        import plistlib
        data = plistlib.loads(info_path.read_bytes())
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        return None
    if not isinstance(data, dict):
        return None
    for key in ("CFBundleDisplayName", "CFBundleName"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _macos_name_hint(root, paths):
    try:
        _, _, product = _desktop_metadata(root / DESKTOP_CRATE)
    except ManagerError:
        return None
    app = _macos_bundle_root(paths)
    try:
        present = app.exists()
    except OSError:
        return None
    if not present:
        return None
    stored = _stored_dir_entry(app)
    stored_name = stored.name if isinstance(stored, Path) else None
    visible = None
    info = paths.get("info")
    if info is not None and info.is_file():
        visible = _plist_visible_name(info)
    wanted = f"{product}.app"
    folder_mismatch = (stored_name is not None and stored_name.casefold() == wanted.casefold()
                       and stored_name != wanted)
    name_mismatch = visible is not None and visible != product
    if not folder_mismatch and not name_mismatch:
        return None
    shown = visible or stored_name or product
    return (f"显示名称: {shown}。源码产品名是 {product}。"
            "nmd update 不会重装桌面壳；要改菜单名和目录大小写，请运行 "
            "nmd desktop install（无 sudo，会构建）。")


def _macos_install(root, receipt, paths, built, crate):
    """Wrap the cargo binary in a minimal unsigned local .app; no bundler dependency."""
    identifier, version, product = _desktop_metadata(crate)
    _desktop_copy(built, paths["binary"], 0o755,
                  lambda: _desktop_check(paths["binary"], "binary", receipt))
    _desktop_remember(root, receipt, "binary", paths["binary"])
    _desktop_copy(crate / "icons/icon.icns", paths["icon"], 0o644,
                  lambda: _desktop_check(paths["icon"], "icon", receipt))
    _desktop_remember(root, receipt, "icon", paths["icon"])
    _desktop_write_file(root, receipt, "info", paths["info"],
                        _macos_info_plist(DESKTOP_BIN_NAME, identifier, version, product))


def _desktop_install(root, paths):
    if scope_of(root) != "user":
        raise ManagerError("desktop_requires_user_scope:桌面壳仅支持用户范围安装")
    receipt = _desktop_receipt(root)
    for key, path in paths.items():
        _desktop_check(path, key, receipt)
    if sys.platform == "darwin":
        _macos_check_bundle(paths, receipt)
    if not shutil.which("cargo"):
        raise ManagerError("desktop_requires_cargo:未找到 cargo;请先安装 Rust 工具链(rustup)后重试")
    crate = root / DESKTOP_CRATE
    if not (crate / "Cargo.toml").is_file():
        raise ManagerError("desktop_crate_missing:管理安装缺少桌面壳源码;请先 nmd update 后重试")
    if sys.platform == "darwin" and not (crate / "icons/icon.icns").is_file():
        raise ManagerError("desktop_icons_missing:管理安装缺少桌面壳图标(icon.icns);请先 nmd update 后重试")
    print("正在构建桌面壳(cargo build --release --locked,首次可能需要数分钟)...", flush=True)
    try:
        run("cargo", "build", "--release", "--locked", cwd=crate)
    except subprocess.CalledProcessError:
        raise ManagerError("desktop_build_failed:cargo 构建失败;请检查上方输出后重试") from None
    built = crate / "target/release" / DESKTOP_BIN_NAME
    if not built.is_file() or built.is_symlink() or not os.access(built, os.X_OK):
        raise ManagerError("desktop_build_output_missing:构建产物缺失或不可执行")
    receipt = receipt or {"version": 1, "root": str(root),
                          "paths": {key: str(path) for key, path in paths.items()}, "files": {}}
    _save_desktop_receipt(root, receipt)
    if sys.platform == "darwin":
        paths = _macos_refresh_bundle_case(root, receipt, paths)
        _macos_install(root, receipt, paths, built, crate)
    else:
        for key, source, mode in (("binary", built, 0o755),
                                  ("icon", crate / "icons/icon.png", 0o644)):
            _desktop_copy(source, paths[key], mode,
                          lambda: _desktop_check(paths[key], key, receipt))
            _desktop_remember(root, receipt, key, paths[key])
        _desktop_write_entry(root, receipt, "entry", paths)
    setting(root, "desktopInstalled", "true")
    if sys.platform == "darwin":
        print(f"已安装: {_macos_bundle_root(paths)}\n"
              f"开机自启(默认关): nmd desktop autostart on", flush=True)
    else:
        print(f"已安装: {paths['binary']}\n桌面入口: {paths['entry']}\n"
              f"开机自启(默认关): nmd desktop autostart on", flush=True)


def _desktop_autostart(root, paths, state):
    receipt = _desktop_receipt(root)
    _desktop_check(paths["autostart"], "autostart", receipt)
    if state == "on":
        if (not receipt or setting(root, "desktopInstalled") != "true"
                or not paths["binary"].is_file()):
            raise ManagerError("desktop_not_installed:请先运行 nmd desktop install")
        _desktop_check(paths["binary"], "binary", receipt)
        if sys.platform == "darwin":
            # The label travels with the recorded autostart path, not today's config.
            content = _macos_launchagent_plist(paths["binary"], paths["autostart"].stem)
        else:
            content = _desktop_entry(paths["binary"])
        _desktop_write_file(root, receipt, "autostart", paths["autostart"], content)
        setting(root, "desktopAutostart", "true")
        print(f"开机自启已开启: {paths['autostart']}", flush=True)
    else:
        paths["autostart"].unlink(missing_ok=True)
        if receipt:
            receipt["files"].pop("autostart", None)
            _save_desktop_receipt(root, receipt)
        setting(root, "desktopAutostart", "false")
        print("开机自启已关闭", flush=True)


def _desktop_uninstall(root, paths):
    receipt = _desktop_receipt(root)
    # Preflight all paths first: a foreign collision must not partially uninstall.
    for key, path in paths.items():
        _desktop_check(path, key, receipt)
    if sys.platform == "darwin":
        _macos_check_bundle(paths, receipt)
    for key, path in paths.items():
        _desktop_check(path, key, receipt)
        path.unlink(missing_ok=True)
        if receipt:
            receipt["files"].pop(key, None)
            _save_desktop_receipt(root, receipt)
    if sys.platform == "darwin":
        app = _macos_bundle_root(paths)
        install_scope._plain_path(app)
        if app.exists():
            # Only the receipt-proven bundle remainder (directories) is left here.
            shutil.rmtree(app)
    setting(root, "desktopInstalled", "false")
    setting(root, "desktopAutostart", "false")
    print("桌面壳已卸载;保留 cargo 构建缓存,不影响 dashboard 与监控。", flush=True)


def _desktop_status(root, paths):
    installed = paths["binary"].is_file()
    if sys.platform == "darwin":
        app = _macos_bundle_root(paths)
        hint = _macos_name_hint(root, paths)
        print(f"安装范围: {scope_of(root)}\n"
              f"桌面壳: {'已安装' if installed else '未安装'}\n"
              f"应用包: {app} ({'存在' if app.is_dir() else '不存在'})\n"
              f"开机自启: {'已开启' if paths['autostart'].is_file() else '未开启'}\n"
              + (f"{hint}\n" if hint else "")
              + "提示: 开启自启 nmd desktop autostart on;卸载 nmd desktop uninstall",
              flush=True)
        return
    print(f"安装范围: {scope_of(root)}\n"
          f"桌面壳: {'已安装' if installed else '未安装'}\n"
          f"二进制: {paths['binary']}\n"
          f"桌面入口: {paths['entry']} ({'存在' if paths['entry'].is_file() else '不存在'})\n"
          f"开机自启: {'已开启' if paths['autostart'].is_file() else '未开启'}\n"
          f"提示: 开启自启 nmd desktop autostart on;卸载 nmd desktop uninstall", flush=True)


def monitor_uninstall(root):
    if nmd_platform.name() == "windows":
        install_scope.windows_task(root, Path(setting(root, "binDir")), "uninstall")
        setting(root, "monitorInstalled", "false")
        print("已删除计划任务；保留配置、日志与历史。", flush=True)
        return
    install_scope.uninstall_monitor(root, scope_of(root),
                                    Path(setting(root, "configDir")), Path(setting(root, "stateDir")))
    setting(root, "monitorInstalled", "false")


def adopt(root, scope):
    # An explicit receipt repair only; never move a checkout or change ownership.
    if not (root / ".git").is_dir() or setting(root, "home") != str(root):
        raise ManagerError("adopt 只适用于路径未变化的旧管理安装；不能直接 mv 安装目录。")
    if root.stat().st_uid != _euid():
        raise ManagerError("必须由安装所属用户执行 adopt。")
    old = setting(root, "scope")
    if old and old != scope:
        raise ManagerError("adopt 不能切换 scope；请卸载旧 monitor 后在新路径显式安装。")
    defaults = install_scope.paths(scope)
    if scope == "system" and (_euid() != 0 or root != defaults["home"]):
        raise ManagerError("系统 adopt 要求 root-owned /opt/nmd；旧个人目录不能直接改为系统模式。")
    if scope == "system":
        trusted_system_checkout(root)
    with lock(root / ".git/nmd.lock"):
        setting(root, "scope", scope)
        # Repeating adoption must not redirect an existing installation when
        # the caller's XDG environment changes.
        if not setting(root, "configDir"):
            setting(root, "configDir", defaults["config_dir"])
        if not setting(root, "stateDir"):
            setting(root, "stateDir", defaults["state_dir"])
    print("已明确记录 scope；现有网络与监控数据未改变。")


def installation_status(root):
    print(f"安装范围: {scope_of(root)}\n管理目录: {root}\n远端: {git(root, 'remote', 'get-url', 'origin')}\n"
          f"管理版本: {git(root, 'rev-parse', '--short', 'HEAD')}\n"
          f"上次部署并验证的版本: {setting(root, 'appliedRevision') or '尚未记录'}\n"
          f"待应用: {setting(root, 'pendingApply') or 'true'}\n"
          f"工作区: {'有修改' if git(root, 'status', '--porcelain') else '干净'}", flush=True)


MACOS_HELP = """\
NMD macOS：默认只做监控和诊断，不接管流量

与 Linux 共享的动词留在顶层，包括 apply / refresh。macOS 的 apply 仍可能 bootstrap 未加载的 root job，并回退正在进行的接管。nmd macos 是 Darwin 实验面，不是只有这里会改网络。

监控和诊断
  monitor config-check --config FILE
  monitor run --config FILE --state-dir DIR [--once]
  monitor status [--state-dir DIR] [--dry-run]
                                       --dry-run 打印合成快照后退出，不读本机、不建状态目录
  gui [--state-dir DIR] [--config FILE] [--port PORT] [--dry-run]
                                       面板可在「设置与帮助」编辑监控配置。
                                       --dry-run 用合成数据打开面板，不采集本机、不读来源配置
  machine capabilities | machine status --state-dir DIR
  desktop install|uninstall|status|autostart on|off
                                       用户级桌面壳，见 docs/desktop.md

安装、更新、应用
  bootstrap --manager-only             建立管理安装。macOS 必须带 --manager-only
  update [--check]                     快进代码。不部署网络，不重载守护
  apply / refresh                      记录当前版本。已安装守护时先补齐缺少的地理数据，
                                       再做只读预检，通过后才 daemon restart。
                                       restart 等于先 stop 再 start。下载或预检失败不 stop。
                                       不部署 Linux 网络，不改 on_boot，不调用 takeover-start。
                                       用户 LaunchAgent 不在这次重载里。
                                       进行中的接管会被 stop 回退。
                                       on_boot 为 true 时，新的一次开机可能开始接管

实验性常驻守护（按下面的顺序；不是与外部客户端一起用时的默认路径）
  这一节才是 nmd macos。顶层的 apply 不在这里，但 macOS 上它仍可能 bootstrap 并回退接管。
  onboard                              交互终端逐项填写。确认前不下载、不写配置
  onboard --server ADDR --port PORT
  onboard --inputs FILE                非交互。不安装 Tailscale。mihomo 不在时才放到
                                       当前用户可写目录。不加载守护，不把 on_boot 改成 true，
                                       不执行 apply。不要 sudo
  macos geodata ensure [--geodata-dir DIR] [--inputs FILE]
                                       下载缺少的 geosite.dat / geoip.metadb。不要 sudo。
                                       预检、help、status 和面板不会跑这一步
  macos preflight [--tier readonly|daemon|takeover] [--json|--summary]
                                       只读预检。终端逐项显示并在末尾给中文摘要；
                                       非终端默认仍是完整 JSON。--json 只要 JSON。
                                       --summary 在非终端也给摘要。默认 readonly。不会下载
  macos daemon init --inputs FILE [--mihomo PATH]
                                       写入 daemon.json。on_boot 固定为 JSON false。
                                       拒绝占位地址 203.0.113.20。不覆盖已有文件。不要 sudo
  macos daemon on-boot [on|off|status]
                                       只读写 takeover.on_boot。不加载守护，也不开始接管。
                                       不要 sudo。之后的 start 或 apply 只有在被当成新的一次开机时
                                       才可能马上接管。
                                       on-boot、init、onboard 成功 JSON 里的 loaded_daemon: false
                                       表示这条命令没有去加载守护，不表示守护处于未加载
  macos daemon install|uninstall|start|stop|restart|status|takeover-start|takeover-stop
                                       root supervisor 与用户 daemon。这些动作不改 on_boot。
                                       restart 等于先 stop 再 start。stop 失败不 start。
                                       未加载的 root job 会在 start 里 bootstrap 已安装的 plist。
                                       用户 LaunchAgent 不在这次 restart 里。预检失败则不 stop。
                                       进行中的接管会被这次 stop 回退
  macos accept                         2 分钟验收：独立 root 回退进程就绪后才改网络
  macos takeover|rollback              实验性 sudo 前台接管。见 docs/macos-mihomo-tailscale.md

Linux 的网络部署与 systemd 生命周期在 macOS 不支持。
子命令一览：nmd macos
"""

MACOS_SUBCOMMANDS = """\
nmd macos 子命令。这是实验路径，不是默认监控。总览见 nmd help。
这些才是 nmd macos 的子命令；nmd apply、nmd update、nmd onboard 不在这里。

  geodata ensure [--geodata-dir DIR] [--inputs FILE]
  preflight [--tier readonly|daemon|takeover] [--json|--summary]
  daemon init --inputs FILE [--mihomo PATH]
  daemon on-boot [on|off|status]
  daemon install|uninstall|start|stop|restart|status|takeover-start|takeover-stop
  accept --inputs FILE --state-dir DIR
  takeover --inputs FILE
  rollback [--state-dir DIR]

restart 等于先 stop 再 start。install、start、restart 和 apply 不改 on_boot。
init 拒绝占位地址 203.0.113.20。某一条的参数：nmd macos <子命令> --help
"""

# Top-level verbs typed under `nmd macos`. Exit 2 before any daemon or takeover work.
MACOS_WRONG_PREFIX = {
    "apply": "没有 nmd macos apply。用 nmd apply。",
    "refresh": "没有 nmd macos refresh。用 nmd refresh。",
    "update": "没有 nmd macos update。用 nmd update。",
    "onboard": "没有 nmd macos onboard。用 nmd onboard。",
    "monitor": "没有 nmd macos monitor。用 nmd monitor status、nmd monitor run 或 nmd monitor config-check。",
    "gui": "没有 nmd macos gui。用 nmd gui。",
    "machine": "没有 nmd macos machine。用 nmd machine status 或 nmd machine capabilities。",
    "desktop": "没有 nmd macos desktop。用 nmd desktop。",
    "bootstrap": "没有 nmd macos bootstrap。用 nmd bootstrap --manager-only。",
    "version": "没有 nmd macos version。用 nmd version。",
}

MACOS_LIFECYCLE_REJECTION = {
    "start": "顶层 nmd start 是 Linux 的 mihomo 命令，macOS 不运行它。对应的实验命令是 nmd macos daemon start。警告：那个 start 会 bootstrap 未加载的 root job。本命令没有执行 sudo，也没有加载 launchd。",
    "stop": "顶层 nmd stop 是 Linux 的 mihomo 命令，macOS 不运行它。对应的实验命令是 nmd macos daemon stop。警告：那个 stop 会回退正在进行的接管；回退未完成则不会 bootout 仍在恢复的管理器。本命令没有执行 sudo，也没有加载 launchd。",
    "restart": "顶层 nmd restart 是 Linux 的 mihomo 命令，macOS 不运行它。对应的实验命令是 nmd macos daemon restart。警告：那是先 stop 再 start；stop 失败不 start；start 会 bootstrap 未加载的 root job；用户 LaunchAgent 不在内。本命令没有执行 sudo，也没有加载 launchd。",
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    command = argv[0] if argv else "help"
    platform = nmd_platform.name()
    if command == "demo":
        raise ManagerError("没有 demo 命令。合成数据用 nmd gui --dry-run，或 nmd monitor status --dry-run。")
    if command == "daemon":
        raise ManagerError(
            "没有顶层 daemon 命令。macOS 的 root 管理器是 nmd macos daemon。"
            "Linux 的 mihomo 仍用顶层 start、stop、restart。本命令没有加载 launchd。")
    if command == "onboard":
        from nmd_onboard import main as onboard_main
        raise SystemExit(onboard_main(argv[1:]))
    service_actions = {"install", "uninstall", "start", "stop", "restart", "enable", "disable", "logs", "service-status"}
    if platform == "windows":
        rejected = set(SERVICE_COMMANDS) | set(MUTATING_COMMANDS) | {
            "apply", "refresh", "install-cli", "adopt", "desktop", "source", "channel"}
        if command in rejected:
            raise ManagerError(
                "此命令仅支持 Linux。Windows 只运行本机采集和诊断；"
                "网络部署、出口来源、systemd 和桌面壳安装不在此平台。")
        if command in {"help", "--help", "-h"}:
            print("NMD Windows：本机采集与诊断（不接管流量）\n"
                  "  monitor config-check --config FILE\n"
                  "  monitor run --config FILE [--state-dir DIR] [--once]  前台采集\n"
                  "  monitor status [--state-dir DIR] [--dry-run]  --dry-run 只打印合成快照\n"
                  "  monitor install    登记当前用户的计划任务，不启动、不设登录触发\n"
                  "  monitor enable     登录时启动；不立即采集\n"
                  "  monitor disable    取消登录触发；不停止正在运行的采集\n"
                  "  monitor start|stop|restart|service-status|logs|uninstall\n"
                  "  gui [--port PORT] [--dry-run]  面板可编辑监控配置；--dry-run 只用合成数据\n"
                  "  machine capabilities | machine status\n"
                  "  bootstrap          当前用户安装（不要加 --system）\n"
                  "  update [--check]   快进更新代码，不部署网络、不重启任务\n"
                  "  install / uninstall\n"
                  "Linux 的 mihomo、Tailscale、VPS 与 systemd 在 Windows 不支持。\n"
                  "计划任务在登录后运行，不等同于开机即采集。详见 docs/windows.md。")
            return
    if platform not in ("linux", "windows"):
        allowed = {"monitor", "gui", "machine", "help", "--help", "-h", "version"}
        if platform == "macos":
            # User-level shell lifecycle, code update, and an explicit apply that
            # reloads an installed daemon after preflight. That reload can roll
            # back an active takeover. Linux network deploy and systemd stay
            # unsupported. `macos` is the experimental takeover controller.
            allowed |= {"desktop", "bootstrap", "update", "apply", "refresh", "macos", "onboard"}
        if platform == "macos" and command in MACOS_LIFECYCLE_REJECTION:
            raise ManagerError(MACOS_LIFECYCLE_REJECTION[command])
        if (command not in allowed
                or (command == "monitor" and len(argv) > 1 and argv[1] in service_actions)):
            raise ManagerError("此命令仅支持 Linux；macOS 仅支持源码诊断 CLI、只读诊断 GUI"
                               "（「设置与帮助」页可编辑监控配置）、"
                               "管理安装（bootstrap --manager-only）、代码更新、"
                               "nmd apply / refresh（预检通过后才重载已安装的常驻守护）、"
                               "用户级桌面壳与常驻守护（nmd macos daemon）；"
                               "不管理 Linux 网络部署或 systemd。")
        if command in {"help", "--help", "-h"}:
            print(MACOS_HELP, end="")
            return
        if command == "version":
            if argv[1:]:
                raise ManagerError("version 不接受额外参数。")
            print(git(ROOT, "rev-parse", "HEAD"))
            return
    if command in {"source", "channel"}:
        import json
        import egress_sources
        try:
            installed = (ROOT / ".git").is_dir() and setting(ROOT, "home") == str(ROOT)
            if installed:
                managed(ROOT)
            egress_sources.main(argv[1:], directory=source_directory(ROOT), allow_directory_override=not installed)
        except (egress_sources.SourceError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            code = str(exc) if isinstance(exc, egress_sources.SourceError) else "source_operation_failed"
            print(json.dumps({"schema_version": 1, "error": code}), file=sys.stderr)
            raise SystemExit(1)
        return
    if command == "update":
        parser = argparse.ArgumentParser(prog="nmd update")
        parser.add_argument("--home", type=Path, default=ROOT,
                            help="明确选择已有管理安装（旧版本迁移时由新版源码运行）")
        parser.add_argument("--check", action="store_true")
        args = parser.parse_args(argv[1:])
        update(args.home.expanduser().resolve(), args.check)
        return
    if command == "adopt":
        parser = argparse.ArgumentParser(prog="nmd adopt")
        parser.add_argument("--home", type=Path, default=ROOT)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--user", action="store_true")
        group.add_argument("--system", action="store_true")
        args = parser.parse_args(argv[1:])
        adopt(args.home.expanduser().resolve(), "system" if args.system else "user")
        return
    if command == "monitor" and len(argv) == 2 and argv[1] in {
            "install", "uninstall", "start", "stop", "restart", "enable", "disable", "logs", "service-status"}:
        managed(ROOT)
        with lock(ROOT / ".git/nmd.lock"):
            if argv[1] == "install":
                monitor_install(ROOT)
            elif argv[1] == "uninstall":
                monitor_uninstall(ROOT)
            elif nmd_platform.name() == "windows":
                if argv[1] == "logs":
                    install_scope.windows_logs(Path(setting(ROOT, "stateDir")) / "monitor.log")
                else:
                    install_scope.windows_task(
                        ROOT, Path(setting(ROOT, "binDir")),
                        "status" if argv[1] == "service-status" else argv[1])
            else:
                install_scope.check_monitor(ROOT, scope_of(ROOT), Path(setting(ROOT, "configDir")))
                install_scope.service(scope_of(ROOT), "status" if argv[1] == "service-status" else argv[1])
        return
    if command == "desktop":
        if not argv[1:] or argv[1] in {"-h", "--help", "help"}:
            print("用法: nmd desktop install|uninstall|status 或 nmd desktop autostart on|off\n"
                  "用户级桌面壳(Linux/macOS);构建需要 Rust 工具链。详见 docs/desktop.md。", flush=True)
            return
        managed(ROOT)
        with lock(ROOT / ".git" / "nmd.lock"):
            desktop_main(ROOT, argv[1:])
        return
    if command == "macos":
        # Darwin-only by construction: on Linux the platform gate above never
        # opens this path, and the controller itself re-execs under sudo —
        # so never let another platform fall through into that re-exec.
        if platform != "macos":
            print(f"未知命令: {command}", file=sys.stderr)
            raise SystemExit(2)
        if len(argv) > 1 and argv[1] in MACOS_WRONG_PREFIX:
            print(MACOS_WRONG_PREFIX[argv[1]], file=sys.stderr)
            raise SystemExit(2)
        if argv[1:2] == ["preflight"]:
            from macos_preflight import main as preflight_main
            raise SystemExit(preflight_main(argv[2:]))
        if argv[1:2] == ["geodata"]:
            from macos_geodata import main as geodata_main
            raise SystemExit(geodata_main(argv[2:]))
        if argv[1:2] == ["daemon"]:
            from nmd_daemon import cli_daemon
            raise SystemExit(cli_daemon(argv[2:]))
        if len(argv) == 1 or argv[1] in {"help", "-h", "--help"}:
            print(MACOS_SUBCOMMANDS, end="")
            return
        if argv[1] not in {"accept", "takeover", "rollback",
                           "rollback-watch", "rollback-sentinel"}:
            print(MACOS_SUBCOMMANDS, end="", file=sys.stderr)
            raise SystemExit(2)
        from macos_takeover import main as takeover_cli
        raise SystemExit(takeover_cli(argv[1:]))
    if command in {"monitor", "gui", "machine"}:
        # Observability also works in an uninstalled checkout, without sudo.
        from observability import main as observe, run_synthetic_if_requested
        try:
            if run_synthetic_if_requested(argv):
                return
            kwargs = {"sources_dir": None}
            if platform == "linux":
                kwargs["sources_dir"] = source_directory(ROOT)
            if (platform == "linux"
                    and (ROOT / ".git").is_dir() and setting(ROOT, "home") == str(ROOT)):
                scope = scope_of(ROOT)
                kwargs = {"state_dir": Path(setting(ROOT, "stateDir")),
                          "config_file": Path(setting(ROOT, "configDir")) / "monitor.json",
                          "sources_dir": source_directory(ROOT)}
                if (scope == "system" and not any(arg in {"--help", "-h"} for arg in argv)
                        and not (command == "machine" and argv[1:] == ["capabilities"])):
                    import pwd
                    try:
                        account = pwd.getpwnam("nmd-monitor")
                    except KeyError:
                        raise ManagerError("系统 monitor 尚未安装；管理员先运行 nmd monitor install。")
                    if _euid() != account.pw_uid:
                        raise ManagerError("系统监控数据仅限 nmd-monitor UID；GUI/读取请由管理员以该身份运行，或使用个人模式。不会放宽权限。")
            elif (platform == "windows"
                    and (ROOT / ".git").is_dir() and setting(ROOT, "home") == str(ROOT)):
                kwargs = {"state_dir": Path(setting(ROOT, "stateDir")),
                          "config_file": Path(setting(ROOT, "configDir")) / "monitor.json",
                          "sources_dir": None}
            elif (platform == "macos" and command == "gui"
                    and (ROOT / ".git").is_dir() and setting(ROOT, "home") == str(ROOT)):
                # Manager-only install: the dashboard edits the recorded config
                # file; uninstalled checkouts use the XDG default on their own.
                kwargs["config_file"] = Path(setting(ROOT, "configDir")) / "monitor.json"
            observe(argv, **kwargs)
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            import json
            print(json.dumps({"schema_version": 1, "error": type(exc).__name__,
                              "message": "diagnostics operation failed; check config, state permissions, or collector lock"}))
            raise SystemExit(1)
        return
    if command == "bootstrap":
        parser = argparse.ArgumentParser(description="克隆独立 NMD 安装；默认个人模式，系统模式需 --system")
        parser.add_argument("--system", action="store_true")
        parser.add_argument("--home", type=Path)
        parser.add_argument("--repository", default=os.environ.get("NMD_REPOSITORY", REPOSITORY))
        parser.add_argument("--bin-dir", type=Path)
        parser.add_argument("--manager-only", action="store_true", help="仅安装管理命令，暂不部署系统")
        parser.add_argument("--no-path", action="store_true", help="不修改 shell PATH 文件")
        bootstrap(parser.parse_args(argv[1:]))
        return
    if command in ("help", "--help", "-h"):
        print("通道管理：nmd channel --help（兼容 nmd source；私有配置、显式刷新和选择）\n独立诊断：nmd monitor --help | nmd gui --help | nmd machine capabilities\n合成数据：nmd monitor status --dry-run | nmd gui --dry-run\n\n"
              "  onboard                 交互终端逐项填写。端口直接回车为 1080。确认前不下载、不写配置。\n"
              "                         非终端请用 onboard --server ADDR --port 1080 或 --inputs FILE。\n"
              "                         Tailscale 缺失则停止（仓库没有安装器）。\n"
              "                         mihomo 缺失时只跑 fetch-assets.sh 下载 deb，不 dpkg、不 setup、不 apply。\n"
              "                         /usr/bin/mihomo 仍不可执行则不写端点文件。不要 sudo\n\n"
              "NMD 生命周期：\n  install      安装当前 scope 的 monitor 单元（不自动启动）\n"
              "  update --check  拉取 main 并查看可用更新\n  update       校验、快进更新代码（不 apply）\n"
              "  apply / refresh  重新应用当前版本，不拉取远端\n"
              "  monitor install/start/stop/restart/enable/disable/logs/service-status/uninstall\n"
              "               管理已记录 scope 的采集器（独立于 mihomo）\n"
              "  uninstall    卸载采集器和命令链接；保留配置、历史与代码\n"
              "  desktop install/uninstall/status/autostart on|off\n"
              "               用户级桌面壳（Linux/macOS，构建需 Rust；见 docs/desktop.md）\n"
              "  version      查看管理安装版本\n  install-cli  修复已安装的命令链接\n", flush=True)
        run("bash", ROOT / "local-setup.sh", "help")
        return
    known = SERVICE_COMMANDS | {"update", "install", "apply", "refresh", "version", "install-cli", "uninstall"}
    if command not in known:
        print(f"未知命令: {command}", file=sys.stderr)
        raise SystemExit(2)
    if argv[1:]:
        raise ManagerError("不支持的参数；运行 nmd help 查看命令。")
    managed(ROOT)
    if command in ("install", "uninstall"):
        with lock(ROOT / ".git/nmd.lock"):
            if command == "install":
                monitor_install(ROOT)
            else:
                monitor_uninstall(ROOT)
                if nmd_platform.name() == "windows":
                    remove_windows_links(ROOT, Path(setting(ROOT, "binDir")))
                    print("已卸载计划任务和 nmd.cmd；保留代码、配置与历史。")
                else:
                    link = Path(setting(ROOT, "binDir")) / "nmd"
                    if link.is_symlink() and link_target(link) == ROOT / "nmd":
                        link.unlink()
                    print("已卸载 monitor 和所属命令链接；保留代码、配置与历史，不影响 mihomo/tailscaled。")
    elif command in ("apply", "refresh"):
        with lock(ROOT / ".git" / "nmd.lock"):
            apply(ROOT)
    elif command == "install-cli":
        with lock(ROOT / ".git" / "nmd.lock"):
            install_links(ROOT, Path(setting(ROOT, "binDir")), register_path=scope_of(ROOT) == "user")
    elif command == "version":
        print(git(ROOT, "rev-parse", "HEAD"))
    elif command in MUTATING_COMMANDS:
        with lock(ROOT / ".git" / "nmd.lock"):
            network_command(ROOT, command)
    else:
        if command == "status":
            installation_status(ROOT)
        network_command(ROOT, command)


if __name__ == "__main__":
    try:
        main()
    except (ManagerError, OSError, SyntaxError, ValueError, install_scope.ScopeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: 命令失败 ({exc.returncode}): {shlex.join(map(str, exc.cmd))}", file=sys.stderr)
        sys.exit(exc.returncode if exc.returncode > 0 else 1)

