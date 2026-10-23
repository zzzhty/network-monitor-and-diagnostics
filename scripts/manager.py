#!/usr/bin/env python3
"""Own the managed Git checkout, command links and update/apply lifecycle.

Git owns source revisions; .git/config's nmd section owns installation state.
The privileged local-setup.sh remains the owner of systemd and /etc/mihomo.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
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


def run(*args, cwd=None, capture=False):
    result = subprocess.run([str(a) for a in args], cwd=cwd, check=True,
                            text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def git(root, *args):
    return run("git", "-C", root, *args, capture=True)


def setting(root, key, value=None):
    if value is not None:
        run("git", "config", "--file", root / ".git/config", "nmd." + key, str(value))
        return value
    result = subprocess.run(["git", "config", "--file", str(root / ".git/config"),
                             "--get", "nmd." + key], capture_output=True, text=True)
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
        raise ManagerError("当前是源码仓库。请先运行 ./install.sh，再通过 PATH 中的 nmd 管理安装。")
    scope = scope_of(root)
    if scope == "system" and root.stat().st_uid != 0:
        raise ManagerError("系统安装代码必须由 root 拥有。")
    if scope == "system":
        trusted_system_checkout(root)
    if root.stat().st_uid != os.geteuid():
        if scope == "system":
            raise ManagerError("系统安装管理需管理员显式运行 sudo /opt/nmd/nmd；个人安装不加 sudo。")
        raise ManagerError("请以个人安装目录的所属用户运行 nmd，不要在外层加 sudo。")


def clean(root):
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ManagerError("管理安装中存在未提交的修改；请先保存并处理这些修改，更新不会覆盖它们。")
    if git(root, "branch", "--show-current") != "main":
        raise ManagerError("管理安装必须位于 main 分支；请先检查本地分支状态。")


@contextmanager
def lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ManagerError("另一个安装/更新/管理操作正在运行，请稍后重试。") from exc
        yield


def link_target(path):
    """Compare the immediate target, never follow a foreign symlink chain."""
    return Path(os.path.abspath(path.parent / os.readlink(path)))


def migration_targets(migrate_from):
    if migrate_from is None:
        return set()
    old = migrate_from.expanduser().resolve()
    if not old.is_dir() or not (old / ".git").is_dir():
        raise ManagerError(f"迁移来源必须是已有 Git 源码目录: {old}")
    return {old / "mihomoctl", old / "nmd"}


def preflight_links(root, bindir, migrate_from=None):
    allowed = {root / "nmd"} | migration_targets(migrate_from)
    path = bindir / "nmd"
    if path.exists() or path.is_symlink():
        if not path.is_symlink() or link_target(path) not in allowed:
            raise ManagerError(f"命令路径已被占用，未覆盖: {path}")


def install_links(root, bindir, migrate_from=None, register_path=True):
    preflight_links(root, bindir, migrate_from)
    bindir.mkdir(parents=True, exist_ok=True)
    path = bindir / "nmd"
    if path.is_symlink() and link_target(path) != root / "nmd":
        path.unlink()
    if not path.is_symlink():
        path.symlink_to(root / "nmd")
    if not path.is_file() or not os.access(path, os.X_OK) or path.resolve() != root / "nmd":
        raise ManagerError(f"新命令入口校验失败，未清理旧命令: {path}")
    # Explicit migration only: delete exactly owned links after nmd is ready.
    # Keep foreign commands, the old checkout, and all runtime data untouched.
    allowed = migration_targets(migrate_from)
    for name in ("mh", "mihomoctl"):
        legacy = bindir / name
        if legacy.is_symlink() and link_target(legacy) in allowed:
            legacy.unlink()
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


def deploy(root, command="deploy"):
    ensure_assets(root)
    # Pending is written before privileged work. A failed sudo/validation/service
    # operation remains visible and retryable; never report it as applied.
    setting(root, "pendingApply", "true")
    network_command(root, command)
    network_command(root, "verify")
    setting(root, "appliedRevision", git(root, "rev-parse", "HEAD"))
    setting(root, "pendingApply", "false")


def bootstrap(args):
    scope = "system" if args.system else "user"
    if scope == "user" and os.environ.get("SUDO_USER"):
        raise ManagerError("个人安装请去掉 sudo；sudo 不会选择系统模式。系统安装需显式 --system。")
    if scope == "system" and os.geteuid() != 0:
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
    preflight_links(root, bindir, args.migrate_from)
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
            install_links(root, bindir, args.migrate_from, scope == "user" and not args.no_path)
            if args.manager_only:
                print("管理安装已就绪；运行 nmd monitor install 安装采集服务。网络配置仅由 nmd apply 显式应用。", flush=True)
            else:
                monitor_install(root)


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
            setting(root, "pendingApply", "true")
            git(root, "merge", "--ff-only", target)
        print("代码更新完成；没有应用网络配置或重启服务。需要时运行 nmd apply。", flush=True)


def monitor_install(root):
    install_scope.install_monitor(root, scope_of(root),
                                  Path(setting(root, "configDir")), Path(setting(root, "stateDir")))
    setting(root, "monitorInstalled", "true")


# --- Desktop shell (Tauri) user-level lifecycle; Linux only, logic stays in Rust/Python split. ---

DESKTOP_BIN_NAME = "nmd-desktop"
DESKTOP_CRATE = Path("apps/desktop/src-tauri")
DESKTOP_BUILD_TIMEOUT = 900


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


def _desktop_receipt(root):
    raw = setting(root, "desktopReceipt")
    if not raw:
        return None
    try:
        receipt = json.loads(raw)
        if (receipt["version"] != 1 or receipt["root"] != str(root)
                or set(receipt["paths"]) != {"binary", "icon", "entry", "autostart"}
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
            or info.st_uid != os.geteuid() or info.st_mode & 0o022
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


def _desktop_write_entry(root, receipt, key, paths):
    path = paths[key]
    _desktop_check(path, key, receipt)
    path.parent.mkdir(parents=True, exist_ok=True)
    install_scope._atomic_write(path, _desktop_entry(paths["binary"]), 0o644)
    _desktop_remember(root, receipt, key, path)


def desktop_main(root, args):
    if sys.platform != "linux":
        raise ManagerError("desktop_requires_linux:桌面壳仅在 Linux 上安装与验证")
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


def _desktop_install(root, paths):
    if scope_of(root) != "user":
        raise ManagerError("desktop_requires_user_scope:桌面壳仅支持用户范围安装")
    receipt = _desktop_receipt(root)
    for key, path in paths.items():
        _desktop_check(path, key, receipt)
    if not shutil.which("cargo"):
        raise ManagerError("desktop_requires_cargo:未找到 cargo;请先安装 Rust 工具链(rustup)后重试")
    crate = root / DESKTOP_CRATE
    if not (crate / "Cargo.toml").is_file():
        raise ManagerError("desktop_crate_missing:管理安装缺少桌面壳源码;请先 nmd update 后重试")
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
    for key, source, mode in (("binary", built, 0o755),
                              ("icon", crate / "icons/icon.png", 0o644)):
        _desktop_copy(source, paths[key], mode,
                      lambda: _desktop_check(paths[key], key, receipt))
        _desktop_remember(root, receipt, key, paths[key])
    _desktop_write_entry(root, receipt, "entry", paths)
    setting(root, "desktopInstalled", "true")
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
        _desktop_write_entry(root, receipt, "autostart", paths)
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
    for key, path in paths.items():
        _desktop_check(path, key, receipt)
        path.unlink(missing_ok=True)
        if receipt:
            receipt["files"].pop(key, None)
            _save_desktop_receipt(root, receipt)
    setting(root, "desktopInstalled", "false")
    setting(root, "desktopAutostart", "false")
    print("桌面壳已卸载;保留 cargo 构建缓存,不影响 dashboard 与监控。", flush=True)


def _desktop_status(root, paths):
    installed = paths["binary"].is_file()
    print(f"安装范围: {scope_of(root)}\n"
          f"桌面壳: {'已安装' if installed else '未安装'}\n"
          f"二进制: {paths['binary']}\n"
          f"桌面入口: {paths['entry']} ({'存在' if paths['entry'].is_file() else '不存在'})\n"
          f"开机自启: {'已开启' if paths['autostart'].is_file() else '未开启'}\n"
          f"提示: 开启自启 nmd desktop autostart on;卸载 nmd desktop uninstall", flush=True)


def monitor_uninstall(root):
    install_scope.uninstall_monitor(root, scope_of(root),
                                    Path(setting(root, "configDir")), Path(setting(root, "stateDir")))
    setting(root, "monitorInstalled", "false")


def adopt(root, scope):
    # An explicit receipt repair only; never move a checkout or change ownership.
    if not (root / ".git").is_dir() or setting(root, "home") != str(root):
        raise ManagerError("adopt 只适用于路径未变化的旧管理安装；不能直接 mv 安装目录。")
    if root.stat().st_uid != os.geteuid():
        raise ManagerError("必须由安装所属用户执行 adopt。")
    old = setting(root, "scope")
    if old and old != scope:
        raise ManagerError("adopt 不能切换 scope；请卸载旧 monitor 后在新路径显式安装。")
    defaults = install_scope.paths(scope)
    if scope == "system" and (os.geteuid() != 0 or root != defaults["home"]):
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


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    command = argv[0] if argv else "help"
    platform = nmd_platform.name()
    service_actions = {"install", "uninstall", "start", "stop", "restart", "enable", "disable", "logs", "service-status"}
    if platform != "linux":
        if (command not in {"monitor", "gui", "machine", "demo", "help", "--help", "-h", "version"}
                or (command == "monitor" and len(argv) > 1 and argv[1] in service_actions)):
            raise ManagerError("此命令仅支持 Linux；macOS 仅支持源码诊断 CLI、只读 GUI 和模拟 demo，不管理网络或后台服务。")
        if command in {"help", "--help", "-h"}:
            print("NMD macOS 实验性只读诊断（不接管流量）\n"
                  "  demo [--once] [--port PORT]  临时合成数据演示，不采集本机、不读取来源配置\n"
                  "  monitor config-check --config FILE\n"
                  "  monitor run --config FILE --state-dir DIR [--once]  显式前台采集\n"
                  "  monitor status --state-dir DIR\n"
                  "  gui --state-dir DIR [--port PORT]\n"
                  "  machine capabilities | machine status --state-dir DIR\n"
                  "Linux 网络管理、安装/更新和 systemd 生命周期在 macOS 不支持。")
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
            else:
                install_scope.check_monitor(ROOT, scope_of(ROOT), Path(setting(ROOT, "configDir")))
                install_scope.service(scope_of(ROOT), "status" if argv[1] == "service-status" else argv[1])
        return
    if command == "desktop":
        if not argv[1:] or argv[1] in {"-h", "--help", "help"}:
            print("用法: nmd desktop install|uninstall|status 或 nmd desktop autostart on|off\n"
                  "用户级桌面壳(Linux);构建需要 Rust 工具链。详见 docs/desktop.md。", flush=True)
            return
        managed(ROOT)
        with lock(ROOT / ".git" / "nmd.lock"):
            desktop_main(ROOT, argv[1:])
        return
    if command in {"monitor", "gui", "machine", "demo"}:
        # Observability also works in an uninstalled checkout, without sudo.
        from observability import main as observe
        try:
            kwargs = {"sources_dir": None}
            if platform == "linux" and command != "demo":
                kwargs["sources_dir"] = source_directory(ROOT)
            if (platform == "linux" and command != "demo"
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
                    if os.geteuid() != account.pw_uid:
                        raise ManagerError("系统监控数据仅限 nmd-monitor UID；GUI/读取请由管理员以该身份运行，或使用个人模式。不会放宽权限。")
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
        parser.add_argument("--migrate-from", type=Path,
                            help="迁移此旧 Git 目录的命令链接；仅删除指向该目录的 mh/mihomoctl 链接，保留源码和数据")
        parser.add_argument("--manager-only", action="store_true", help="仅安装管理命令，暂不部署系统")
        parser.add_argument("--no-path", action="store_true", help="不修改 shell PATH 文件")
        bootstrap(parser.parse_args(argv[1:]))
        return
    if command in ("help", "--help", "-h"):
        print("通道管理：nmd channel --help（兼容 nmd source；私有配置、显式刷新和选择）\n独立诊断：nmd monitor --help | nmd gui --help | nmd machine capabilities | nmd demo\n\nNMD 生命周期：\n  install      安装当前 scope 的 monitor 单元（不自动启动）\n"
              "  update --check  拉取 main 并查看可用更新\n  update       校验、快进更新代码（不 apply）\n"
              "  apply / refresh  重新应用当前版本，不拉取远端\n"
              "  monitor install/start/stop/restart/enable/disable/logs/service-status/uninstall\n"
              "               管理已记录 scope 的采集器（独立于 mihomo）\n"
              "  uninstall    卸载采集器和命令链接；保留配置、历史与代码\n"
              "  desktop install/uninstall/status/autostart on|off\n"
              "               用户级桌面壳（Linux，构建需 Rust；见 docs/desktop.md）\n"
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
                link = Path(setting(ROOT, "binDir")) / "nmd"
                if link.is_symlink() and link_target(link) == ROOT / "nmd":
                    link.unlink()
                print("已卸载 monitor 和所属命令链接；保留代码、配置与历史，不影响 mihomo/tailscaled。")
    elif command in ("apply", "refresh"):
        with lock(ROOT / ".git" / "nmd.lock"):
            deploy(ROOT, "apply")
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

