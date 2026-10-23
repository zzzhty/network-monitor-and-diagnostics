"""Install and control only the independent NMD monitor, never networking services.

System installation is deliberately explicit: its caller must already be root.
Installing a unit does not enable/start it and never enables user lingering.
"""
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile

UNIT_NAME = "nmd-monitor.service"
SERVICE_USER = "nmd-monitor"
SERVICE_COMMANDS = frozenset({"start", "stop", "restart", "enable", "disable", "status", "logs"})
MARKER = "# Managed by NMD install_scope: "


class ScopeError(RuntimeError):
    pass


def _scope(scope):
    if scope not in {"user", "system"}:
        raise ScopeError("安装范围必须为 user 或 system。")
    return scope


def paths(scope, home=None):
    """Return defaults without creating paths or resolving symlinks.

    An explicit home isolates all user paths from the process's XDG variables.
    Relative XDG values are ignored, as required by the XDG specification.
    """
    _scope(scope)
    if scope == "system":
        result = dict(home=Path("/opt/nmd"), bin_dir=Path("/usr/local/bin"),
                      config_dir=Path("/etc/nmd"), state_dir=Path("/var/lib/nmd-monitor"),
                      unit_file=Path("/etc/systemd/system") / UNIT_NAME)
    else:
        user_home = Path.home() if home is None else Path(home)
        config_base = user_home / ".config"
        state_base = user_home / ".local/state"
        if home is None:
            for name, default in (("XDG_CONFIG_HOME", config_base), ("XDG_STATE_HOME", state_base)):
                value = os.environ.get(name, "")
                candidate = Path(value) if value and Path(value).is_absolute() else default
                if name == "XDG_CONFIG_HOME":
                    config_base = candidate
                else:
                    state_base = candidate
        result = dict(home=user_home / ".nmd", bin_dir=user_home / ".local/bin",
                      config_dir=config_base / "nmd", state_dir=state_base / "nmd-monitor",
                      unit_file=config_base / "systemd/user" / UNIT_NAME)
    result["config_file"] = result["config_dir"] / "monitor.json"
    result["unit"] = result["unit_file"]
    return result


def _absolute(path):
    path = Path(path).expanduser()
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise ScopeError(f"安装路径必须为无控制字符的绝对路径: {path}")
    return path


def _plain_path(path):
    """Reject symlinks (including ancestor symlinks) before any write."""
    path = _absolute(path)
    for component in reversed((path, *path.parents)):
        if component.is_symlink():
            raise ScopeError(f"安装路径不能含符号链接: {component}")
    return path


def _require_root(scope):
    if scope == "system" and os.geteuid() != 0:
        raise ScopeError("system 范围操作需要 root；请显式使用 sudo nmd。")


def _run(*args):
    return subprocess.run([str(arg) for arg in args], check=True)


def _systemctl(scope, *args):
    return _run("systemctl", *(["--user"] if scope == "user" else []), *args)


def service(scope, command):
    """Control precisely one monitor unit; enable/disable do not start/stop it."""
    _scope(scope)
    if command not in SERVICE_COMMANDS:
        raise ScopeError(f"未知监控服务命令: {command}")
    if command not in {"status", "logs"}:
        _require_root(scope)
    if command == "logs":
        return _run("journalctl", *(["--user"] if scope == "user" else []),
                    "--unit", UNIT_NAME, "--no-pager", "-n", "100")
    options = ["--no-pager", "--full"] if command == "status" else []
    return _systemctl(scope, command, *options, UNIT_NAME)


def _unit_argument(value, exec_start=False):
    value = str(_absolute(value)).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if exec_start:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def _provenance(root, scope):
    return MARKER + json.dumps({"root": str(root), "scope": scope}, sort_keys=True)


def _unit_path(scope, config_dir):
    # The configured location is installation state, not today's XDG environment.
    return (Path("/etc/systemd/system") / UNIT_NAME if scope == "system"
            else config_dir.parent / "systemd/user" / UNIT_NAME)


def _check_unit(unit, root, scope):
    _plain_path(unit)
    if unit.exists():
        info = unit.stat()
        if (not unit.is_file() or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise ScopeError(f"服务文件不是独立普通文件，未修改: {unit}")
        expected = _provenance(root, scope)
        if unit.read_text().splitlines()[:1] != [expected]:
            raise ScopeError(f"服务文件不属于此安装，未修改: {unit}")


def check_monitor(root, scope, config_dir):
    """Verify this installation owns a present monitor unit, without commands."""
    _scope(scope)
    root, config_dir = _plain_path(root), _plain_path(config_dir)
    unit = _unit_path(scope, config_dir)
    _check_unit(unit, root, scope)
    if not unit.exists():
        raise ScopeError("监控服务尚未安装；请先运行 nmd monitor install。")
    return unit


def _unit_text(root, scope, config_file, state_dir):
    lines = [_provenance(root, scope), "[Unit]",
             "Description=Network Monitor & Diagnostics (NMD)", "After=network.target", "",
             "[Service]", "Type=simple"]
    if scope == "system":
        lines += [f"User={SERVICE_USER}", f"Group={SERVICE_USER}"]
    command = ["/usr/bin/python3", root / "scripts/observability.py", "monitor", "run",
               "--config", config_file, "--state-dir", state_dir]
    if scope == "user":
        # Automatic failover runs in the collector; the system-scope service
        # account cannot read a user's private source registry by design.
        command += ["--sources-dir", config_file.parent / "egress"]
    lines += ["ExecStart=" + " ".join(_unit_argument(part, True) if isinstance(part, Path)
                                     else part for part in command),
              "Restart=on-failure", "RestartSec=5s", "UMask=0077",
              "Environment=PYTHONDONTWRITEBYTECODE=1", "NoNewPrivileges=true"]
    if scope == "system":
        lines += ["PrivateTmp=true", "ProtectSystem=strict", "ProtectHome=true",
                  "RestrictSUIDSGID=true", "CapabilityBoundingSet=", "AmbientCapabilities=",
                  "ReadWritePaths=" + _unit_argument(state_dir)]
    lines += ["", "[Install]", "WantedBy=" + ("default.target" if scope == "user" else "multi-user.target"), ""]
    return "\n".join(lines)


def _validate_system_code(root):
    """A root-installed service must never execute user-writable code."""
    _plain_path(root)
    if any(root == base or base in root.parents for base in (Path("/home"), Path("/root"), Path("/run/user"))):
        raise ScopeError("system 范围的代码不能位于用户主目录；默认使用 /opt/nmd。")
    for path in (root, *root.parents):
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ScopeError(f"system 代码及父目录必须由 root 拥有且不可由其他用户写入: {path}")
    for path in (root / "scripts", *(root / "scripts").rglob("*")):
        if path.is_symlink():
            raise ScopeError(f"system 脚本不能是符号链接: {path}")
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ScopeError(f"system 脚本必须由 root 拥有且不可由其他用户写入: {path}")
    for name in ("observability.py", "nmd_monitor.py"):
        if not (root / "scripts" / name).is_file():
            raise ScopeError(f"缺少监控代码: {name}")


def _ensure_system_account():
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        _run("useradd", "--system", "--user-group", "--no-create-home",
             "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", SERVICE_USER)
        account = pwd.getpwnam(SERVICE_USER)
    if account.pw_uid == 0 or account.pw_gid == 0 or Path(account.pw_shell).name not in {"nologin", "false"}:
        raise ScopeError("已有 nmd-monitor 账户不符合专用非 root 服务账户要求；未更改该账户。")
    try:
        group = grp.getgrnam(SERVICE_USER)
    except KeyError:
        raise ScopeError("nmd-monitor 服务账户缺少同名专用组；未更改该账户。") from None
    if group.gr_gid != account.pw_gid:
        raise ScopeError("nmd-monitor 服务账户的主组必须为同名专用组；未更改该账户。")
    return account


def _accessible(path, uid, gid, permission):
    info = path.stat()
    shift = 6 if info.st_uid == uid else 3 if info.st_gid == gid else 0
    return ((stat.S_IMODE(info.st_mode) >> shift) & permission) == permission


def _service_access(path, uid, gid, directory=False):
    for parent in path.parents:
        if not _accessible(parent, uid, gid, 1):
            raise ScopeError(f"nmd-monitor 服务账户无法遍历目录: {parent}")
    if not _accessible(path, uid, gid, 5 if directory else 4):
        raise ScopeError(f"nmd-monitor 服务账户无法读取: {path}")


def _directory(path, mode, uid, gid=None, private=False):
    _plain_path(path)
    for parent in path.parents:
        if not parent.exists():
            continue
        info = parent.stat()
        parent_mode = stat.S_IMODE(info.st_mode)
        sticky_root = info.st_uid == 0 and parent_mode & stat.S_ISVTX
        if info.st_uid not in {0, os.geteuid()} or (parent_mode & 0o022 and not sticky_root):
            raise ScopeError(f"目录的父路径不安全，未修改: {parent}")
    existed = path.exists()
    if existed:
        info = path.stat()
        bad_mode = stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022)
        if not path.is_dir() or info.st_uid != uid or bad_mode:
            raise ScopeError(f"目录的所有者或权限不安全，未修改: {path}")
        return
    path.mkdir(parents=True, mode=mode)
    path.chmod(mode)
    if gid is not None:
        os.chown(path, uid, gid)


def _atomic_write(path, text, mode, uid=None, gid=None):
    _plain_path(path)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            if uid is not None:
                os.fchown(stream.fileno(), uid, gid)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install_monitor(root, scope, config_dir, state_dir):
    """Write an opt-in monitor service and config, preserving existing data.

    Does not enable/start/restart the service, probe the network, install proxy
    assets, mutate DNS/routes/Tailscale, or configure login-session lingering.
    """
    _scope(scope)
    _require_root(scope)
    root = _plain_path(root)
    config_dir, state_dir = _plain_path(config_dir), _plain_path(state_dir)
    config_file = config_dir / "monitor.json"
    unit = _unit_path(scope, config_dir)
    _check_unit(unit, root, scope)
    _plain_path(config_file)
    from nmd_monitor import load_config
    if config_file.exists():
        info = config_file.stat()
        if not config_file.is_file() or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ScopeError(f"配置文件的所有者或权限不安全，未修改: {config_file}")
        load_config(config_file)
        config_text = None
    else:
        template = root / "examples/monitor-local.json"
        load_config(template)
        config_text = template.read_text()
    if scope == "system":
        _validate_system_code(root)
        account = _ensure_system_account()
        uid, gid = account.pw_uid, account.pw_gid
        _directory(config_dir, 0o750, 0, gid)
        _directory(state_dir, 0o700, uid, gid, private=True)
        _service_access(config_dir, uid, gid, directory=True)
        _service_access(state_dir, uid, gid, directory=True)
        for name in ("observability.py", "nmd_monitor.py"):
            _service_access(root / "scripts" / name, uid, gid)
        if config_file.exists():
            _service_access(config_file, uid, gid)
    else:
        uid, gid = os.geteuid(), None
        _directory(config_dir, 0o700, uid)
        _directory(state_dir, 0o700, uid, private=True)
    if config_text is not None:
        _atomic_write(config_file, config_text, 0o640 if scope == "system" else 0o600,
                      0 if scope == "system" else None, gid)
    _directory(unit.parent, 0o755 if scope == "system" else 0o700, os.geteuid())
    _atomic_write(unit, _unit_text(root, scope, config_file, state_dir), 0o644)
    _systemctl(scope, "daemon-reload")
    return unit


def uninstall_monitor(root, scope, config_dir, state_dir):
    """Stop/disable and remove only this installation's unit; retain all data."""
    _scope(scope)
    _require_root(scope)
    root = _plain_path(root)
    config_dir = _plain_path(config_dir)
    unit = _unit_path(scope, config_dir)
    _check_unit(unit, root, scope)
    if not unit.exists():
        return False
    _systemctl(scope, "disable", "--now", UNIT_NAME)
    unit.unlink()
    _systemctl(scope, "daemon-reload")
    return True
