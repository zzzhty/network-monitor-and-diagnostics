#!/usr/bin/env python3
"""Configure the tailnet SOCKS address after a fail-closed component check.

Linux may download the mihomo deb with the existing ``fetch-assets.sh`` and
writes a user-owned env file. It does not run ``dpkg``, ``setup``, or
``apply``, and this repository has no Tailscale installer.

macOS never downloads or installs Tailscale. When mihomo is missing it may
place the official darwin binary from the same GitHub release as
``fetch-assets.sh`` into a directory the current user can write, without
sudo. A missing component, a failed download, or an invalid address stops
the command before any config is written.
"""
from __future__ import annotations

import contextlib
import gzip
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

import macos_preflight
import macos_prepare
import macos_readonly
import macos_takeover
import nmd_daemon
import nmd_platform

SCHEMA_VERSION = 1
COMMAND = "nmd onboard"
LINUX_MIHOMO = "/usr/bin/mihomo"
LINUX_TAILSCALE = ("/usr/bin/tailscale", "/usr/local/bin/tailscale")
# local-setup.sh hardcodes this port; onboard will not invent another.
LINUX_SOCKS_PORT = 1080
# Same documentation placeholder as examples/macos-daemon.json. Kept as a
# literal so this shared command does not import the macOS profile module.
_PLACEHOLDER_SERVER = "203.0.113.20"
_MACHO = (
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
)
_DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
_ENV_LINE = re.compile(r"^(NMD_VPS_PUB|NMD_VPS_TS_IP)=([0-9.]+)$")
_VERSION = re.compile(r"^VER=(v\d+\.\d+\.\d+)\s*$", re.MULTILINE)
_RELEASE = "https://github.com/MetaCubeX/mihomo/releases/download/"
_CANDIDATE_DIRS = ("/usr/local/bin", "/opt/homebrew/bin", "/usr/local/sbin")
_DEFAULT = object()

HELP = """\
usage: nmd onboard --server ADDR --port PORT [--proxy-name NAME]
       nmd onboard --inputs INPUTS.json

检查 Tailscale 和 mihomo。缺了或不可用就停止，不写一半的网络配置，
也不开始接管。通过之后才记录 Tailnet SOCKS 地址。

macOS 不下载、不安装 Tailscale。mihomo 不在候选路径上时，只有存在当前用户
可写的目录（优先 /opt/homebrew/bin，其次 /usr/local/bin，否则 ~/.local/bin）
才会从与 fetch-assets.sh 相同的官方发布下载 darwin 包并放入该目录。
下载失败或没有可写目录则停止，不写 daemon.json。on_boot 保持 false，
不加载 LaunchDaemon，不执行 nmd apply。

Linux 上 Tailscale 缺失则停止：仓库没有 Tailscale 安装器。mihomo 缺失时
只运行现有的 fetch-assets.sh 下载 deb；不执行 dpkg、setup 或 apply。
/usr/bin/mihomo 仍然不可执行则停止，不写地址。端口必须是 1080。

不要用 root 运行。拒绝 203.0.113.20 和其他非 Tailnet 地址。Windows 不支持。
"""


class OnboardError(Exception):
    pass


def _print_json(payload, *, error=False):
    print(json.dumps(payload, ensure_ascii=False, indent=2),
          file=sys.stderr if error else sys.stdout)


def _fail(token, remediation):
    _print_json({"schema_version": SCHEMA_VERSION, "command": COMMAND,
                 "error": token, "remediation": remediation}, error=True)
    return 1


def _remediation(token):
    text = {
        "root_refused": "请用当前用户运行，不要 sudo。配置不会写进 /var/root。",
        "unsupported_platform": "nmd onboard 只支持 Linux 和 macOS。",
        "invalid_arguments": "用法见 nmd onboard --help。",
        "placeholder_inputs": "203.0.113.20 是文档占位，不能写入。换成自己的 Tailnet 地址。",
        "linux_requires_ipv4": "Linux 的现有端点文件只接受 IPv4。请改用 Tailnet 的 IPv4 地址。",
        "linux_port_fixed": "Linux 现有路径把 SOCKS 端口固定为 1080。onboard 不会另写一个端口。",
        "tailscale_missing": (
            "没有找到官方 Tailscale。请自行安装官方客户端后重试。"
            "onboard 不会下载或安装 Tailscale。"),
        "tailscale_unusable": "官方 Tailscale 路径不可用。onboard 不会改它，也不会继续。",
        "mihomo_missing": (
            "没有可执行的 mihomo，而且没能放到用户可写目录。"
            "请自行安装官方 mihomo 后重试。没有写入配置。"),
        "mihomo_unusable": "mihomo 路径不可用。onboard 不会覆盖它，也不会继续。",
        "mihomo_download_failed": (
            "官方 mihomo 发布包没有下载成功。没有写入配置，也没有开始接管。"),
        "mihomo_download_invalid": "下载内容不是可用的 mihomo 可执行文件。没有写入配置。",
        "mihomo_install_unavailable": (
            "没有当前用户可写、且不需要 sudo 的目录来放置 mihomo。"
            "fetch-assets.sh 只下载 Linux deb，不能代替这一步。没有写入配置。"),
        "mihomo_not_installed": (
            "已尝试用 fetch-assets.sh 下载 mihomo.deb，但 /usr/bin/mihomo 仍不可执行。"
            "仓库里的 dpkg -i 写在 setup/apply 里，那些命令还会改 DNS。"
            "onboard 不会执行 dpkg、setup 或 apply。请自行安装到 /usr/bin/mihomo 后重试。"),
        "config_not_regular": "配置路径不是当前用户拥有的普通文件。没有覆盖它。",
        "config_unreadable": "现有配置读不出来。没有改它。",
        "env_invalid": "现有端点文件含有允许之外的内容。没有改写。",
    }
    return text.get(token, "命令已停止，没有写入网络配置。")


def release_version(root=None):
    """The version pin in fetch-assets.sh. macOS uses the same release."""
    script = Path(root or Path(__file__).resolve().parents[1]) / "fetch-assets.sh"
    match = _VERSION.search(script.read_text(encoding="utf-8"))
    if match is None:
        raise OnboardError("mihomo_version_unknown")
    return match.group(1)


def darwin_asset_url(version, machine):
    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "amd64"
    else:
        raise OnboardError("unsupported_architecture")
    name = f"mihomo-darwin-{arch}-{version}.gz"
    return _RELEASE + version + "/" + name


def _writable_user_dir(directory):
    directory = Path(directory)
    try:
        info = os.lstat(directory)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return False
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        return False
    try:
        return os.access(directory, os.W_OK | os.X_OK)
    except OSError:
        return False


def _private_parent_ready(path):
    current = Path(path)
    while not current.exists():
        parent = current.parent
        if parent == current:
            return False
        current = parent
    try:
        info = os.lstat(current)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return False
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        return False
    return True


def choose_install_dir(directories, fallback):
    """A directory the current user can write without sudo, or None."""
    for directory in directories:
        if _writable_user_dir(directory):
            return Path(directory)
    if fallback is None:
        return None
    fallback = Path(fallback)
    if fallback.exists():
        return fallback if _writable_user_dir(fallback) else None
    if _private_parent_ready(fallback):
        return fallback
    return None


def _find(candidates):
    unknown = False
    for candidate in candidates:
        status = macos_preflight.probe_executable(candidate)
        if status == "pass":
            return str(candidate)
        if status == "unknown":
            unknown = True
    if unknown:
        raise OnboardError("component_unusable")
    return None


def curl_bytes(url):
    """Same curl flags as fetch-assets.sh. The body is not executed."""
    if not url.startswith(_RELEASE):
        raise OnboardError("mihomo_download_refused")
    fd, name = tempfile.mkstemp(prefix="nmd-mihomo-")
    os.close(fd)
    try:
        result = subprocess.run(
            ["curl", "-fsSL", "--connect-timeout", "10", "--max-time", "180",
             "--retry", "3", "-o", name, url],
            capture_output=True, timeout=200)
        if result.returncode != 0:
            raise OnboardError("mihomo_download_failed")
        data = Path(name).read_bytes()
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OnboardError("mihomo_download_failed") from exc
    finally:
        with contextlib.suppress(OSError):
            os.unlink(name)
    if not data or len(data) > 40 * 1024 * 1024:
        raise OnboardError("mihomo_download_failed")
    return data


def unpack_darwin_gzip(blob):
    try:
        binary = gzip.decompress(blob)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise OnboardError("mihomo_download_invalid") from exc
    if len(binary) < 64 or len(binary) > 80 * 1024 * 1024 or not binary.startswith(_MACHO):
        raise OnboardError("mihomo_download_invalid")
    return binary


def place_user_binary(directory, binary):
    directory = Path(directory)
    dest = directory / "mihomo"
    try:
        nmd_daemon._require_trusted_path(dest)
    except nmd_daemon.DaemonError as exc:
        raise OnboardError("mihomo_install_unavailable") from exc
    if not directory.exists():
        macos_prepare._create_private_parents(directory)
    try:
        os.lstat(dest)
    except FileNotFoundError:
        pass
    else:
        raise OnboardError("mihomo_install_blocked")
    fd, temporary = tempfile.mkstemp(dir=str(directory), prefix=".mihomo.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(binary)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o755)
        try:
            os.lstat(dest)
        except FileNotFoundError:
            pass
        else:
            raise OnboardError("mihomo_install_blocked")
        os.replace(temporary, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    if macos_preflight.probe_executable(str(dest)) != "pass":
        with contextlib.suppress(OSError):
            dest.unlink()
        raise OnboardError("mihomo_install_failed")
    return dest


def _parse(argv):
    server = port = proxy_name = inputs_path = None
    seen = set()
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag not in ("--server", "--port", "--proxy-name", "--inputs") or flag in seen:
            raise OnboardError("invalid_arguments")
        if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith("-"):
            raise OnboardError("invalid_arguments")
        seen.add(flag)
        value = argv[index + 1]
        index += 2
        if flag == "--server":
            server = value
        elif flag == "--port":
            if not value.isdecimal():
                raise OnboardError("invalid_port")
            port = int(value)
        elif flag == "--proxy-name":
            proxy_name = value
        else:
            inputs_path = value
    if inputs_path is not None and (server is not None or port is not None or proxy_name is not None):
        raise OnboardError("invalid_arguments")
    if inputs_path is None and (server is None or port is None):
        raise OnboardError("invalid_arguments")
    if inputs_path is not None:
        try:
            raw = macos_takeover._load_trusted_json(inputs_path)
        except (macos_takeover.TakeoverError, ValueError, OSError) as exc:
            token = str(exc).split(":", 1)[0].strip()
            raise OnboardError(token or "invalid_inputs") from None
    else:
        raw = {"server": server, "port": port}
        if proxy_name is not None:
            raw["proxy_name"] = proxy_name
    try:
        inputs = macos_prepare.validate_inputs(raw)
    except ValueError as exc:
        raise OnboardError(str(exc).split(":", 1)[0].strip() or "invalid_inputs") from None
    if inputs["server"] == _PLACEHOLDER_SERVER:
        raise OnboardError("placeholder_inputs")
    return inputs


def _linux_constraints(inputs):
    if ipaddress.ip_address(inputs["server"]).version != 4:
        raise OnboardError("linux_requires_ipv4")
    if inputs["port"] != LINUX_SOCKS_PORT:
        raise OnboardError("linux_port_fixed")


def _mihomo_path_value(found, existing):
    parent = Path(found).parent.as_posix()
    if parent in _CANDIDATE_DIRS or found == LINUX_MIHOMO:
        return existing
    return str(found)


def _outside_repository(path):
    repo = Path(__file__).resolve().parents[1]
    if path == repo or repo in Path(path).parents:
        raise OnboardError("config_not_regular")


def _write_daemon(path, inputs, mihomo):
    path = Path(path)
    _outside_repository(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        info = None
    except OSError as exc:
        raise OnboardError("config_unreadable") from exc
    if info is not None and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
        raise OnboardError("config_not_regular")
    if info is None:
        config = {
            "schema_version": nmd_daemon.DAEMON_SCHEMA_VERSION,
            "dashboard": {"port": nmd_daemon.DEFAULT_DASHBOARD_PORT},
            "takeover": {
                "inputs": inputs,
                "profile": None,
                "on_boot": False,
                "check_interval_seconds": nmd_daemon._INIT_INTERVAL,
                "critical_failures": nmd_daemon._INIT_CRITICAL,
                "mihomo_path": _mihomo_path_value(mihomo, None),
                "state_dir": None,
            },
        }
    else:
        try:
            config = nmd_daemon.load_daemon_config(path, expected_uid=os.geteuid())
        except nmd_daemon.DaemonError as exc:
            raise OnboardError(str(exc)) from None
        if config["takeover"]["on_boot"] is True:
            # Preserve an already-true flag, but do not start anything.
            pass
        takeover = dict(config["takeover"])
        takeover["inputs"] = inputs
        takeover["mihomo_path"] = _mihomo_path_value(mihomo, takeover.get("mihomo_path"))
        config = {"schema_version": config["schema_version"],
                  "dashboard": dict(config["dashboard"]), "takeover": takeover}
    if config["takeover"]["on_boot"] is True and info is None:
        raise OnboardError("invalid_on_boot")
    nmd_daemon._require_trusted_path(path)
    if info is None:
        macos_prepare._create_private_parents(path.parent)
    nmd_daemon.write_daemon_config(path, config)
    loaded = nmd_daemon.load_daemon_config(path, expected_uid=os.geteuid())
    if type(loaded["takeover"]["on_boot"]) is not bool:
        raise OnboardError("invalid_on_boot")
    if info is None and loaded["takeover"]["on_boot"] is not False:
        raise OnboardError("invalid_on_boot")
    return loaded["takeover"]["on_boot"]


def _read_env(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OnboardError("config_unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OnboardError("config_not_regular")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OnboardError("config_unreadable") from exc
    found = {}
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        match = _ENV_LINE.fullmatch(line.strip())
        if match is None:
            raise OnboardError("env_invalid")
        found[match.group(1)] = match.group(2)
    public = found.get("NMD_VPS_PUB")
    if public and public.startswith(_DOC_PREFIXES):
        raise OnboardError("placeholder_inputs")
    return found


def _write_linux_env(path, server):
    path = Path(path)
    _outside_repository(path)
    existing = _read_env(path)
    if existing is not None and existing.get("NMD_VPS_TS_IP") == server:
        return False
    lines = [f"NMD_VPS_TS_IP={server}"]
    if existing and existing.get("NMD_VPS_PUB"):
        lines.append(f"NMD_VPS_PUB={existing['NMD_VPS_PUB']}")
    payload = ("\n".join(lines) + "\n").encode("ascii")
    nmd_daemon._require_trusted_path(path)
    macos_prepare._create_private_parents(path.parent)
    macos_prepare._atomic_private_write(path.parent, path.name, payload)
    return True


def _default_fetch():
    import manager
    try:
        manager.ensure_assets(manager.ROOT)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise OnboardError("mihomo_download_failed") from exc


def main(argv, *, platform=None, find_tailscale=None, find_mihomo=None,
         fetch_linux_assets=None, download=None, install_directories=_DEFAULT,
         fallback_dir=_DEFAULT, daemon_path=None, env_path=None, machine=None):
    if any(arg in ("-h", "--help") for arg in argv):
        sys.stdout.write(HELP)
        return 0
    if os.geteuid() == 0:
        return _fail("root_refused", _remediation("root_refused"))
    platform = platform or nmd_platform.name()
    if platform not in ("linux", "macos"):
        return _fail("unsupported_platform", _remediation("unsupported_platform"))
    try:
        inputs = _parse(argv)
        if platform == "linux":
            _linux_constraints(inputs)
    except OnboardError as exc:
        token = str(exc)
        if token == "invalid_arguments":
            sys.stderr.write(HELP)
            return 2
        return _fail(token, _remediation(token))
    try:
        tailscale = (find_tailscale or _default_tailscale)(platform)
    except OnboardError as exc:
        token = "tailscale_unusable" if str(exc) == "component_unusable" else str(exc)
        return _fail(token, _remediation(token))
    if not tailscale:
        return _fail("tailscale_missing", _remediation("tailscale_missing"))
    if platform == "linux":
        # Reject a bad endpoint file before fetch-assets.sh writes a deb.
        try:
            env_target = Path(env_path) if env_path is not None else _env_path()
            _outside_repository(env_target)
            _read_env(env_target)
        except OnboardError as exc:
            return _fail(str(exc), _remediation(str(exc)))
        except nmd_daemon.DaemonError as exc:
            return _fail(str(exc), _remediation(str(exc)))
    installed = False
    try:
        mihomo, installed = _ensure_mihomo(
            platform, find_mihomo=find_mihomo, fetch_linux_assets=fetch_linux_assets,
            download=download, install_directories=install_directories,
            fallback_dir=fallback_dir, machine=machine)
    except OnboardError as exc:
        token = str(exc)
        if token == "component_unusable":
            token = "mihomo_unusable"
        return _fail(token, _remediation(token))
    try:
        if platform == "macos":
            path = Path(daemon_path) if daemon_path is not None else _daemon_path()
            on_boot = _write_daemon(path, inputs, mihomo)
            extra = {"on_boot": on_boot}
        else:
            path = Path(env_path) if env_path is not None else _env_path()
            _write_linux_env(path, inputs["server"])
            extra = {}
    except OnboardError as exc:
        return _fail(str(exc), _remediation(str(exc)))
    except nmd_daemon.DaemonError as exc:
        return _fail(str(exc), _remediation(str(exc)))
    body = {
        "schema_version": SCHEMA_VERSION,
        "command": COMMAND,
        "result": "configured",
        "platform": platform,
        "path": str(path),
        "mihomo": mihomo,
        "mihomo_installed": installed,
        "tailscale": tailscale,
        "loaded_daemon": False,
        "takeover_started": False,
        "apply_ran": False,
        "note": (_note(platform, installed)),
    }
    body.update(extra)
    _print_json(body)
    return 0


def _note(platform, installed):
    if platform == "macos":
        placed = "已把官方 mihomo 放到当前用户可写的目录。" if installed else ""
        return (placed + "已记录 Tailnet 地址。没有下载或安装 Tailscale，"
                "没有加载 LaunchDaemon，没有把 on_boot 从 false 改成 true，"
                "没有改路由、DNS 或代理，也没有执行 nmd apply。")
    return ("已把 Tailnet 地址写入当前用户的端点文件，没有写入 /etc。"
            "没有执行 dpkg、setup 或 apply，没有改 DNS、路由或代理。")


def _default_tailscale(platform):
    if platform == "macos":
        return _find(macos_readonly.TAILSCALE_CANDIDATES)
    return _find(LINUX_TAILSCALE)


def _default_mihomo(platform):
    if platform == "linux":
        return _find((LINUX_MIHOMO,))
    return _find(macos_takeover.MIHOMO_CANDIDATES)


def _daemon_path():
    import manager
    return nmd_daemon.default_daemon_config_path(manager.ROOT)


def _env_path():
    import manager
    recorded = ""
    try:
        recorded = manager.setting(manager.ROOT, "configDir")
    except Exception:
        recorded = ""
    if isinstance(recorded, str) and recorded and Path(recorded).is_absolute():
        directory = Path(recorded)
    else:
        import install_scope
        directory = install_scope.paths("user")["config_dir"]
    return directory / "nmd-local.env"


def _ensure_mihomo(platform, *, find_mihomo, fetch_linux_assets, download,
                   install_directories, fallback_dir, machine):
    finder = find_mihomo or _default_mihomo
    found = finder(platform)
    if found:
        return found, False
    if platform == "linux":
        (fetch_linux_assets or _default_fetch)()
        found = finder(platform)
        if not found:
            raise OnboardError("mihomo_not_installed")
        return found, False
    directories = (("/opt/homebrew/bin", "/usr/local/bin")
                   if install_directories is _DEFAULT else install_directories)
    fallback = (Path.home() / ".local" / "bin"
                if fallback_dir is _DEFAULT else fallback_dir)
    directory = choose_install_dir(directories, fallback)
    if directory is None:
        raise OnboardError("mihomo_install_unavailable")
    version = release_version()
    url = darwin_asset_url(version, machine or os.uname().machine)
    blob = (download or curl_bytes)(url)
    binary = unpack_darwin_gzip(blob)
    placed = place_user_binary(directory, binary)
    return str(placed), True


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
