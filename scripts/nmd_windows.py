"""Windows local-monitor helpers. No network configuration and no uv venv launchers.

Smart App Control on the target machine blocks uv-generated python.exe trampolines,
including %USERPROFILE%\\.local\\bin\\python.exe and the interpreter created by
`uv venv`. A virtual environment has to be created with `python -m venv
--without-pip` so uv can reuse it. The monitor itself uses the standard library
and does not create a virtual environment.
"""
import hashlib
import json
import os
from pathlib import Path
import re


TASK_NAME = "Monitor"
TASK_PATH = "\\NMD\\"
MARKER = "Managed by NMD install_scope: "
_STATUS = {
    "Up": "up",
    "Down": "down",
    "Disconnected": "down",
}


class InterpreterError(ValueError):
    pass


def system_root():
    return os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"


def powershell_exe():
    return str(Path(system_root()) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def curl_exe():
    return str(Path(system_root()) / "System32" / "curl.exe")


def description(root):
    payload = json.dumps({"root": str(root), "scope": "user"}, sort_keys=True, ensure_ascii=True)
    return MARKER + payload


def ps_quote(value):
    """PowerShell single-quoted literal. Reject quotes and control characters."""
    text = str(value)
    if not text or re.search(r"[\x00-\x1f']", text):
        raise ValueError("unsafe_windows_path")
    return "'" + text + "'"


def _path_parts(text):
    return [part.lower() for part in re.split(r"[\\/]", os.fspath(text)) if part]


def blocked_reason(path):
    """Return why this interpreter must not be launched, or None when it is usable.

    The check is lexical plus pyvenv.cfg. It does not execute the file: Smart
    App Control can block the launch itself. Separators are split explicitly so
    the same rules can be tested on Linux.
    """
    text = os.fspath(path)
    if "\x00" in text:
        return "unsafe_path"
    parts = _path_parts(text)
    for index in range(len(parts) - 1):
        if parts[index] == ".local" and parts[index + 1] == "bin":
            return "smart_app_control_local_bin"
        if parts[index] == "microsoft" and parts[index + 1] == "windowsapps":
            return "windowsapps_stub"
    candidate = Path(text)
    if candidate.parent.name.lower() == "scripts":
        cfg = candidate.parent.parent / "pyvenv.cfg"
        try:
            body = cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        if re.search(r"(?im)^uv\s*=", body):
            return "smart_app_control_uv_venv"
    return None


def explain_interpreter(path, reason):
    return (
        f"不能使用这个 Python：{path}（{reason}）。\n"
        "智能应用控制（Smart App Control）会拦截 uv 生成的 python.exe 跳板，"
        r"包括 %USERPROFILE%\.local\bin\python.exe，以及 uv venv 创建的 .venv\Scripts\python.exe。"
        "\n不要用 uv 创建虚拟环境。若需要虚拟环境，用已经能运行的 python 执行：\n"
        "  python -m venv --without-pip .venv\n"
        "然后可以用 uv pip install、uv sync 或 uv run，uv 会复用这个环境。\n"
        "NMD 采集器只用标准库，不会创建虚拟环境。请让 python 指向 python.org、winget "
        "或 uv 安装的真实 CPython（sys.executable），不要指向被拦截的跳板。\n"
        "也可设置 NMD_PYTHON 为该 python.exe 的绝对路径。"
    )


def require_interpreter(path):
    reason = blocked_reason(path)
    if reason:
        raise InterpreterError(explain_interpreter(path, reason))
    if not Path(path).is_file():
        raise InterpreterError(explain_interpreter(path, "missing"))
    return Path(path)


def user_paths(profile):
    """Layout for one Windows profile. The command directory stays outside the git checkout."""
    profile = Path(profile)
    local = profile / "AppData" / "Local"
    roaming = profile / "AppData" / "Roaming"
    result = dict(
        home=local / "nmd",
        bin_dir=local / "nmd-bin",
        config_dir=roaming / "nmd",
        state_dir=local / "nmd-monitor",
        task_name=TASK_NAME,
        task_path=TASK_PATH,
    )
    result["config_file"] = result["config_dir"] / "monitor.json"
    result["task_script"] = result["bin_dir"] / "nmd-monitor-task.ps1"
    result["command"] = result["bin_dir"] / "nmd.cmd"
    result["log_file"] = result["state_dir"] / "monitor.log"
    result["unit_file"] = result["task_script"]
    result["unit"] = result["task_script"]
    return result


def paths_from_env(home=None):
    if home is not None:
        return user_paths(home)
    local = os.environ.get("LOCALAPPDATA")
    roaming = os.environ.get("APPDATA")
    local = Path(local) if local else Path.home() / "AppData" / "Local"
    roaming = Path(roaming) if roaming else Path.home() / "AppData" / "Roaming"
    profile = local.parent.parent if local.name.lower() == "local" else Path.home()
    # Rebuild from the profile so a custom LOCALAPPDATA still wins when home is unset.
    result = user_paths(profile)
    result["home"] = local / "nmd"
    result["bin_dir"] = local / "nmd-bin"
    result["config_dir"] = roaming / "nmd"
    result["state_dir"] = local / "nmd-monitor"
    result["config_file"] = result["config_dir"] / "monitor.json"
    result["task_script"] = result["bin_dir"] / "nmd-monitor-task.ps1"
    result["command"] = result["bin_dir"] / "nmd.cmd"
    result["log_file"] = result["state_dir"] / "monitor.log"
    result["unit_file"] = result["task_script"]
    result["unit"] = result["task_script"]
    return result


def merge_user_path(existing, bindir):
    """Prepend bindir to a user PATH. None means it is already present."""
    bindir = str(bindir)
    parts = existing.split(";") if existing else []
    folded = {os.path.normcase(os.path.normpath(part)) for part in parts if part}
    if os.path.normcase(os.path.normpath(bindir)) in folded:
        return None
    return bindir if not existing else bindir + ";" + existing


def remove_user_path(existing, bindir):
    if not existing:
        return None
    target = os.path.normcase(os.path.normpath(str(bindir)))
    parts = existing.split(";")
    kept = [part for part in parts if not part or os.path.normcase(os.path.normpath(part)) != target]
    if kept == parts:
        return None
    return ";".join(kept)


def command_inside_checkout(root, bindir):
    root = Path(root)
    bindir = Path(bindir)
    return bindir == root or root in bindir.parents


def command_dir_blocked(bindir):
    parts = _path_parts(bindir)
    return any(parts[index] == ".local" and parts[index + 1] == "bin" for index in range(len(parts) - 1))


def render_cmd():
    """ASCII launcher. The Unicode paths live in the sibling ps1, not in this file."""
    lines = [
        "@echo off",
        "rem Managed by NMD install_scope",
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0nmd-entry.ps1" %*',
    ]
    return "\r\n".join(lines) + "\r\n"


def render_entry_ps1(python, root):
    line = "& " + ps_quote(python) + " " + ps_quote(Path(root) / "scripts" / "manager.py") + " @args"
    lines = ["# " + description(root), "$ErrorActionPreference = 'Stop'", line, "exit $LASTEXITCODE"]
    return "\r\n".join(lines) + "\r\n"


def render_task_script(python, observability, config, state, log, root):
    line = (
        "& " + ps_quote(python) + " -u " + ps_quote(observability)
        + " monitor run --config " + ps_quote(config)
        + " --state-dir " + ps_quote(state)
        + " *>> " + ps_quote(log)
    )
    lines = ["# " + description(root), "$ErrorActionPreference = 'Stop'", line, "exit $LASTEXITCODE"]
    return "\r\n".join(lines) + "\r\n"


def task_action_argument(task_script):
    text = str(task_script)
    if re.search(r'[\x00-\x1f\'"]', text):
        raise ValueError("unsafe_windows_path")
    return '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + text + '"'


def task_powershell(action, root, task_script, workdir):
    """PowerShell that registers or controls only this install's scheduled task.

    install does not start the task and does not add a logon trigger.
    enable adds the logon trigger without starting. disable removes triggers
    without stopping a running collector. That matches the systemd user unit:
    install, enable, and start are separate.
    """
    if action not in {"install", "start", "stop", "restart", "enable", "disable", "status", "uninstall"}:
        raise ValueError("unknown_task_action")
    desc = ps_quote(description(root))
    argument = ps_quote(task_action_argument(task_script))
    executable = ps_quote(powershell_exe())
    work = ps_quote(workdir)
    prelude = f"""$ErrorActionPreference = 'Stop'
$TaskName = '{TASK_NAME}'
$TaskPath = '{TASK_PATH}'
$Description = {desc}
function Get-OwnedTask {{
  $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
  if (-not $task) {{ return $null }}
  if ($task.Description -ne $Description) {{
    Write-Error '计划任务不属于此安装，未修改。'
    exit 2
  }}
  return $task
}}
"""
    bodies = {
        "install": f"""$action = New-ScheduledTaskAction -Execute {executable} -Argument {argument} -WorkingDirectory {work}
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable
$existing = Get-OwnedTask
if ($existing) {{
  if ($existing.Triggers.Count -gt 0) {{
    Set-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Settings $settings -Trigger $existing.Triggers | Out-Null
  }} else {{
    Set-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Settings $settings | Out-Null
  }}
}} else {{
  $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Settings $settings -Principal $principal -Description $Description | Out-Null
}}
Write-Output '已登记计划任务；未启动，也未设置登录触发。'
""",
        "enable": """$existing = Get-OwnedTask
if (-not $existing) { Write-Error '监控任务尚未安装；请先运行 nmd monitor install。'; exit 1 }
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
Set-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Trigger $trigger | Out-Null
Write-Output '已设置登录时启动；本次没有启动采集。'
""",
        "disable": """$existing = Get-OwnedTask
if (-not $existing) { Write-Error '监控任务尚未安装；请先运行 nmd monitor install。'; exit 1 }
$existing.Triggers.Clear()
Set-ScheduledTask -InputObject $existing | Out-Null
Write-Output '已取消登录触发；正在运行的采集不会被停止。'
""",
        "start": """$existing = Get-OwnedTask
if (-not $existing) { Write-Error '监控任务尚未安装；请先运行 nmd monitor install。'; exit 1 }
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
Write-Output '已启动采集任务。'
""",
        "stop": """$existing = Get-OwnedTask
if (-not $existing) { Write-Error '监控任务尚未安装；请先运行 nmd monitor install。'; exit 1 }
if ($existing.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath }
Write-Output '采集任务已停止。'
""",
        "restart": """$existing = Get-OwnedTask
if (-not $existing) { Write-Error '监控任务尚未安装；请先运行 nmd monitor install。'; exit 1 }
if ($existing.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath }
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
Write-Output '已重启采集任务。'
""",
        "status": """$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if (-not $existing) { Write-Output 'State=Missing'; exit 0 }
if ($existing.Description -ne $Description) { Write-Error '计划任务不属于此安装。'; exit 2 }
$info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath
Write-Output ('State=' + $existing.State)
Write-Output ('LastTaskResult=' + $info.LastTaskResult)
Write-Output ('LastRunTime=' + $info.LastRunTime)
Write-Output ('LogonTrigger=' + $(if ($existing.Triggers.Count -gt 0) { 'yes' } else { 'no' }))
""",
        "uninstall": """$existing = Get-OwnedTask
if (-not $existing) { Write-Output '计划任务不存在，未修改。'; exit 0 }
if ($existing.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath }
Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
Write-Output '已删除计划任务。'
""",
    }
    return prelude + bodies[action]


def sample_argv():
    script = (
        "$OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
        "[Console]::OutputEncoding = $OutputEncoding; "
        "$ErrorActionPreference = 'Stop'; "
        "Get-NetAdapter | Select-Object -First 64 | ForEach-Object { "
        "'IF|' + ($_.Name -replace '\\|','/') + '|' + [string]$_.Status }; "
        "Get-NetRoute -AddressFamily IPv4 | Select-Object -First 256 | ForEach-Object { "
        "'RT|' + [string]$_.DestinationPrefix }"
    )
    return [powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", script]


def parse_local_sample(output):
    """Turn the fixed sampler lines into interface state and an IPv4 route fingerprint.

    Gateway addresses are not kept. The fingerprint covers destination prefixes only.
    """
    states = {}
    routes = []
    recognized = False
    foreign = False
    for line in output.splitlines():
        if not line.strip():
            continue
        if line.startswith("IF|"):
            parts = line.split("|")
            recognized = True
            if len(parts) != 3 or not parts[1] or len(parts[1]) > 128 or re.search(r"[\x00-\x1f]", parts[1]):
                foreign = True
                continue
            if len(states) < 64:
                states[parts[1]] = _STATUS.get(parts[2].strip(), "unknown")
            continue
        if line.startswith("RT|"):
            prefix = line[3:].strip()
            recognized = True
            if not re.fullmatch(r"[0-9a-fA-F:./]{1,64}", prefix):
                foreign = True
                continue
            routes.append(prefix)
            continue
        foreign = True
    return dict(states=states, routes=routes, recognized=recognized, foreign=foreign)


def route_fingerprint(routes):
    payload = "\n".join(sorted(routes)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def http_probe_argv(probe, timeout):
    argv = [curl_exe(), "--disable", "--globoff", "--silent", "--head", "--output", "NUL",
            "--max-time", str(timeout), "--connect-timeout", str(timeout),
            "--max-redirs", "0", "--proto", "=http,https", "--write-out",
            "%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}"]
    if probe["path"] == "proxy":
        argv += ["--proxy", probe["proxy"], "--noproxy", ""]
    else:
        argv += ["--noproxy", "*"]
    argv += ["--url", probe["target"]]
    return argv


def decode_command_output(data):
    """Decode a captured Windows console buffer without assuming the OEM code page."""
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le", "replace")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be", "replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", "replace")
    if len(data) >= 4 and len(data) % 2 == 0 and data[1] == 0 and data[3] == 0:
        return data.decode("utf-16-le", "replace")
    return data.decode("utf-8", "replace")


def tail_log(path, limit=100):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        return ""
    data = path.read_bytes()[-65536:]
    return "\n".join(decode_command_output(data).splitlines()[-limit:])
