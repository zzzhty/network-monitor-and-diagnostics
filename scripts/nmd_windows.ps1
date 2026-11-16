# Shared Python discovery for the Windows local monitor.
# Smart App Control blocks uv launcher trampolines. This file never runs uv,
# and it never executes a python.exe that the block list already rejects.
# A virtual environment, if one is wanted, is created with:
#   python -m venv --without-pip .venv
# uv pip install, uv sync, and uv run can then reuse that environment.

$ErrorActionPreference = 'Stop'

function Test-NmdBlockedPython {
    param([Parameter(Mandatory)][string]$Path)
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $true }
    $parts = @($full.ToLowerInvariant().Split(@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries))
    for ($i = 0; $i -lt ($parts.Length - 1); $i++) {
        if ($parts[$i] -eq '.local' -and $parts[$i + 1] -eq 'bin') { return $true }
        if ($parts[$i] -eq 'microsoft' -and $parts[$i + 1] -eq 'windowsapps') { return $true }
    }
    $dir = Split-Path -Parent $full
    if ((Split-Path -Leaf $dir).ToLowerInvariant() -eq 'scripts') {
        $cfg = Join-Path (Split-Path -Parent $dir) 'pyvenv.cfg'
        if (Test-Path -LiteralPath $cfg) {
            $text = [System.IO.File]::ReadAllText($cfg)
            if ($text -match '(?m)^uv\s*=') { return $true }
        }
    }
    return $false
}

function Invoke-NmdQuiet {
    param([Parameter(Mandatory)][string]$Program, [Parameter(Mandatory)][string[]]$ArgumentList)
    $had = $false
    $previous = $false
    if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
        $had = $true
        $previous = $global:PSNativeCommandUseErrorActionPreference
        $global:PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        $output = & $Program @ArgumentList 2>$null
        return @{ Ok = ($LASTEXITCODE -eq 0); Output = (@($output) -join "`n").Trim() }
    } catch {
        return @{ Ok = $false; Output = '' }
    } finally {
        if ($had) { $global:PSNativeCommandUseErrorActionPreference = $previous }
    }
}

function Explain-NmdPython {
    [Console]::Error.WriteLine(@'
没有可用的 Python 3.9+。
Town 上开着智能应用控制（Smart App Control）。它会拦截 uv 生成的 python.exe 跳板，包括 %USERPROFILE%\.local\bin\python.exe，以及 uv 创建的 .venv\Scripts\python.exe。
不要用 uv 创建虚拟环境。若需要虚拟环境，先用已经能运行的 python 执行：
  python -m venv --without-pip .venv
然后可以用 uv pip install、uv sync 或 uv run，uv 会复用这个环境。
NMD 采集器只用标准库，安装不会创建虚拟环境。计划任务调用所选解释器的 sys.executable。
若 python 不在 PATH：用 python.org 安装包，或
  winget install -e --id Python.Python.3.13
安装位置用默认的 %LOCALAPPDATA%\Programs\Python 或 Program Files，不要装到 %USERPROFILE%\.local\bin。
也可以设置 NMD_PYTHON 为那个 python.exe 的绝对路径。
'@)
    exit 1
}

function Test-NmdPythonCandidate {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if (Test-NmdBlockedPython $Path) { return $false }
    $version = Invoke-NmdQuiet -Program $Path -ArgumentList @('-c', 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 9) else 1)')
    if (-not $version.Ok) { return $false }
    $resolved = Invoke-NmdQuiet -Program $Path -ArgumentList @('-c', 'import sys; print(sys.executable)')
    if (-not $resolved.Ok -or -not $resolved.Output) { return $false }
    $exe = $resolved.Output.Trim()
    if (Test-NmdBlockedPython $exe) { return $false }
    $script:NmdPythonExe = $exe
    return $true
}

function Find-NmdPython {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($env:NMD_PYTHON) { $candidates.Add($env:NMD_PYTHON) }
    foreach ($name in @('python', 'python3')) {
        foreach ($cmd in @(Get-Command $name -All -ErrorAction SilentlyContinue)) {
            if ($cmd.Source) { $candidates.Add([string]$cmd.Source) }
        }
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py -and $py.Source -and -not (Test-NmdBlockedPython $py.Source)) {
        $listed = Invoke-NmdQuiet -Program $py.Source -ArgumentList @('-0p')
        if ($listed.Ok) {
            foreach ($line in ($listed.Output -split "`n")) {
                if ($line -match '([A-Za-z]:\\.*\\python\.exe)\s*$') { $candidates.Add($Matches[1]) }
            }
        }
    }
    $roots = @(
        (Join-Path $env:APPDATA 'uv\python'),
        (Join-Path $env:LOCALAPPDATA 'uv\python'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python'),
        (Join-Path ${env:ProgramFiles} 'Python')
    )
    foreach ($root in $roots) {
        if ($root -and (Test-Path -LiteralPath $root)) {
            Get-ChildItem -LiteralPath $root -Filter python.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                ForEach-Object { $candidates.Add($_.FullName) }
        }
    }
    $seen = @{}
    foreach ($candidate in $candidates) {
        if (-not $candidate -or $seen.ContainsKey($candidate)) { continue }
        $seen[$candidate] = $true
        if (Test-NmdPythonCandidate $candidate) { return $script:NmdPythonExe }
    }
    Explain-NmdPython
}
