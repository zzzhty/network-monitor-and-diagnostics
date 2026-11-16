#Requires -Version 5.1
# Install the current-user NMD monitor. Does not deploy mihomo, Tailscale, or a VPS.
# Run: pwsh -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
# -ExecutionPolicy Bypass applies only to this process. It does not need an administrator.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'scripts\nmd_windows.ps1')
if ($args -contains '--system') {
    [Console]::Error.WriteLine('Windows 只支持当前用户安装。--system、VPS 与网络部署仍仅限 Linux。')
    exit 2
}
$python = Find-NmdPython
$env:NMD_PYTHON = $python
$manager = Join-Path $here 'scripts\manager.py'
if (-not (Test-Path -LiteralPath $manager)) {
    [Console]::Error.WriteLine('请在已克隆的仓库里运行 install.ps1。当前脚本旁边没有 scripts\manager.py。')
    exit 1
}
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
    $global:PSNativeCommandUseErrorActionPreference = $false
}
& $python $manager bootstrap @args
exit $LASTEXITCODE
