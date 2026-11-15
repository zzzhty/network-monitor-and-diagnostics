#Requires -Version 5.1
# Source-checkout entry. The installed command is nmd.cmd beside nmd-entry.ps1.
# Run: pwsh -NoProfile -ExecutionPolicy Bypass -File .\nmd.ps1 <command>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'scripts\nmd_windows.ps1')
$python = Find-NmdPython
$env:NMD_PYTHON = $python
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
    $global:PSNativeCommandUseErrorActionPreference = $false
}
& $python (Join-Path $here 'scripts\manager.py') @args
exit $LASTEXITCODE
