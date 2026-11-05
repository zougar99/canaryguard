# Launcher for CanaryGuard (invoked by the CanaryGuard scheduled task).
# Paths are derived from this script's location - copy the repo anywhere.
#
# Auto-update is OPT-IN: set $env:CANARYGUARD_AUTO_UPDATE = '1' (or machine env
# var) to enable `git pull --ff-only` before every start. Default is OFF so an
# unreviewed upstream change never reaches this host with your privileges.
$ErrorActionPreference = 'SilentlyContinue'
$dir = $PSScriptRoot
if (-not $dir) { $dir = Split-Path -Parent $MyInvocation.MyCommand.Path }

if ($env:CANARYGUARD_AUTO_UPDATE -eq '1') {
    # opt-in only. Pin your deployment by checking out a tag instead of main.
    git -C $dir pull --ff-only 2>$null | Out-Null
}

# prefer python.exe (logs work); override by setting CANARYGUARD_PYTHON
$python = $env:CANARYGUARD_PYTHON
if (-not $python) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { $python = $cmd.Source } else { $python = 'python.exe' }
}
$out = Join-Path $dir 'guard.out.log'
$err = Join-Path $dir 'guard.err.log'
Start-Process $python -ArgumentList '-u', (Join-Path $dir 'main.py') -WorkingDirectory $dir `
    -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
