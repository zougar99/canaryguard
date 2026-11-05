# Launch the always-on CanaryGuard control supervisor.
#
# cgctl.py only talks to Telegram + canaryguard/control.py, so it keeps
# running while the main service is stopped. That is what makes /start work
# from a Telegram group or channel even after a full /stop.
#
# Safe to call repeatedly: a second supervisor is refused (lock file) and
# this script also skips spawning when one is already alive.
#
# python.exe (not pythonw.exe) is used with output redirection because
# pythonw has no stdout/stderr and any print() in imported code would kill
# the process silently.

$ErrorActionPreference = 'SilentlyContinue'
$dir = $PSScriptRoot
if (-not $dir) { $dir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$python = $env:CANARYGUARD_PYTHON
if (-not $python) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) { $python = $cmd.Source } else { $python = 'python.exe' }
}
$out = "$dir\control.out.log"
$err = "$dir\control.err.log"

$existing = Get-CimInstance Win32_Process |
    Where-Object { $_.Name -like 'python*.exe' -and $_.CommandLine -like '*cgctl.py*' }
if ($existing) { exit 0 }

Start-Process $python `
    -ArgumentList '-u', "$dir\cgctl.py" `
    -WorkingDirectory $dir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $out `
    -RedirectStandardError $err
