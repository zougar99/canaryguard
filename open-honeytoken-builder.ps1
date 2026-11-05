$dir = $PSScriptRoot
if (-not $dir) { $dir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$pythonw = $env:CANARYGUARD_PYTHONW
if (-not $pythonw) { $pythonw = 'pythonw.exe' }
Start-Process -FilePath $pythonw -ArgumentList (Join-Path $dir 'honeytoken_builder.py') -WorkingDirectory $dir
