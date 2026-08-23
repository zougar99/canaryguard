# Register CanaryGuard + OpenCanary as background scheduled tasks.
# Must run as Administrator (UAC). Creates tasks that start at logon,
# hidden, with output redirected to log files.

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $script = $MyInvocation.MyCommand.Path
    Start-Process -FilePath 'pwsh.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$script`"" -Verb RunAs
    exit
}

Write-Output "elevated as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

function Register-BackgroundTask {
    param(
        [string]$Name,
        [string]$Execute,
        [string]$Arguments,
        [string]$WorkDir,
        [switch]$Highest
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden
    $principal = if ($Highest) {
        New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    } else {
        New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    }
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute $Execute -Argument $Arguments -WorkingDirectory $WorkDir
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -AtLogOn)
    )
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force
    Write-Output "$Name registered (runlevel=$(if ($Highest) {'HIGHEST'} else {'LIMITED'}), startup+logon)"
}

Register-BackgroundTask `
    -Name "CanaryGuard" `
    -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Arguments '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\werlist99\canaryguard\start-canaryguard.ps1"' `
    -WorkDir 'C:\Users\werlist99\canaryguard' `
    -Highest

Register-BackgroundTask `
    -Name "OpenCanaryHoneypot" `
    -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Arguments '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\werlist99\opencanary\start-opencanary.ps1"' `
    -WorkDir 'C:\Users\werlist99\opencanary'

# --- tamper watchdog: every minute, revives killed services + alerts ---
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$tTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
Unregister-ScheduledTask -TaskName "TamperGuard" -Confirm:$false -ErrorAction SilentlyContinue
$tAction = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\werlist99\canaryguard\tamper-check.ps1"' `
    -WorkingDirectory 'C:\Users\werlist99\canaryguard'
Register-ScheduledTask -TaskName "TamperGuard" -Action $tAction -Trigger $tTrigger -Settings $settings -Principal $principal -Force | Out-Null
Write-Output "TamperGuard registered (every 1 min)"

Write-Output "done"
