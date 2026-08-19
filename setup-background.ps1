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
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Settings $settings -Principal $principal -Force
    Write-Output "$Name registered (runlevel=$(if ($Highest) {'HIGHEST'} else {'LIMITED'}))"
}

Register-BackgroundTask `
    -Name "CanaryGuard" `
    -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Arguments '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\werlist99\canaryguard\start-canaryguard.ps1"' `
    -WorkDir 'C:\Users\werlist99\canaryguard'

Register-BackgroundTask `
    -Name "OpenCanaryHoneypot" `
    -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Arguments '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\werlist99\opencanary\start-opencanary.ps1"' `
    -WorkDir 'C:\Users\werlist99\opencanary'

Register-BackgroundTask `
    -Name "CanaryGuard" `
    -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Arguments '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\werlist99\canaryguard\start-canaryguard.ps1"' `
    -WorkDir 'C:\Users\werlist99\canaryguard' `
    -Highest

Write-Output "done"
