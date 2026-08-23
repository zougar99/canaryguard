# Tamper watchdog: runs every minute as a scheduled task (SYSTEM-level
# resilience). If CanaryGuard or OpenCanary are killed/crashed, it revives
# them and sends a Telegram alert. Create 'tamper.mute' in this folder to
# silence alerts during intentional maintenance.

$ErrorActionPreference = 'SilentlyContinue'
$dir = 'C:\Users\werlist99\canaryguard'
$cfg = Get-Content "$dir\config.json" -Raw | ConvertFrom-Json
$tg = $cfg.alerts.telegram

function Send-TG([string]$txt) {
    if (-not $tg.bot_token) { return }
    try {
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$($tg.bot_token)/sendMessage" `
            -Method Post -Body @{ chat_id = $tg.chat_id; text = $txt } -TimeoutSec 8 | Out-Null
    } catch {}
}

function Log([string]$line) {
    try { Add-Content -Path "$dir\tamper.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $line" } catch {}
}

$mute = Test-Path "$dir\tamper.mute"
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$upMin = ((Get-Date) - $boot).TotalMinutes

# 1. CanaryGuard dashboard/port check
$cg = Test-NetConnection 127.0.0.1 -Port 8080 -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $cg) {
    Start-ScheduledTask -TaskName 'CanaryGuard'
    Log "CanaryGuard down -> reviving"
    if (-not $mute -and $upMin -gt 5) {
        Send-TG "[SHIELD] TAMPER ALERT: CanaryGuard was killed or crashed at $(Get-Date -Format 'HH:mm:ss') - auto-reviving..."
    }
    Start-Sleep -Seconds 15
    $cg2 = Test-NetConnection 127.0.0.1 -Port 8080 -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $cg2 -and -not $mute -and $upMin -gt 5) {
        Send-TG "[X] REVIVE FAILED at $(Get-Date -Format 'HH:mm:ss') - manual check needed!"
        Log "revive FAILED"
    }
}

# 2. OpenCanary honeypot check (port 9200 = elasticsearch fake)
$oc = Get-NetTCPConnection -State Listen -LocalPort 9200 -ErrorAction SilentlyContinue
if (-not $oc) {
    Start-ScheduledTask -TaskName 'OpenCanaryHoneypot'
    Log "OpenCanary down -> restarted"
    if (-not $mute -and $upMin -gt 5) {
        Send-TG "[SHIELD] OpenCanary honeypot down at $(Get-Date -Format 'HH:mm:ss') - restarted."
    }
}