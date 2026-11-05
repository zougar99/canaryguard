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

# Fast TCP connect probe. Get-NetTCPConnection needs admin rights to report the
# Listen state, so the old check returned false "down" results and revived the
# stack every minute - which piled up dozens of main.py instances.
function Test-Port([string]$h, [int]$p, [int]$ms = 1500) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($h, $p, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($ms, $false)) { return $false }
        $c.EndConnect($ar)
        return $true
    } catch { return $false } finally { $c.Close() }
}

# TCP is not enough: a wedged process keeps the port open but never answers.
# Probe the control API over HTTP; on failure the service is revived.
function Test-Http([string]$url, [int]$seconds = 6) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $seconds
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

# One revive attempt per service every 5 minutes, so a slow start cannot turn
# into a spawn storm.
function Too-Soon([string]$file, [int]$min) {
    if (-not (Test-Path $file)) { return $false }
    try {
        $last = [datetime]::Parse((Get-Content $file -Raw).Trim())
        return (((Get-Date) - $last).TotalMinutes -lt $min)
    } catch { return $false }
}

function Mark-Try([string]$file) {
    try { (Get-Date).ToString('o') | Set-Content -Path $file -NoNewline -Encoding ascii } catch {}
}

# 0. Control supervisor (cgctl.py) must always be alive: it is the piece that
# lets Telegram /start work while the main service is stopped. Never gated by
# tamper.stopped - the supervisor is what clears that flag.
$sup = Get-CimInstance Win32_Process |
    Where-Object { $_.Name -like 'python*.exe' -and $_.CommandLine -like '*cgctl.py*' }
if (-not $sup) {
    if (-not (Too-Soon "$dir\tamper.ctl.cooldown" 5)) {
        Mark-Try "$dir\tamper.ctl.cooldown"
        Start-ScheduledTask -TaskName 'CanaryGuardControl'
        Log "control supervisor down -> revived"
    }
}

# 1. CanaryGuard dashboard/port check.
# If the user asked for a full stop (Telegram /stop or the app), a stop flag
# exists and the watchdog must leave the service down until /start.
$userStopped = Test-Path "$dir\tamper.stopped"
if ($userStopped) {
    # nothing to do: stop is intentional
} elseif (-not (Test-Port '127.0.0.1' 8080) -or
          -not (Test-Http 'http://127.0.0.1:8080/api/control/state' 6)) {
    if (-not (Too-Soon "$dir\tamper.cg.cooldown" 5)) {
        Mark-Try "$dir\tamper.cg.cooldown"
        Start-ScheduledTask -TaskName 'CanaryGuard'
        Log "CanaryGuard down -> reviving"
        if (-not $mute -and $upMin -gt 5) {
            Send-TG "[SHIELD] TAMPER ALERT: CanaryGuard was killed or crashed at $(Get-Date -Format 'HH:mm:ss') - auto-reviving..."
        }
        Start-Sleep -Seconds 15
        if (-not (Test-Port '127.0.0.1' 8080)) {
            if (-not $mute -and $upMin -gt 5) {
                Send-TG "[X] REVIVE FAILED at $(Get-Date -Format 'HH:mm:ss') - manual check needed!"
            }
            Log "revive FAILED"
        } else {
            Log "revive OK"
        }
    }
}

# 2. OpenCanary honeypot check (port 9200 = elasticsearch fake)
if (-not (Test-Port '127.0.0.1' 9200)) {
    if (-not (Too-Soon "$dir\tamper.oc.cooldown" 5)) {
        Mark-Try "$dir\tamper.oc.cooldown"
        Start-ScheduledTask -TaskName 'OpenCanaryHoneypot'
        Log "OpenCanary down -> restarted"
        if (-not $mute -and $upMin -gt 5) {
            Send-TG "[SHIELD] OpenCanary honeypot down at $(Get-Date -Format 'HH:mm:ss') - restarted."
        }
    }
}