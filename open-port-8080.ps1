# Opens port 8080 for inbound traffic using the Windows Firewall.
# Note: this only opens the Windows Firewall rule. The ROUTER also needs
# a port-forwarding rule (manual, see instructions printed at the end).
param(
    [int]$Port = 8080,
    [string]$Name = "CanaryGuard Dashboard"
)

$ErrorActionPreference = "Stop"

Write-Host "=== CanaryGuard port opener ===" -ForegroundColor Cyan
Write-Host "Opening firewall rule for TCP port $Port ..."

try {
    New-NetFirewallRule -DisplayName $Name -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow -Profile Any | Out-Null
    Write-Host "OK: firewall rule created." -ForegroundColor Green
} catch {
    Write-Host "ERROR: could not create firewall rule." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "Run this script as Administrator." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "=== Manual router configuration (NOT done by this script) ===" -ForegroundColor Yellow
Write-Host "1. Open your router admin page (usually http://192.168.1.1 or http://192.168.0.1)"
Write-Host "2. Find 'Port Forwarding' / 'Virtual Server' / 'NAT'"
Write-Host "3. Create a rule:"
Write-Host "     External Port : $Port (TCP)"
Write-Host "     Internal Port : $Port (TCP)"
Write-Host "     Internal IP   : your PC's LAN IP (see below)"
Write-Host "4. Save and reboot the router if needed."
Write-Host ""
$lan = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like "192.168.*" -or $_.IPAddress -like "10.*" -or $_.IPAddress -like "172.*" } | Select-Object -First 1
if ($lan) { Write-Host "Your LAN IP is likely: $($lan.IPAddress)" -ForegroundColor Green }
Write-Host ""
Write-Host "Test externally at: http://wer5huiu.ddns.net:$Port" -ForegroundColor Green