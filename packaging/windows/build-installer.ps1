# Full release pipeline: PyInstaller exes -> Inno Setup installer.
# Requires: Python, Inno Setup 6 (ISCC.exe on PATH or at the default location).
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

& (Join-Path $PSScriptRoot 'build-desktop-exe.ps1')

$iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if (-not $iscc) {
    $candidate = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
    if (Test-Path $candidate) { $iscc = $candidate }
}
if (-not $iscc) {
    Write-Host "Inno Setup not found. Install it from https://jrsoftware.org/isinfo.php" -ForegroundColor Red
    Write-Host "Exes are ready in dist\ — install manually or rerun after installing Inno Setup." -ForegroundColor Yellow
    exit 1
}
& $iscc (Join-Path $PSScriptRoot 'CanaryGuard.iss')
Write-Host ""
Write-Host "Installer ready: dist\CanaryGuard-Setup-1.1.0.exe" -ForegroundColor Green
