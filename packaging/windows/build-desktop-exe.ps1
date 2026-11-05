# Build CanaryGuard.exe (service) and CanaryGuardApp.exe (desktop app) with PyInstaller.
# Run on Windows from the repo root:  pwsh packaging\windows\build-desktop-exe.ps1
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$icon = Join-Path $root 'static\icons\icon-source.png'

Write-Host "== CanaryGuard desktop/exe build ==" -ForegroundColor Cyan
python -m pip install --upgrade pyinstaller pillow | Out-Null

# service executable: console app, hidden by the scheduled task
python -m PyInstaller --noconfirm --clean --onefile `
    --name CanaryGuard `
    --collect-submodules canaryguard `
    main.py

# desktop app: windowed
python -m PyInstaller --noconfirm --clean --onefile --noconsole `
    --name CanaryGuardApp `
    --collect-submodules canaryguard `
    guardapp.py

# PWA icons for the exe icons (Windows wants .ico; generate one)
python - <<'PY'
from PIL import Image
img = Image.open("static/icons/icon-source.png").convert("RGBA")
img.save("static/icons/icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
print("icon.ico written")
PY

Write-Host ""
Write-Host "Build complete:" -ForegroundColor Green
Write-Host "  dist\CanaryGuard.exe      (service entry point)"
Write-Host "  dist\CanaryGuardApp.exe   (desktop app)"
Write-Host ""
Write-Host "Next: ISCC packaging\windows\CanaryGuard.iss   (or run build-installer.ps1)"
