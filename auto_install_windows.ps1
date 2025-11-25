Write-Host "[*] Detecting OS…" -ForegroundColor Cyan
$OS = (Get-CimInstance Win32_OperatingSystem).Caption

if ($OS -notlike "*Windows*") {
    Write-Host "[!] This installer is for Windows only." -ForegroundColor Red
    exit
}

Write-Host "[*] Ensuring Python is installed…" -ForegroundColor Cyan
$python = Get-Command python -ErrorAction SilentlyContinue

if (-not $python) {
    Write-Host "[!] Python not detected. Install Python 3.10+" -ForegroundColor Red
    exit
}

Write-Host "[*] Creating folder structure…" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path logs, temp, reports, rules, scripts/windows, scripts/linux, runners | Out-Null

Write-Host "[*] Setting PowerShell execution policy…" -ForegroundColor Cyan
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force

Write-Host "[*] Installing Python dependencies…" -ForegroundColor Cyan
pip install -r requirements.txt

Write-Host "[*] Installation complete!" -ForegroundColor Green
Write-Host "Run Cross-Guard using: python engine.py --mode audit"
