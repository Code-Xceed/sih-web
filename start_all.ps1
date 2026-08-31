# GovShield Sentinel Grid - One-Click Launcher (PowerShell)
# SIH 2026 Problem Statement SIH1454

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "🛡️  GOVSHIELD SENTINEL GRID — AI/ML PHISHING DEFENSE LAYER" -ForegroundColor Green
Write-Host "    Smart India Hackathon 2026 (SIH1454)" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Cyan

# Prioritize Portable Python Runtime in project directory
$localPy = "$PSScriptRoot\python_runtime\python.exe"
if (Test-Path $localPy) {
    $pythonExe = $localPy
} else {
    $pythonExe = "python"
    $pythonFound = Get-Command python -ErrorAction SilentlyContinue
    if (!$pythonFound) {
        $customPy = (Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python", "C:\Program Files\Python*" -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
        if ($customPy) { $pythonExe = $customPy }
    }
}

Write-Host "Using Python Runtime: $pythonExe" -ForegroundColor Gray

# 1. Start AI/ML FastAPI Backend & Web Portal (Port 8000)
Write-Host "Starting GovShield AI/ML Backend & Web Portal on http://127.0.0.1:8000..." -ForegroundColor Cyan
Start-Process -FilePath $pythonExe -ArgumentList "run_backend.py" -WindowStyle Normal

Start-Sleep -Seconds 2

Write-Host "`n✅ System Online!" -ForegroundColor Green
Write-Host "• Official Web Portal: http://127.0.0.1:8000" -ForegroundColor White
Write-Host "• Backend API Docs:    http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "• Extension Directory: $PSScriptRoot\extension" -ForegroundColor Yellow

# Open Web Portal in default browser
Start-Process "http://127.0.0.1:8000"
