@echo off
title GovShield Sentinel Grid - SIH1454
color 0B
echo ================================================================
echo  GOVSHIELD SENTINEL GRID - AI/ML PHISHING DETECTION LAYER
echo  Smart India Hackathon 2026 (SIH1454)
echo ================================================================
echo.

set PYTHON_EXE=python
if exist "%~dp0python_runtime\python.exe" (
    set PYTHON_EXE=%~dp0python_runtime\python.exe
)

echo Using Python: %PYTHON_EXE%
echo Starting FastAPI AI/ML Backend & Web Portal (Port 8000)...
start "GovShield AI Backend & Web Portal (Port 8000)" cmd /k ""%PYTHON_EXE%" run_backend.py"

timeout /t 2 /nobreak >nul
start http://127.0.0.1:8000
echo.
echo ================================================================
echo System online!
echo - Web Portal: http://127.0.0.1:8000
echo - Backend API: http://127.0.0.1:8000/docs
echo - Extension:  %~dp0extension
echo ================================================================
pause
