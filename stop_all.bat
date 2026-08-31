@echo off
title Stop GovShield Services
echo Stopping GovShield background services...
powershell -ExecutionPolicy Bypass -File "%~dp0stop_all.ps1"
echo.
pause
