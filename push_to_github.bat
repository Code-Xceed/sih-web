@echo off
title Push GovShield to GitHub
color 0B
echo ===================================================
echo   Pushing GovShield Sentinel Grid to GitHub
echo   Repository: https://github.com/Code-Xceed/sih-web.git
echo ===================================================
echo.
cd /d "C:\Users\DELL\Desktop\SIH"

echo [1/2] Checking Git status...
"C:\Program Files\Git\cmd\git.exe" status

echo.
echo [2/2] Executing Git Push to main branch...
"C:\Program Files\Git\cmd\git.exe" push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ===================================================
    echo  SUCCESS! All code has been pushed to GitHub!
    echo ===================================================
) else (
    echo.
    echo ===================================================
    echo  Push failed or requires GitHub login credentials.
    echo ===================================================
)
echo.
pause
