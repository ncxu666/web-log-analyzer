@echo off
title Web Log Analyzer
cd /d "%~dp0"

echo ============================================
echo   Web Access Log Visualization Analyzer
echo   The browser will open automatically.
echo   Close this window to stop the server.
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python and check "Add to PATH".
    pause
    exit /b 1
)

echo Starting server, please wait...
start "" cmd /c "ping -n 3 127.0.0.1 >nul & start http://127.0.0.1:5000"

python app.py

echo.
echo Server stopped.
pause
