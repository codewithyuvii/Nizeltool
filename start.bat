@echo off
setlocal
title Nezel OSINT Launcher
cd /d "%~dp0"

echo.
echo ==========================================
echo          Nezel OSINT Auto Launcher
echo ==========================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo Python install nahi hai ya PATH me set nahi hai.
    echo Python 3.10+ install karo: https://www.python.org/downloads/
    echo Install karte time "Add python.exe to PATH" tick karna.
    echo.
    pause
    exit /b 1
)

echo [1/2] Requirements install ho rahe hain...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Requirements install nahi ho paye. Internet/Python/pip check karo.
    echo.
    pause
    exit /b 1
)

echo.
echo [2/2] Nezel OSINT start ho raha hai...
echo.
python nizeltool.py

echo.
pause
