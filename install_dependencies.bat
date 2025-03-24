@echo off
echo ======================================
echo   PentTest Dependencies Installer
echo   Created by DevCraftXCoder
echo ======================================
echo.

:: Check if Python is installed
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [INFO] Python is installed. Installing dependencies...
echo.

:: Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

:: Install required packages
echo.
echo [INFO] Installing paramiko...
pip install paramiko
if %errorlevel% neq 0 (
    echo [WARNING] Failed to install paramiko. Trying with version specification...
    pip install paramiko==3.4.0
)

echo.
echo [INFO] Installing requests...
pip install requests

echo.
echo [INFO] Installing other dependencies...
pip install tqdm colorama

echo.
echo ======================================
echo   Installation Complete!
echo ======================================
echo.
echo You can now run PentTestpy.py
echo.
pause 