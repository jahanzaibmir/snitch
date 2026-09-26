@echo off
setlocal enabledelayedexpansion

echo.
echo  ==========================================
echo   Snitch - Setup
echo  ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo          Download from https://python.org and check "Add to PATH"
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% found

:: Check pip
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] pip not found. Run: python -m ensurepip
    pause
    exit /b 1
)
echo  [OK] pip found

:: Move to project root (parent of scripts/)
cd /d "%~dp0.."
echo  [..] Working directory: %CD%

:: Create virtual environment
echo.
echo  [..] Creating virtual environment...
if exist ".venv" (
    echo  [..] .venv already exists, skipping creation
) else (
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo  [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created
)

:: Activate venv
call .venv\Scripts\activate.bat
echo  [OK] Virtual environment activated

:: Install dependencies
echo.
echo  [..] Installing dependencies...
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo  [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo  [OK] Dependencies installed

:: Create required directories
if not exist "uploads"  mkdir uploads
if not exist "reports"  mkdir reports

echo.
echo  ==========================================
echo   Setup complete!
echo   Run:  scripts\start.bat
echo  ==========================================
echo.
pause
