@echo off
setlocal

echo.
echo  ==========================================
echo   Snitch - Starting Server
echo  ==========================================
echo.

:: Move to project root
cd /d "%~dp0.."

:: Check venv exists
if not exist ".venv\Scripts\activate.bat" (
    echo  [ERROR] Virtual environment not found.
    echo          Run setup.bat first.
    pause
    exit /b 1
)

:: Activate venv
call .venv\Scripts\activate.bat

:: Create dirs if missing
if not exist "uploads"  mkdir uploads
if not exist "reports"  mkdir reports

echo  [OK] Starting Snitch on http://localhost:8000
echo  [..] Press Ctrl+C to stop
echo.

:: Open browser after 2 seconds
start "" /b cmd /c "timeout /t 2 >nul && start http://localhost:8000"

:: Start server
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

pause
