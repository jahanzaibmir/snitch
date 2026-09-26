@echo off
cd /d "%~dp0.."

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Run setup.bat first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat

echo.
echo  Running Snitch engine tests...
echo.
python test_engine.py

pause
