@echo off
cd /d "%~dp0.."
echo [1/3] Creating virtual environment...
python -m venv .venv
call .venv\Scripts\activate.bat
echo [2/3] Upgrading pip...
python -m pip install --upgrade pip >nul
echo [3/3] Installing dependencies...
pip install -r requirements.txt
echo.
echo  Setup complete. Run scripts\start.bat to launch Snitch.
pause