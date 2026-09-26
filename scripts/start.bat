@echo off
cd /d "%~dp0.."
if not exist ".venv" (
  echo [!] Virtual environment not found. Run scripts\setup.bat first.
  pause & exit /b 1
)
call .venv\Scripts\activate.bat
start "" /b cmd /c "timeout /t 3 >nul && start http://localhost:8000"
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
pause