@echo off
cd /d "%~dp0"

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo [WARNING] No virtual environment found. Run setup.bat first.
    echo Attempting to run on system Python...
)

echo [*] Launching SentinelX...
python main.py
pause
