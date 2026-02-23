@echo off
echo [*] Activating virtual environment...
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo [WARNING] No venv found. Running on system python.
)

echo [*] Launching SentinelX...
python main.py
pause
