@echo off
cd /d "%~dp0"

echo ==============================================
echo  SentinelX Antivirus - Setup
echo ==============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in the system PATH.
    echo Please install Python 3.10 or newer from https://python.org and try again.
    pause
    exit /b 1
)

:: Check requirements.txt
if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found. Make sure you are running this from the SentinelX project folder.
    pause
    exit /b 1
)

:: Create venv if missing
if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

echo [*] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Some dependencies failed to install. Check the output above.
    pause
    exit /b 1
)

echo.
echo ==============================================
echo  Setup complete!
echo  Run SentinelX any time with: run_sentinel.bat
echo ==============================================
echo.
set /p launch="Do you want to launch SentinelX now? (Y/n): "
if /i "%launch%"=="n" goto :done
if /i "%launch%"=="N" goto :done

echo.
echo [*] Launching SentinelX...
python main.py

:done
pause
