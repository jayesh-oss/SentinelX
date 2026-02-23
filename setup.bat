@echo off
echo ==============================================
echo SentinelX Antivirus setup
echo ==============================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in the system PATH.
    echo Please install Python 3.9 or newer and try again.
    pause
    exit /b
)

:: Check if virtual environment exists
if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
)

echo [*] Activating virtual environment...
call venv\Scripts\activate

echo [*] Upgrading pip...
python -m pip install --upgrade pip

echo [*] Installing dependencies from requirements.txt...
pip install -r requirements.txt

echo.
echo ==============================================
echo Setup complete! To launch SentinelX in the future,
echo you can run 'run_sentinel.bat' or use the activated env.
echo ==============================================
echo.
set /p launch="Do you want to launch SentinelX now? (Y/n): "
if /i "%launch%"=="n" goto :eof
if /i "%launch%"=="N" goto :eof

echo [*] Launching SentinelX...
python main.py
