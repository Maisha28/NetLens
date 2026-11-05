@echo off
rem NetLens launcher - double-click to start the dashboard WITH Administrator rights
rem (packet capture needs them). Arguments are passed through, e.g.:
rem     run_netlens.bat --live
rem     run_netlens.bat --sim
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights for packet capture...
    echo Click YES on the Windows prompt. A new window will open.
    if "%~1"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    if errorlevel 1 (
        echo.
        echo Could not request Administrator rights.
        echo Right-click run_netlens.bat and choose "Run as administrator" instead.
        pause
    )
    exit /b
)

cd /d "%~dp0"
if exist "venv\Scripts\activate.bat" call "venv\Scripts\activate.bat"
echo Starting NetLens dashboard (close this window or press Ctrl+C to stop)...
python app.py %*
echo.
echo NetLens stopped. If this was unexpected, the message above explains why.
pause
