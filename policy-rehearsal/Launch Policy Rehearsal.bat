@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating the project's private Python environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo Could not create the environment. Install Python 3.10 or newer and try again.
        pause
        exit /b 1
    )
)

".venv\Scripts\python.exe" -c "import streamlit" >nul 2>nul
if errorlevel 1 (
    echo Installing project packages. This is needed only the first time.
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Package installation failed. Check your internet connection and try again.
        pause
        exit /b 1
    )
)

start "Open Policy Rehearsal" powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://127.0.0.1:8501'"
".venv\Scripts\python.exe" -m streamlit run ui\app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false

if errorlevel 1 (
    echo The app stopped with an error. Read the message above for details.
    pause
)
