@echo off
rem Starts the SecureOTA-V demo console and opens it in the browser.
cd /d "%~dp0"
call .venv\Scripts\activate.bat
if not exist console\web\dist\index.html (
    echo Building the web UI for the first time, please wait...
    pushd console\web
    call npm install
    call npm run build
    popd
)
rem Open the browser a few seconds later, once the server is up.
start "" /b cmd /c "timeout /t 4 >nul & start http://127.0.0.1:8000"
python console\server.py
pause
