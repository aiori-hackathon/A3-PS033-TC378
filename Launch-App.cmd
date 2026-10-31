@echo off
cd /d "%~dp0"
if exist "desktop\DiagDiscover.exe" (
  start "" "desktop\DiagDiscover.exe"
) else (
  start "" ".venv\Scripts\pythonw.exe" "desktop_app.py"
)
