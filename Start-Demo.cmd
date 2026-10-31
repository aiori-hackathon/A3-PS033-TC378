@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python environment missing. Follow the setup instructions in README.md.
  pause
  exit /b 1
)
echo Open http://127.0.0.1:8765 in your browser after the server starts.
echo Keep this window open while using the demo. Press Ctrl+C to stop.
".venv\Scripts\python.exe" dashboard.py
pause
