@echo off
REM Double-click launcher for the Secure Access Lab live demo.
REM Runs start_demo.ps1 with an execution-policy bypass scoped to this process only.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_demo.ps1"
pause
