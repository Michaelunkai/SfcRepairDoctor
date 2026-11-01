@echo off
rem SfcRepairDoctor launcher - self-elevates, shows live progress, logs to .\logs
rem Usage: Run-SfcRepairDoctor.cmd [-DiagnoseOnly] [-SkipDism] [-MaxSfcPasses N]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SfcRepairDoctor.ps1" %*
echo.
echo Exit code: %ERRORLEVEL%
pause
