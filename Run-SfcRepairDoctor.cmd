@echo off
rem SfcRepairDoctor launcher - self-elevates, shows live progress, logs to .\logs
rem Last command is always a native "sfc /scannow"; then control returns to your shell.
rem Usage: Run-SfcRepairDoctor.cmd [-DiagnoseOnly] [-SkipDism] [-MaxSfcPasses N]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SfcRepairDoctor.ps1" %*
exit /b %ERRORLEVEL%
