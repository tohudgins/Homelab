@echo off
REM Wazuh Windows active-response wrapper: pipe the AR stdin JSON into the PowerShell handler.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0remove-threat.ps1"
