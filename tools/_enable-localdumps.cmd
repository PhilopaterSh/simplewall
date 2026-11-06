@echo off
rem One-shot admin helper: enable WER LocalDumps for simplewall.exe (crash capture)
rem Created by ZCode debugging session 2026-11-07. Safe: only writes LocalDumps keys.
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpFolder /t REG_EXPAND_SZ /d "%LOCALAPPDATA%\CrashDumps" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpType /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpCount /t REG_DWORD /d 5 /f
if errorlevel 1 (echo FAILED > "%~dp0_ld_ok.txt") else echo OK > "%~dp0_ld_ok.txt"
exit /b 0
