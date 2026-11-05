@echo off
title simplewall hardening sandbox bootstrap
setlocal

set REPO=%USERPROFILE%\Desktop\simplewall
set EXE64=%REPO%\bin\64\simplewall.exe
set EXE32=%REPO%\bin\32\simplewall.exe

echo ============================================================
echo  simplewall hardening-round-1 - isolated test environment
echo ============================================================
echo.

if exist "%EXE64%" (
    set "APP=%EXE64%"
) else if exist "%EXE32%" (
    set "APP=%EXE32%"
) else (
    echo [!] No built simplewall.exe found under %REPO%\bin\{64,32}\.
    echo     Build the solution on the HOST first (Release ^| x64),
    echo     then close and re-open this .wsb file.
    echo.
    pause
    exit /b 1
)

echo [*] Launching %APP% (UAC elevates silently inside the sandbox)...
powershell -NoProfile -Command "Start-Process -FilePath '%APP%' -Verb RunAs"

echo.
echo [!] WAIT for simplewall to initialize, then:
echo     1. Click the shield (toolbar) to ENABLE filtering - first run
echo        starts disabled by design.
echo     2. Re-open a notification or trigger one to test the gates.
echo.

echo [*] Running automated smoke tests (FR-08 bogus-pointer, no-crash)...
timeout /t 20 /nobreak >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%REPO%\tools\hardening-smoke-tests.ps1"

echo.
echo ============================================================
echo  Manual checks (see docs\specs\hardening-round-1\verification.md):
echo   - FR-05: idle token shows SE_INC_BASE_PRIORITY only
echo            (Process Explorer -\> simplewall -\> Security tab)
echo   - FR-04: set LogViewer to any binary, open log -\> viewer must
echo            run MEDIUM integrity (never High)
echo   - FR-09: icacls on the log file = user + administrators only
echo   - FR-03: re-run the smoke script with
echo            -TestInternalOverride -ProfileDir ^<config dir^>
echo ============================================================
echo.
echo Everything in this sandbox (including any blocking misconfig)
echo is discarded when you close the window.
pause
