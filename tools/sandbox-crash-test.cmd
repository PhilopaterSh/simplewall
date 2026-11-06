@echo off
setlocal
set REPO=C:\Users\WDAGUtilityAccount\Desktop\simplewall
set OUT=%REPO%\crash-out
set EXE=%REPO%\bin\64\simplewall.exe

echo === sandbox crash-test bootstrap ===
if not exist "%EXE%" (
  echo [!] no exe at %EXE%
  pause
  exit /b 1
)

echo [*] enabling LocalDumps inside sandbox (admin, no UAC)
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpFolder /t REG_EXPAND_SZ /d "C:\Users\WDAGUtilityAccount\Desktop\simplewall\crash-out" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpType /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\simplewall.exe" /v DumpCount /t REG_DWORD /d 5 /f

echo [*] launching simplewall (asInvoker - WFP needs admin: relaunch expected)
start "" "%EXE%"
timeout /t 12 /nobreak >nul

echo [*] collecting artifacts into crash-out (writable map)
if exist "%LOCALAPPDATA%\simplewall" xcopy /e /y /i "%LOCALAPPDATA%\simplewall" "%OUT%\appdata-simplewall" >nul
if exist "%APPDATA%\simplewall" xcopy /e /y /i "%APPDATA%\simplewall" "%OUT%\roaming-simplewall" >nul
if exist "%USERPROFILE%\Desktop\simplewall_crash\*.dmp" copy /y "%USERPROFILE%\Desktop\simplewall_crash\*.dmp" "%OUT%\" >nul
if exist "%LOCALAPPDATA%\CrashDumps\simplewall*.dmp" copy /y "%LOCALAPPDATA%\CrashDumps\simplewall*.dmp" "%OUT%\" >nul
tasklist /fi "imagename eq simplewall.exe" > "%OUT%\tasklist.txt"
powershell -NoProfile -Command "Get-WinEvent -LogName Application -MaxEvents 40 -ErrorAction SilentlyContinue | Where-Object {$_.Message -match 'simplewall'} | Out-File -Encoding utf8 '%OUT%\events.txt'"

echo.
echo === STATUS ===
tasklist /fi "imagename eq simplewall.exe" | findstr /i simplewall || echo [!] simplewall NOT running
echo.
echo [i] If simplewall is running: click the shield to ENABLE filtering,
echo     then let the tests continue. Artifacts are copied to crash-out
echo     (visible on the HOST in D:\CV\Github\simplewall\crash-out).
pause
