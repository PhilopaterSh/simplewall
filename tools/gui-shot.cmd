@echo off
rem GUI shell (G-1) sandbox verification: launch -gui shell, screenshot it,
rem write both into the writable mapped folder (bin\mergetest on the host).
set REPO=C:\Users\WDAGUtilityAccount\Desktop\simplewall
set OUT=C:\Users\WDAGUtilityAccount\Desktop\mergetest

start "" "%REPO%\bin\mergetest\simplewall.exe" -gui
timeout /t 6 /nobreak >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%REPO%\tools\gui-shot.ps1"
if exist "%OUT%\shell_live.png" (
  echo SCREENSHOT-OK
) else (
  echo SCREENSHOT-FAILED
)
if exist "%OUT%\shell_crash.txt" type "%OUT%\shell_crash.txt"
pause
