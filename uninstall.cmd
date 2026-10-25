@echo off
rem ============================================
rem  GuardKit uninstall script (run as Administrator)
rem  Stops and removes service, scheduled task and startup entry. Keeps install dir.
rem ============================================
setlocal
net session >nul 2>&1
if errorlevel 1 (
  echo Please run this script as Administrator.
  exit /b 1
)

sc stop GuardKitSvc >nul 2>&1
sc delete GuardKitSvc >nul 2>&1
schtasks /delete /tn GuardKitWatch /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v GuardKitWatch /f >nul 2>&1

echo Removed service GuardKitSvc, task GuardKitWatch and startup entry.
set /p REMOVE=Also delete C:\Program Files\GuardKit and log dir? (y/n):
if /i "%REMOVE%"=="y" (
  rmdir /s /q "C:\Program Files\GuardKit" 2>nul
  rmdir /s /q "C:\ProgramData\GuardKit" 2>nul
  echo Deleted.
)
endlocal
