@echo off
rem World's End Protect - student endpoint uninstaller (run as Administrator)
setlocal
echo Removing WEPStudent service ...
sc stop WEPStudent >nul 2>&1
sc delete WEPStudent >nul 2>&1

echo Removing watchdog task ...
schtasks /delete /tn WEPWatch /f >nul 2>&1

echo Removing Run autostart ...
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WEPWatch /f >nul 2>&1

echo.
echo Uninstalled service/task/autostart. The folder
echo   C:\Program Files\WorldEndProtect
echo is left in place; delete it manually if you are sure.
endlocal
