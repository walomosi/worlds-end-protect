@echo off
rem ============================================
rem  World's End Protect - student endpoint installer (run as Administrator)
rem  Copies StudentGuard.exe to Program Files, deploys 3 mutual-guard
rem  replicas, registers the WEPStudent service, a watchdog task and Run autostart.
rem  Usage:  install.cmd http://TEACHER-PC:8300
rem ============================================
setlocal
if "%~1"=="" ( echo Usage: install.cmd http://TEACHER-PC:8300 & exit /b 1 )
set INSTALL=C:\Program Files\WorldEndProtect
set TEACHER=%~1

mkdir "%INSTALL%" 2>nul
mkdir "%INSTALL%\backup" 2>nul

set SRC=%~dp0
echo Copying StudentGuard.exe ...
copy /y "%SRC%bin\StudentGuard.exe" "%INSTALL%\StudentGuardA.exe" >nul
copy /y "%INSTALL%\StudentGuardA.exe" "%INSTALL%\StudentGuardB.exe" >nul
copy /y "%INSTALL%\StudentGuardA.exe" "%INSTALL%\StudentGuardC.exe" >nul
copy /y "%INSTALL%\StudentGuardA.exe" "%INSTALL%\backup\StudentGuardA.exe.bak" >nul
copy /y "%INSTALL%\StudentGuardB.exe" "%INSTALL%\backup\StudentGuardB.exe.bak" >nul
copy /y "%INSTALL%\StudentGuardC.exe" "%INSTALL%\backup\StudentGuardC.exe.bak" >nul

echo Writing teacher.url ...
> "%INSTALL%\teacher.url" echo %TEACHER%

echo Registering service WEPStudent ...
sc stop WEPStudent >nul 2>&1
sc delete WEPStudent >nul 2>&1
sc create WEPStudent binPath= "\"%INSTALL%\StudentGuardA.exe\"" start= auto DisplayName= "World's End Protect Student"
sc failure WEPStudent reset= 0 actions= restart/5000/restart/5000/restart/5000

echo Watchdog task (restart service if it stops) ...
schtasks /create /tn WEPWatch /sc MINUTE /mo 1 /ru SYSTEM /rl HIGHEST /f /tr "cmd /c sc query WEPStudent^|findstr /i RUNNING^|^|sc start WEPStudent"

echo Run autostart (one replica joins the mutual guard) ...
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WEPWatch /t REG_SZ /d "\"%INSTALL%\StudentGuardB.exe\" --guard" /f >nul

sc start WEPStudent
echo.
echo Installed. Teacher endpoint: %TEACHER%
echo Logs: %%ProgramData%%\WorldEndProtect\student.log
endlocal
