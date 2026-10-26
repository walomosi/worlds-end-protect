@echo off
rem ============================================
rem  World's End Protect build (local .NET Framework csc, no VS needed)
rem  Output:
rem    bin\StudentGuard.exe    headless student service (guard + pull policy)
rem    bin\TeacherConsole.exe  teacher GUI (edit policy + HTTP policy server)
rem ============================================
setlocal
set CORE=C:\Windows\Microsoft.NET\Framework64\v4.0.30319
set SRC=%~dp0
if not exist "%SRC%bin" mkdir "%SRC%bin"

echo [1/2] Building StudentGuard.exe ...
"%CORE%\csc.exe" /nologo /optimize+ /target:exe /out:"%SRC%bin\StudentGuard.exe" ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.ServiceProcess.dll ^
  "%SRC%PolicyCore.cs" ^
  "%SRC%StudentGuard.cs"
if errorlevel 1 ( echo StudentGuard build FAILED & exit /b 1 )

echo [2/2] Building TeacherConsole.exe ...
"%CORE%\csc.exe" /nologo /optimize+ /target:winexe /out:"%SRC%bin\TeacherConsole.exe" ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.Drawing.dll ^
  /reference:System.Windows.Forms.dll ^
  "%SRC%PolicyCore.cs" ^
  "%SRC%TeacherConsole.cs"
if errorlevel 1 ( echo TeacherConsole build FAILED & exit /b 1 )

echo.
echo Build OK:
echo   %SRC%bin\StudentGuard.exe
echo   %SRC%bin\TeacherConsole.exe
endlocal
