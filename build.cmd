@echo off
rem ============================================
rem  GuardKit build script (uses local .NET Framework csc, no VS needed)
rem  Output: bin\GuardApp.exe (guard daemon), bin\GuardGui.exe (admin console)
rem ============================================
setlocal
set CORE=C:\Windows\Microsoft.NET\Framework64\v4.0.30319
set SRC=%~dp0
if not exist "%SRC%bin" mkdir "%SRC%bin"

echo [1/2] Building GuardApp.exe ...
"%CORE%\csc.exe" /nologo /optimize+ /target:exe /out:"%SRC%bin\GuardApp.exe" ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.ServiceProcess.dll ^
  "%SRC%GuardCrypto.cs" ^
  "%SRC%GuardApp.cs"
if errorlevel 1 ( echo GuardApp build FAILED & exit /b 1 )

echo [2/2] Building GuardGui.exe ...
"%CORE%\csc.exe" /nologo /optimize+ /target:winexe /out:"%SRC%bin\GuardGui.exe" ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.Drawing.dll ^
  /reference:System.Windows.Forms.dll ^
  "%SRC%GuardCrypto.cs" ^
  "%SRC%GuardGui.cs"
if errorlevel 1 ( echo GuardGui build FAILED & exit /b 1 )

echo.
echo Build OK:
echo   %SRC%bin\GuardApp.exe
echo   %SRC%bin\GuardGui.exe
endlocal
