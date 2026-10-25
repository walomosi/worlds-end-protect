@echo off
rem ============================================
rem  GuardKit install launcher (v2: GUI deployment)
rem  Build first (build.cmd), then run bin\GuardGui.exe AS ADMIN and click "Deploy".
rem  Deploy creates: 3 replicas (mutual watch) + service + scheduled task + startup + encrypted config.
rem ============================================
setlocal
set SRC=%~dp0

if not exist "%SRC%bin\GuardGui.exe" (
  echo GuardGui.exe not found. Run build.cmd first.
  exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
  echo Please run this script as Administrator (or right-click GuardGui.exe - Run as administrator).
  exit /b 1
)

echo Starting GuardKit console, click "Deploy" in the window...
start "" "%SRC%bin\GuardGui.exe"
echo Started. Check service/replica status in the console.
endlocal
