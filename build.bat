@echo off
setlocal
cd /d "%~dp0"

where go >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Go toolchain not found in PATH.
    echo Install Go 1.21 or newer: https://go.dev/dl/
    pause
    exit /b 1
)

if not exist build mkdir build

echo Building build\navicat-crack.exe ...
go build -trimpath -ldflags "-H windowsgui -s -w" -o build\navicat-crack.exe .
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See messages above.
    pause
    exit /b 1
)

echo.
echo [OK] Build finished:
for %%F in (build\navicat-crack.exe) do echo      %%~fF  ^(%%~zF bytes^)
echo.
echo Reminder: run the exe as administrator to patch libcc.dll.
pause
