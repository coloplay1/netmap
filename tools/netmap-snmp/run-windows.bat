@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
title netmap-snmp
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 netmap_snmp.py %*
  goto done
)
where python >nul 2>nul
if %errorlevel%==0 (
  python netmap_snmp.py %*
  goto done
)
echo.
echo 找不到 Python。請先安裝 Python 3（安裝時勾選 Add python.exe to PATH），再重新執行。
echo 即將開啟下載頁面…
start https://www.python.org/downloads/windows/
:done
echo.
pause
