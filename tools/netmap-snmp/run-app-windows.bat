@echo off
cd /d "%~dp0"
where pyw >nul 2>nul
if %errorlevel%==0 (
  start "" pyw -3 netmap_app.py
  exit /b
)
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw netmap_app.py
  exit /b
)
chcp 65001 >nul
echo 找不到 Python。請先安裝 Python 3（安裝時勾選 Add python.exe to PATH 與 tcl/tk），再重新執行。
start https://www.python.org/downloads/windows/
pause
