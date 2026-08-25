@echo off
rem pwman -- one-click start for Windows.
rem Creates a private Python environment on first run, then serves the browser
rem interface on 127.0.0.1. Closing this window stops the server and wipes the
rem keys from memory.

setlocal
title pwman
cd /d "%~dp0"

echo pwman - local, encrypted password manager
echo.

rem ---------------------------------------------------------------- Python --
rem The Windows Store stub named python.exe exits non-zero, so probing with a
rem real command is what separates a usable interpreter from a placeholder.
set "PY="
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto have_python
python -c "import sys" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto have_python
goto no_python

:have_python
set "VPY=%~dp0.venv\Scripts\python.exe"
if exist "%VPY%" goto have_venv
echo Setting up a private Python environment in .venv (first run only)...
%PY% -m venv ".venv"
if errorlevel 1 goto venv_failed

:have_venv
"%VPY%" -c "import cryptography, argon2" >nul 2>&1
if not errorlevel 1 goto have_deps
echo Installing dependencies (needs internet, first run only)...
"%VPY%" -m pip install --disable-pip-version-check --quiet cryptography argon2-cffi
if not errorlevel 1 goto have_deps
echo   argon2-cffi is unavailable here - falling back to scrypt.
"%VPY%" -m pip install --disable-pip-version-check --quiet cryptography
if errorlevel 1 goto pip_failed

:have_deps
rem Mirrors pwman.session.default_vault_path() for Windows.
set "VAULT=%APPDATA%\pwman\vault.pmv"
if defined PWMAN_VAULT set "VAULT=%PWMAN_VAULT%"
if exist "%VAULT%" goto have_vault

echo.
echo No vault found at:
echo   %VAULT%
echo.
echo Creating one now. Choose a master password you can remember:
echo it cannot be recovered, reset or recovered for you.
echo.
"%VPY%" -m pwman init
if errorlevel 1 goto init_failed

:have_vault
echo.
echo Starting the browser interface on http://localhost:8765
echo Keep this window open - closing it locks the vault and wipes the keys.
echo.
"%VPY%" -m pwman web %*
if errorlevel 1 goto web_failed
echo.
echo pwman stopped. The vault is locked.
pause
exit /b 0

rem ----------------------------------------------------------------- errors --
:no_python
echo.
echo Python was not found.
echo Install it, then start this file again:
echo.
echo   winget install Python.Python.3.12
echo.
echo (or download it from https://www.python.org/downloads/windows/ and tick
echo  "Add python.exe to PATH" during setup)
echo.
pause
exit /b 1

:venv_failed
echo.
echo Could not create the .venv environment.
echo If this folder is inside OneDrive or a network share, copy it to a local
echo folder such as C:\Users\%USERNAME%\pwman and try again.
echo.
pause
exit /b 1

:pip_failed
echo.
echo Could not install the "cryptography" package.
echo Check the internet connection (a proxy or firewall may block pip) and retry.
echo.
pause
exit /b 1

:init_failed
echo.
echo The vault was not created. Nothing was changed.
echo.
pause
exit /b 1

:web_failed
echo.
echo The web interface could not start.
echo If pwman is already running, open http://localhost:8765 in your browser.
echo To use a different port, start this file from a terminal with: start-windows.cmd --port 8790
echo.
pause
exit /b 1
