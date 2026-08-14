@echo off
rem TableX installer bootstrap for cmd.exe. Downloads and runs install.ps1.
rem
rem   curl -fsSLO https://tablex.dev/install.cmd && install.cmd
rem
rem Configuration flows through the same TABLEX_* environment variables the
rem PowerShell script reads (TABLEX_VERSION, TABLEX_INSTALL_DIR, ...).
rem TABLEX_PS1_URL overrides where the script itself is fetched from (CI).
rem
rem Full path to powershell.exe so a doctored PATH cannot substitute another
rem binary; WebClient.DownloadString is content-type-agnostic, which a Pages
rem MIME type could otherwise break; 3072 = TLS 1.2 for old defaults.

setlocal
if "%TABLEX_PS1_URL%"=="" set "TABLEX_PS1_URL=https://tablex.dev/install.ps1"

rem A PSModulePath inherited from PowerShell 7 (a pwsh-spawned terminal, CI)
rem makes Windows PowerShell resolve Core-only modules it cannot load, and
rem built-ins like Get-FileHash and Expand-Archive vanish. Clearing the
rem variable (scoped to this script by setlocal) lets powershell.exe rebuild
rem its own default module path.
set "PSModulePath="

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; iex (New-Object Net.WebClient).DownloadString($env:TABLEX_PS1_URL)"
exit /b %ERRORLEVEL%
