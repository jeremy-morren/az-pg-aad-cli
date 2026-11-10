@echo off
rem Windows cmd / batch exit-code checks for azpgaad (see README: Exit codes).
rem
rem   test\errorlevel.cmd [EXE] [EXPECTED_VERSION]
rem
rem EXE defaults to azpgaad (found on PATH). EXPECTED_VERSION, if given, must
rem appear in the captured --version output.
rem
rem Checks: exit codes 0 / 2 (usage) / 3 (no token file) as seen by %%ERRORLEVEL%%
rem and "if errorlevel"; for /f capture of --version and of --query ... --output tsv;
rem --names @file and @- (stdin) parsing via --dry-run (no server needed).

setlocal EnableExtensions EnableDelayedExpansion

set "EXE=%~1"
if not defined EXE set "EXE=azpgaad"
set "EXPECTED=%~2"
set FAILED=0
set "PGAADTOKENFILE="

rem 1. --version exits 0, and "if errorlevel 1" (">= 1") does not fire.
"%EXE%" --version >nul
call :expect 0 "--version"
"%EXE%" --version >nul
if errorlevel 1 (
    echo FAIL: "if errorlevel 1" fired after a successful --version
    set FAILED=1
) else (
    echo ok: "if errorlevel 1" does not fire after success
)

rem 2. Capture --version and a --query/-o tsv value with for /f.
set "VER="
for /f "usebackq delims=" %%v in (`"%EXE%" --version`) do set "VER=%%v"
if not defined VER (
    echo FAIL: for /f captured nothing from --version
    set FAILED=1
) else (
    echo ok: for /f captured --version: !VER!
    if defined EXPECTED (
        set "STRIPPED=!VER:%EXPECTED%=!"
        if "!STRIPPED!"=="!VER!" (
            echo FAIL: captured version "!VER!" does not contain "%EXPECTED%"
            set FAILED=1
        ) else (
            echo ok: captured version contains %EXPECTED%
        )
    )
)
set "TSV="
for /f "usebackq delims=" %%v in (`"%EXE%" version --query version --output tsv`) do set "TSV=%%v"
if "!TSV!"=="!VER!" (
    echo ok: for /f captured "version --query version --output tsv": !TSV!
) else (
    echo FAIL: --query/-o tsv capture "!TSV!" differs from --version "!VER!"
    set FAILED=1
)

rem 3. Usage errors exit exactly 2; "if errorlevel 1" fires.
"%EXE%" --definitely-not-a-flag >nul 2>&1
call :expect 2 "unknown flag"
"%EXE%" role drop --name x >nul 2>&1
call :expect 2 "role drop without --yes and no terminal"
"%EXE%" --definitely-not-a-flag >nul 2>&1
if errorlevel 1 (
    echo ok: "if errorlevel 1" fires after a failure
) else (
    echo FAIL: "if errorlevel 1" did not fire after a failure
    set FAILED=1
)

rem 4. No token file exits exactly 3; test highest code first with "if errorlevel".
"%EXE%" role list >nul 2>&1
call :expect 3 "role list with no token file"
"%EXE%" role list >nul 2>&1
if errorlevel 3 (
    echo ok: "if errorlevel 3" fires for not-logged-in
) else (
    echo FAIL: "if errorlevel 3" did not fire
    set FAILED=1
)

rem 5. JSON list input from a file and from stdin (cmd can't quote JSON inline).
set "NAMES=%TEMP%\azpgaad-names-%RANDOM%.json"
> "%NAMES%" echo ["a","b"]
set "OUT="
for /f "usebackq delims=" %%v in (`call "%EXE%" role drop --names "@%NAMES%" --yes --dry-run --query "statements[0]" --output tsv`) do set "OUT=%%v"
call :expect_text "DROP ROLE "a", "b"" "--names @file"
set "OUT="
for /f "usebackq delims=" %%v in (`type "%NAMES%" ^| "%EXE%" role grant --names @- --role r --dry-run --query "statements[0]" --output tsv`) do set "OUT=%%v"
call :expect_text "GRANT "r" TO "a", "b"" "--names @-"
del "%NAMES%" >nul 2>&1

if !FAILED! NEQ 0 (
    echo FAILED
    exit /b 1
)
echo PASS
exit /b 0

:expect
set RC=%ERRORLEVEL%
if "%RC%"=="%~1" (
    echo ok: %~2 exits %RC%
) else (
    echo FAIL: %~2 exited %RC%, want %~1
    set FAILED=1
)
exit /b 0

:expect_text
if "!OUT!"==%1 (
    echo ok: %~2 produced !OUT!
) else (
    echo FAIL: %~2 produced [!OUT!], want %1
    set FAILED=1
)
exit /b 0
