@echo off
rem Download the azpgaad binary for this machine from cmd.exe / batch files.
rem No install step, no PATH changes, no admin. Delegates to download.ps1 through
rem Windows PowerShell (present on every supported Windows), so compression,
rem attestation checks and options behave exactly as in download.ps1.
rem
rem   curl.exe --fail --silent --show-error --location --output download.cmd https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.cmd
rem   call download.cmd [--output PATH] [--version vX.Y.Z] [--require-attestation]
rem
rem   --output PATH          where to write the binary (default: .\azpgaad.exe)
rem   --version vX.Y.Z       a specific release (default: the latest release)
rem   --require-attestation  fail unless the build provenance can be verified (needs gh)
rem
rem Exit code: 0 success, 1 download/verification failure, 2 bad arguments.
rem If download.ps1 sits next to this file (a repository checkout), that copy is used.

setlocal EnableExtensions
set "AZPGAAD_DL_OUTFILE="
set "AZPGAAD_DL_VERSION="
set "AZPGAAD_DL_REQUIRE="
set "AZPGAAD_DL_SCRIPT=%~dp0download.ps1"
set "AZPGAAD_DL_URL=https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.ps1"

:parse
if "%~1"=="" goto run
if /i "%~1"=="--output" (
    if "%~2"=="" goto missing
    set "AZPGAAD_DL_OUTFILE=%~2"
    shift & shift & goto parse
)
if /i "%~1"=="-o" (
    if "%~2"=="" goto missing
    set "AZPGAAD_DL_OUTFILE=%~2"
    shift & shift & goto parse
)
if /i "%~1"=="--version" (
    if "%~2"=="" goto missing
    set "AZPGAAD_DL_VERSION=%~2"
    shift & shift & goto parse
)
if /i "%~1"=="--require-attestation" (
    set "AZPGAAD_DL_REQUIRE=1"
    shift & goto parse
)
if /i "%~1"=="--help" goto usage
if /i "%~1"=="-h" goto usage
if "%~1"=="/?" goto usage
>&2 echo azpgaad: unknown argument: "%~1"
goto usage_error

:missing
>&2 echo azpgaad: "%~1" needs a value
goto usage_error

:usage
echo usage: download.cmd [--output PATH] [--version vX.Y.Z] [--require-attestation]
exit /b 0

:usage_error
>&2 echo usage: download.cmd [--output PATH] [--version vX.Y.Z] [--require-attestation]
exit /b 2

:run
rem Options travel as environment variables so the -Command string needs no nested
rem quoting (which cmd.exe can't do reliably). TLS 1.2 is forced before the first
rem request because older .NET Framework defaults can't reach GitHub.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "${ErrorActionPreference} = 'Stop'; ${ProgressPreference} = 'SilentlyContinue';" ^
  "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12;" ^
  "try {" ^
  "  if (Test-Path -LiteralPath ${env:AZPGAAD_DL_SCRIPT}) { ${s} = [IO.File]::ReadAllText(${env:AZPGAAD_DL_SCRIPT}) }" ^
  "  else { ${s} = (Invoke-WebRequest -UseBasicParsing ${env:AZPGAAD_DL_URL}).Content }" ^
  "  ${a} = @{};" ^
  "  if (${env:AZPGAAD_DL_OUTFILE}) { ${a}.OutFile = ${env:AZPGAAD_DL_OUTFILE} }" ^
  "  if (${env:AZPGAAD_DL_VERSION}) { ${a}.Version = ${env:AZPGAAD_DL_VERSION} }" ^
  "  if (${env:AZPGAAD_DL_REQUIRE} -eq '1') { ${a}.RequireAttestation = ${true} }" ^
  "  & ([scriptblock]::Create(${s})) @a; exit 0" ^
  "} catch { [Console]::Error.WriteLine(${_}.Exception.Message); exit 1 }"
exit /b %ERRORLEVEL%
