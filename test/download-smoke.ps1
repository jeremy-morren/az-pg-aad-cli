# Smoke test for download.ps1, run by CI under Windows PowerShell 5.1
# (shell: powershell) and PowerShell 7 (shell: pwsh).
#
#   test/download-smoke.ps1 -Expect br|gz|raw -ServeDir DIR [-Port 8000]
#   test/download-smoke.ps1 -Expect br|gz|raw -ScriptUrl URL   (server already running)
#
# The release tree is laid out as described in test/download-smoke.sh, plus
# download.ps1 copied to download.ps1.txt (so it is served as text/plain, as
# raw.githubusercontent.com does). With -ServeDir, this script serves DIR with
# `python -m http.server` and sets $env:AZPGAAD_BASE_URL itself; otherwise
# $env:AZPGAAD_BASE_URL must point at a running server. download.ps1 is run
# only through the two documented in-memory forms. The binaries must report
# -WantVersion from --version.

param(
    [Parameter(Mandatory = $true)][ValidateSet('br', 'gz', 'raw')][string]$Expect,
    [string]$ServeDir = '',
    [int]$Port = 8000,
    [string]$ScriptUrl = '',
    [string]$WantVersion = 'v0.0.0-ci'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

$server = $null
if ($ServeDir) {
    $ServeDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ServeDir)
    $logBase = Join-Path ([System.IO.Path]::GetTempPath()) ('azpgaad-smoke-server-' + [guid]::NewGuid().ToString('N'))
    $server = Start-Process python -ArgumentList '-m', 'http.server', "$Port", '--bind', '127.0.0.1', '--directory', $ServeDir `
        -PassThru -NoNewWindow -RedirectStandardOutput "$logBase.out" -RedirectStandardError "$logBase.err"
    $env:AZPGAAD_BASE_URL = "http://127.0.0.1:$Port"
    $up = $false
    for ($i = 0; $i -lt 30 -and -not $up; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$env:AZPGAAD_BASE_URL/download.ps1.txt" | Out-Null
            $up = $true
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $up) {
        throw 'test server did not start'
    }
}
if (-not $env:AZPGAAD_BASE_URL) {
    throw 'pass -ServeDir, or set AZPGAAD_BASE_URL'
}
if (-not $ScriptUrl) {
    $ScriptUrl = "$env:AZPGAAD_BASE_URL/download.ps1.txt"
}

$exe = ''
if ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) {
    $exe = '.exe'
}

$content = (Invoke-WebRequest -UseBasicParsing -Uri $ScriptUrl).Content
if ($content -isnot [string]) {
    throw "Invoke-WebRequest .Content is $($content.GetType().FullName), not a string: serve the script as text/plain"
}

if ($Expect -eq 'raw') {
    $pattern = "downloading \S+/azpgaad-[a-z]+-[a-z0-9]+(\.exe)?\s*$"
}
else {
    $pattern = "downloading \S+/azpgaad-[a-z]+-[a-z0-9]+(\.exe)?\.$Expect\s*$"
}

function Assert-Bin([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "FAIL: $Path was not created"
    }
    $v = (& $Path --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "FAIL: $Path --version exited $LASTEXITCODE"
    }
    if (-not $v.Contains($WantVersion)) {
        throw "FAIL: $Path --version printed '$v', want '$WantVersion'"
    }
}

function Assert-Only([string]$Dir, [string[]]$Names) {
    $have = @(Get-ChildItem -LiteralPath $Dir -Force | ForEach-Object { $_.Name } | Sort-Object)
    if (($have -join ',') -ne (@($Names | Sort-Object) -join ',')) {
        throw "FAIL: $Dir contains '$($have -join ',')', want '$($Names -join ',')'"
    }
}

function Assert-Log([string]$Log, [string]$Regex, [string]$What) {
    $found = $false
    foreach ($line in ($Log -split "`r?`n")) {
        if ($line -match $Regex) {
            $found = $true
        }
    }
    if (-not $found) {
        throw "FAIL: expected $What in output:`n$Log"
    }
}

$sb = [scriptblock]::Create($content)
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('azpgaad-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # 1. (iwr).Content | Invoke-Expression - default output in the current location.
    $d1 = Join-Path $work 't1'
    New-Item -ItemType Directory -Path $d1 | Out-Null
    Push-Location $d1
    try {
        $log = $content | Invoke-Expression 6>&1 | Out-String
    }
    finally {
        Pop-Location
    }
    Assert-Log $log $pattern "a .$Expect download"
    if ($Expect -ne 'raw' -and $log -match 'falling back') {
        throw "FAIL: unexpected raw fallback:`n$log"
    }
    Assert-Bin (Join-Path $d1 "azpgaad$exe")
    Assert-Only $d1 @("azpgaad$exe")
    if (Get-Command Get-Asset -ErrorAction SilentlyContinue) {
        throw 'FAIL: download.ps1 leaked its helper functions into the caller scope'
    }
    Write-Host "ok: .Content | Invoke-Expression, default output, picked $Expect"

    # 2. & ([scriptblock]::Create(...)) -OutFile -Version, missing parent dirs.
    $f2 = Join-Path $work "t2\a\b\azpgaad$exe"
    $log = & $sb -OutFile $f2 -Version $WantVersion 6>&1 | Out-String
    Assert-Log $log $pattern "a .$Expect download"
    Assert-Log $log "/download/$([regex]::Escape($WantVersion))/" "the /download/$WantVersion/ URL"
    Assert-Bin $f2
    Assert-Only (Split-Path -Parent $f2) @("azpgaad$exe")
    Write-Host "ok: scriptblock form, -OutFile (nested), -Version $WantVersion"

    # 3. Overwrite; -OutFile naming an existing directory.
    $log = & $sb -OutFile $f2 6>&1 | Out-String
    Assert-Bin $f2
    $d3 = Join-Path $work 't3'
    New-Item -ItemType Directory -Path $d3 | Out-Null
    $log = & $sb -OutFile $d3 6>&1 | Out-String
    Assert-Bin (Join-Path $d3 "azpgaad$exe")
    Assert-Only $d3 @("azpgaad$exe")
    Write-Host 'ok: overwrite, -OutFile DIR'

    # 4. Compressed asset missing (404) -> raw fallback.
    $f4 = Join-Path $work "t4\azpgaad$exe"
    $log = & $sb -OutFile $f4 -Version v0.0.0-rawonly 6>&1 | Out-String
    if ($Expect -ne 'raw') {
        Assert-Log $log 'falling back' 'the 404 fallback to raw'
    }
    Assert-Bin $f4
    Assert-Only (Split-Path -Parent $f4) @("azpgaad$exe")
    Write-Host 'ok: compressed asset 404 -> raw fallback'

    # 5. Failures throw and leave nothing behind. The test server has no
    #    attestation bundle, so -RequireAttestation fails with or without gh.
    $d5 = Join-Path $work 't5'
    New-Item -ItemType Directory -Path $d5 | Out-Null
    $cases = @(
        @{ Name = 'missing release'; Args = @{ OutFile = (Join-Path $d5 "azpgaad$exe"); Version = 'v9.9.9-missing' }; Match = 'not found' },
        @{ Name = '-RequireAttestation'; Args = @{ OutFile = (Join-Path $d5 "azpgaad$exe"); RequireAttestation = $true }; Match = 'RequireAttestation' },
        @{ Name = 'bad -Version'; Args = @{ OutFile = (Join-Path $d5 "azpgaad$exe"); Version = '1.2.3' }; Match = 'invalid -Version' }
    )
    foreach ($c in $cases) {
        $a = $c.Args
        $msg = $null
        try {
            & $sb @a 6>&1 | Out-Null
        }
        catch {
            $msg = $_.Exception.Message
        }
        if ($null -eq $msg) {
            throw "FAIL: $($c.Name) did not fail"
        }
        if ($msg -notmatch $c.Match) {
            throw "FAIL: $($c.Name) failed with '$msg', want /$($c.Match)/"
        }
        Assert-Only $d5 @()
    }
    Write-Host 'ok: failures throw and leave no files'
    Write-Host "PASS ($Expect)"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    if ($null -ne $server) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}
