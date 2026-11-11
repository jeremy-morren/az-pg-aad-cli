<#
.SYNOPSIS
Downloads the azpgaad binary for this machine.

.DESCRIPTION
Downloads the azpgaad build for this operating system and architecture from the
project's GitHub releases and writes it to the path you choose. Nothing is
installed: no PATH changes, no admin rights.

PowerShell 7 fetches the .br asset (BrotliStream) and Windows PowerShell 5.1
the .gz asset (GZipStream). If those are missing, it fetches the raw binary.

If the GitHub CLI (gh) is on PATH, the binary is checked against the release's
build-provenance attestation, offline and without a login. -RequireAttestation
makes the check mandatory.

Runs on Windows PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS), either
saved to a file or in memory (see the examples). Failures are thrown as errors;
the script never calls 'exit', so an in-memory run can't close your session.

.PARAMETER OutFile
Where to write the binary. Default: .\azpgaad.exe on Windows, ./azpgaad
elsewhere. If it names an existing directory, the binary gets the default name
inside it. Missing parent directories are created. An existing file is replaced.

.PARAMETER Version
The release to download, as vX.Y.Z. Default: the latest release.

.PARAMETER RequireAttestation
Fail unless the build-provenance attestation can be verified. Needs the GitHub
CLI (gh) on PATH.

.EXAMPLE
(Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.ps1).Content | Invoke-Expression

Runs in memory with no parameters: downloads the latest release to
.\azpgaad.exe (./azpgaad on Linux and macOS).

.EXAMPLE
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/jeremy-morren/az-pg-aad-cli/main/download.ps1).Content)) -OutFile .\tools\azpgaad.exe -Version v0.1.3

Runs in memory with parameters: downloads release v0.1.3 to .\tools\azpgaad.exe.

.EXAMPLE
.\download.ps1 -OutFile C:\tools -RequireAttestation

Runs a saved copy: downloads the latest release to C:\tools\azpgaad.exe, and
fails unless gh can verify its build provenance.

.INPUTS
None.

.OUTPUTS
None. Progress messages are written to the host.

.NOTES
Keep this file ASCII-only with no BOM and Windows PowerShell 5.1 compatible: a
BOM breaks both in-memory forms (CI enforces both rules).

.LINK
https://github.com/jeremy-morren/az-pg-aad-cli
#>

param(
    [string]$OutFile = '',
    [string]$Version = '',
    [switch]$RequireAttestation
)

# A child scope, so that under Invoke-Expression (which runs in the caller's scope)
# the preference variables and helpers below don't leak into the caller's session.
# Errors are thrown, never 'exit', which would close the caller's session too.
& {
    param([string]$OutFile, [string]$Version, [bool]$RequireAttestation)

    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    # 5.1's progress bar makes large downloads many times slower.
    $ProgressPreference = 'SilentlyContinue'
    # Native commands report failure through $LASTEXITCODE, checked below.
    $PSNativeCommandUseErrorActionPreference = $false

    $repo = 'jeremy-morren/az-pg-aad-cli'

    function Write-Status([string]$Message) {
        Write-Host "azpgaad: $Message"
    }

    function Get-HttpStatus($ErrorRecord) {
        $ex = $ErrorRecord.Exception
        if ($ex.PSObject.Properties['Response'] -and $null -ne $ex.Response) {
            return [int]$ex.Response.StatusCode
        }
        return 0
    }

    # Downloads Url to Path. Returns $true on success, $false on HTTP 404,
    # throws on anything else.
    function Get-Asset([string]$Url, [string]$Path) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Path
            return $true
        }
        catch {
            if ((Get-HttpStatus $_) -eq 404) {
                return $false
            }
            throw "download failed: $Url : $($_.Exception.Message)"
        }
    }

    function Expand-Asset([string]$Source, [string]$Destination, [type]$StreamType) {
        $in = [System.IO.File]::OpenRead($Source)
        try {
            $decoder = New-Object -TypeName $StreamType.FullName -ArgumentList $in, ([System.IO.Compression.CompressionMode]::Decompress)
            try {
                $out = [System.IO.File]::Create($Destination)
                try {
                    $decoder.CopyTo($out)
                }
                finally {
                    $out.Dispose()
                }
            }
            finally {
                $decoder.Dispose()
            }
        }
        finally {
            $in.Dispose()
        }
    }

    # TLS 1.2: .NET Framework may still default to TLS 1.0/1.1, which GitHub
    # refuses. (No effect on PowerShell 7, which negotiates TLS 1.2+ anyway.)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Verbose "could not enable TLS 1.2: $($_.Exception.Message)"
    }

    # --- platform -----------------------------------------------------------
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $os = 'windows'
        # PROCESSOR_ARCHITEW6432 is the real architecture when this is a
        # 32-bit (or emulated) PowerShell.
        $archName = $env:PROCESSOR_ARCHITEW6432
        if (-not $archName) {
            $archName = $env:PROCESSOR_ARCHITECTURE
        }
    }
    else {
        if ($IsWindows) {
            $os = 'windows'
        }
        elseif ($IsLinux) {
            $os = 'linux'
        }
        elseif ($IsMacOS) {
            $os = 'darwin'
        }
        else {
            throw 'azpgaad: unsupported operating system'
        }
        $archName = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    }
    switch ($archName.ToUpperInvariant()) {
        'AMD64' { $arch = 'amd64' }
        'X64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "azpgaad: unsupported architecture: $archName" }
    }
    $exe = ''
    if ($os -eq 'windows') {
        $exe = '.exe'
    }
    $asset = "azpgaad-$os-$arch$exe"

    if ($Version) {
        if ($Version -notmatch '^v[0-9][^/\s]*$') {
            throw "azpgaad: invalid -Version '$Version' (expected vX.Y.Z)"
        }
    }

    # AZPGAAD_BASE_URL is a test-only override of the release base URL.
    $baseUrl = $env:AZPGAAD_BASE_URL
    if (-not $baseUrl) {
        $baseUrl = "https://github.com/$repo/releases"
    }
    $baseUrl = $baseUrl.TrimEnd('/')
    if ($Version) {
        $releaseUrl = "$baseUrl/download/$Version"
    }
    else {
        $releaseUrl = "$baseUrl/latest/download"
    }

    # --- output path ----------------------------------------------------------
    if (-not $OutFile) {
        $OutFile = "azpgaad$exe"
    }
    # Resolve against PowerShell's current location (not the process's).
    $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
    if (Test-Path -LiteralPath $target -PathType Container) {
        $target = Join-Path $target "azpgaad$exe"
    }
    $targetDir = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $targetDir -PathType Container)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    # Work next to the target, so the final move is a rename on the same
    # volume and a failed run never leaves a half-written binary behind.
    $work = Join-Path $targetDir ('.azpgaad.' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        # The name must end in .exe on Windows for it to run as a program.
        $bin = Join-Path $work "azpgaad$exe"

        # --- download -------------------------------------------------------
        $stream = 'System.IO.Compression.BrotliStream' -as [type]
        $ext = 'br'
        if ($null -eq $stream) {
            $stream = 'System.IO.Compression.GZipStream' -as [type]
            $ext = 'gz'
        }
        $done = $false
        if ($null -ne $stream) {
            $url = "$releaseUrl/$asset.$ext"
            Write-Status "downloading $url"
            $compressed = Join-Path $work "download.$ext"
            if (Get-Asset $url $compressed) {
                Expand-Asset -Source $compressed -Destination $bin -StreamType $stream
                Remove-Item -LiteralPath $compressed -Force
                $done = $true
            }
            else {
                Write-Status "$asset.$ext not found; falling back to the uncompressed binary"
            }
        }
        if (-not $done) {
            $url = "$releaseUrl/$asset"
            Write-Status "downloading $url"
            if (-not (Get-Asset $url $bin)) {
                throw "azpgaad: not found: $url (no such release, or no build for $os/$($arch)?)"
            }
        }
        if ((Get-Item -LiteralPath $bin).Length -eq 0) {
            throw 'azpgaad: downloaded binary is empty'
        }
        if ($os -ne 'windows') {
            & chmod 755 $bin
            if ($LASTEXITCODE -ne 0) {
                throw "azpgaad: chmod failed on $bin"
            }
        }

        # --- provenance (opportunistic: no login and no GitHub API needed) ---
        $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $gh) {
            $bundle = Join-Path $work 'attestation.sigstore.jsonl'
            if (Get-Asset "$releaseUrl/attestation.sigstore.jsonl" $bundle) {
                # gh has no --quiet: with stdout not a terminal it prints nothing on success; errors still go to stderr.
                & $gh.Path attestation verify $bin --repo $repo --bundle $bundle | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "azpgaad: attestation verification FAILED for $asset - do not use this binary"
                }
                Write-Status 'attestation succeeded'
            }
            elseif ($RequireAttestation) {
                throw 'azpgaad: -RequireAttestation: this release has no attestation.sigstore.jsonl'
            }
            else {
                Write-Status 'note: this release has no attestation bundle; provenance not checked'
            }
        }
        elseif ($RequireAttestation) {
            throw 'azpgaad: -RequireAttestation: the GitHub CLI (gh) is needed to verify the attestation but is not on PATH'
        }
        else {
            Write-Status 'note: gh not found; skipping build-provenance check (see README to verify manually)'
        }

        # --- sanity check and install -----------------------------------------
        $installedVersion = & $bin --version
        if ($LASTEXITCODE -ne 0) {
            throw "azpgaad: the downloaded binary failed to run ($bin --version)"
        }
        Move-Item -LiteralPath $bin -Destination $target -Force
        Write-Status "saved azpgaad $(($installedVersion | Out-String).Trim()) to $target"
    }
    finally {
        if (Test-Path -LiteralPath $work) {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
} $OutFile $Version ([bool]$RequireAttestation)
