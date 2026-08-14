# TableX installer for Windows (PowerShell 5.1 and PowerShell 7+).
#
#   irm https://tablex.dev/install.ps1 | iex
#
# Or download and run with flags:
#   .\install.ps1 -Version v1.0.1 -InstallDir C:\Tools\TableX
#
# Parameters fall back to environment variables so the piped form is equally
# configurable: TABLEX_VERSION, TABLEX_INSTALL_DIR, TABLEX_BASE_URL,
# TABLEX_NO_MODIFY_PATH.
#
# What it does: detect the architecture, download the release zip and
# SHA256SUMS, verify the checksum (and, when the GitHub CLI is available and
# logged in, the build-provenance attestation), install to
# %LOCALAPPDATA%\Programs\TableX, add that directory to the user PATH, and
# prove the installed binary runs. Errors THROW rather than exit, so a piped
# run returns non-zero without killing an interactive shell.

#Requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'console installer: host-directed progress text is the product, and it must not leak into the pipeline of an irm|iex chain')]
param(
    [string]$Version,
    [string]$InstallDir,
    [string]$BaseUrl,
    [switch]$NoModifyPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Windows PowerShell 5.1 may still default to TLS 1.0; opt in to TLS 1.2+.
# (3072 = Tls12; harmless no-op on PowerShell 7.)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072

$Repo = 'tablexdev/tablex'

function Write-Info([string]$msg) { Write-Host "tablex install: $msg" }
function Fail([string]$msg) { throw "tablex install: $msg" }

# param() wins when the script is run as a file; env vars serve the iex path.
if (-not $Version -and $env:TABLEX_VERSION) { $Version = $env:TABLEX_VERSION }
if (-not $InstallDir -and $env:TABLEX_INSTALL_DIR) { $InstallDir = $env:TABLEX_INSTALL_DIR }
if (-not $BaseUrl -and $env:TABLEX_BASE_URL) { $BaseUrl = $env:TABLEX_BASE_URL }
if (-not $NoModifyPath -and $env:TABLEX_NO_MODIFY_PATH) { $NoModifyPath = $true }
if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\TableX' }

# Send-EnvironmentChange tells running shells the environment block changed
# (WM_SETTINGCHANGE with lParam "Environment") - the broadcast
# [Environment]::SetEnvironmentVariable used to provide before the PATH write
# moved to the raw registry API. Best-effort: on a timeout or an error, new
# terminals still read the registry and stay correct.
function Send-EnvironmentChange {
    try {
        Add-Type -Namespace TablexNative -Name EnvBroadcast -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@ -ErrorAction Stop
        $result = [UIntPtr]::Zero
        # HWND_BROADCAST = 0xffff, WM_SETTINGCHANGE = 0x1A, SMTO_ABORTIFHUNG = 0x2.
        [void][TablexNative.EnvBroadcast]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
    } catch {
        Write-Info 'could not broadcast the PATH change; new terminals will still see it'
    }
}

function Test-GhLoggedIn {
    # gh writes to stderr when not logged in. Under 5.1's EAP=Stop, a native
    # command's redirected stderr becomes a TERMINATING error, so the
    # preference is relaxed around exactly this probe.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { & gh auth status *> $null } catch { return $false } finally { $ErrorActionPreference = $prev }
    return ($LASTEXITCODE -eq 0)
}

function Get-TablexArch {
    # OSArchitecture reports the OPERATING SYSTEM architecture even from an
    # emulated x64 process on an arm64 machine, which is what decides the
    # right binary. The env-var pair is the fallback for exotic hosts.
    $a = $null
    try { $a = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch { $a = $null }
    if (-not $a) {
        $a = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    }
    switch -Regex ($a) {
        '^(X64|AMD64|EM64T)$' { return 'amd64' }
        '^ARM64$'             { return 'arm64' }
        default { Fail "unsupported architecture: $a (supported: x64, arm64)" }
    }
}

function Resolve-LatestTag {
    # The /releases/latest redirect carries the tag and is not rate-limited
    # the way the API is. HttpWebRequest works identically on 5.1 and 7, so
    # one code path serves both editions.
    $req = [System.Net.HttpWebRequest]::Create("https://github.com/$Repo/releases/latest")
    $req.Method = 'HEAD'
    $req.AllowAutoRedirect = $false
    try {
        $resp = $req.GetResponse()
        try { $loc = $resp.Headers['Location'] } finally { $resp.Close() }
    } catch {
        Fail "could not reach github.com to resolve the latest release: $($_.Exception.Message)"
    }
    if (-not $loc) { Fail 'could not resolve the latest release (no redirect from GitHub)' }
    $tag = ($loc.TrimEnd('/') -split '/')[-1]
    if ($tag -notmatch '^v[0-9]') { Fail "could not determine the latest release (got '$tag'); pass -Version vX.Y.Z" }
    return $tag
}

$arch = Get-TablexArch
Write-Info "detected windows/$arch"

if (-not $Version) {
    if ($BaseUrl) { Fail 'TABLEX_BASE_URL / -BaseUrl requires an explicit version' }
    $tag = Resolve-LatestTag
} elseif ($Version.StartsWith('v')) {
    $tag = $Version
} else {
    $tag = "v$Version"
}
Write-Info "installing tablex $tag"

$base = if ($BaseUrl) { $BaseUrl.TrimEnd('/') } else { "https://github.com/$Repo/releases/download/$tag" }
$archive = "tablex_${tag}_windows_${arch}.zip"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tablex-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $zipPath = Join-Path $tmp $archive
    $sumsPath = Join-Path $tmp 'SHA256SUMS'
    Write-Info "downloading $archive..."
    try {
        Invoke-WebRequest -Uri "$base/$archive" -OutFile $zipPath -UseBasicParsing
        Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
    } catch {
        Fail "download failed from ${base}: $($_.Exception.Message)"
    }

    Write-Info 'verifying checksum...'
    # Anchored to the exact file name: a substring match could accept the
    # checksum line of a different artifact whose name shares a suffix.
    $pattern = '^([0-9a-fA-F]{64})\s+\*?' + [regex]::Escape($archive) + '$'
    $line = Get-Content $sumsPath | Where-Object { $_ -match $pattern } | Select-Object -First 1
    if (-not $line) { Fail "no entry for $archive in SHA256SUMS" }
    $expected = [regex]::Match($line, $pattern).Groups[1].Value.ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Fail "checksum mismatch for ${archive}: expected $expected, got $actual. Nothing was installed."
    }

    # Second, independent proof beyond the checksum: GitHub's provenance
    # attestation, pinned to the exact producing workflow. Only applies to
    # GitHub-released artifacts (not a -BaseUrl mirror), and gh only talks to
    # the API when logged in - both degrade to a loud skip, but a FAILED
    # verification is fatal.
    if (-not $BaseUrl) {
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if (-not $gh) {
            Write-Info 'provenance: GitHub CLI not installed; skipping attestation verify (checksum already verified)'
        } else {
            if (-not (Test-GhLoggedIn)) {
                Write-Info 'provenance: GitHub CLI not logged in; skipping attestation verify (checksum already verified)'
            } else {
                Write-Info 'verifying build provenance attestation...'
                & gh attestation verify $sumsPath --repo $Repo --signer-workflow "$Repo/.github/workflows/release.yml" 1> $null
                if ($LASTEXITCODE -ne 0) { Fail 'attestation verification failed for SHA256SUMS; refusing to install' }
                Write-Info "attestation OK (built by $Repo's release workflow)"
            }
        }
    }

    Write-Info 'extracting...'
    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    $src = Join-Path $tmp 'tablex.exe'
    if (-not (Test-Path $src)) { Fail 'archive did not contain tablex.exe' }

    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    $target = Join-Path $InstallDir 'tablex.exe'

    # A RUNNING exe cannot be overwritten but CAN be renamed, so the upgrade
    # dance is: stage the new file, shove any existing binary aside to .old,
    # rename the staged file into place, then clean up the .old (best-effort;
    # it stays behind only while the old binary is still running).
    $staged = Join-Path $InstallDir "tablex.exe.new.$PID"
    Copy-Item $src $staged -Force
    $old = "$target.old"
    if (Test-Path $old) { Remove-Item $old -Force -ErrorAction SilentlyContinue }
    if (Test-Path $target) { Move-Item $target $old -Force }
    Move-Item $staged $target -Force
    if (Test-Path $old) { Remove-Item $old -Force -ErrorAction SilentlyContinue }
    Write-Info "installed $target"

    $got = & $target -version
    if ($LASTEXITCODE -ne 0) { Fail 'the installed binary failed to run' }
    if ($got -ne "tablex $tag") { Fail "installed binary reports '$got', expected 'tablex $tag'" }
    Write-Info "verified: $got"
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# User PATH, exact-entry semantics: split on ';' and compare whole entries
# (trailing slash normalized). A substring test would treat the value as a
# wildcard AND false-match a directory that merely shares the prefix.
#
# The registry value is read RAW and written back under its EXISTING kind.
# [Environment]::GetEnvironmentVariable reads the user PATH expanded and
# SetEnvironmentVariable writes REG_SZ, so the pair permanently converted
# HKCU\Environment\Path from REG_EXPAND_SZ and baked in the current expansion
# of every %VAR% entry (the stock Windows 11 user PATH carries
# %USERPROFILE%\...). Writing ExpandString unconditionally would mirror the
# defect - an existing REG_SZ PATH holding literal %NAME% text would start
# expanding it - so the kind that was there is preserved, and ExpandString is
# used only when CREATING an absent value. Stated consequence, no repair
# heuristic: a machine already converted to REG_SZ by an earlier run stays
# REG_SZ, because "expanded by our bug" and "the operator wrote a literal
# path" are indistinguishable. Raw entries are compared alongside their
# expansions so an expandable entry already covering the target is not
# duplicated.
if (-not $NoModifyPath) {
    $envKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($null -eq $envKey) { Fail 'could not open HKCU\Environment' }
    try {
        $userPath = $envKey.GetValue('Path', $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString # creating an absent value
        if ($null -ne $userPath) { $kind = $envKey.GetValueKind('Path') }
        $want = $InstallDir.TrimEnd('\')
        $entries = @()
        if ($userPath) {
            $entries = $userPath -split ';' | ForEach-Object {
                $raw = $_.Trim().TrimEnd('\')
                $raw
                [Environment]::ExpandEnvironmentVariables($raw).TrimEnd('\')
            }
        }
        if ($entries -notcontains $want) {
            $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
            $envKey.SetValue('Path', $newPath, $kind)
            Send-EnvironmentChange
            Write-Info "added $InstallDir to the user PATH (new terminals pick it up)"
        }
    } finally {
        $envKey.Close()
    }
}

# Current session too, so `tablex` works immediately in this window.
$sessionEntries = $env:Path -split ';' | ForEach-Object { $_.Trim().TrimEnd('\') }
if ($sessionEntries -notcontains $InstallDir.TrimEnd('\')) {
    $env:Path = "$InstallDir;$env:Path"
}

Write-Info "done. Run 'tablex' and open http://localhost:8080 (new terminals see it on PATH)"
