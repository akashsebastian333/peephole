<#
    peephole fleet installer - Windows. Run as SYSTEM (JumpCloud Command, PowerShell).

    Idempotent: exits 0 if already at the pinned version, so it is safe to schedule
    on every check-in rather than run once.

    Environment:
      PEEPHOLE_VERSION   pinned release tag, e.g. v0.5.1   (REQUIRED - never "latest")
      PEEPHOLE_MODE      guided (default) | audit | strict | hardened
      PEEPHOLE_BASE_URL  artifact source. STRONGLY PREFERRED: an internal mirror,
                         e.g. https://artifacts.corp/peephole/v0.5.1
      PEEPHOLE_REPO      owner/repo - GitHub fallback, only if no mirror is set
      GH_TOKEN           required for the GitHub fallback while the repo is PRIVATE

    The upstream repo is private, so an unauthenticated GitHub download returns 404
    and an MDM Command has no credential. Mirror the assets to internal storage,
    verify checksums at mirror time, and point PEEPHOLE_BASE_URL at it.

    Exit codes: 0 ok/already current | 1 usage | 2 download/checksum | 3 install
                4 verification
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Log  { param($m) Write-Output "[peephole-install] $m" }
function Die  { param([int]$c,$m) Log "ERROR: $m"; exit $c }

$Version = $env:PEEPHOLE_VERSION
if (-not $Version) { Die 1 'set PEEPHOLE_VERSION to a pinned tag, e.g. v0.5.1' }
$Mode = if ($env:PEEPHOLE_MODE) { $env:PEEPHOLE_MODE } else { 'guided' }
$Repo = if ($env:PEEPHOLE_REPO) { $env:PEEPHOLE_REPO } else { 'akashsebastian333/peephole' }
$Want = $Version.TrimStart('v')

$InstallDir = Join-Path $env:ProgramFiles 'peephole'
$Bin        = Join-Path $InstallDir 'peephole.exe'
$Asset      = 'peephole-windows-amd64.exe'

# TLS 1.2 on older PowerShell hosts.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- 1. skip if already at the pinned version --------------------------------
if (Test-Path $Bin) {
    $cur = & $Bin version 2>$null | Select-Object -First 1
    if ($cur -and $cur -match "^peephole $([regex]::Escape($Want)) ") {
        Log "already at $Want; verifying integrity"
        & $Bin selfcheck *> $null
        if ($LASTEXITCODE -ne 0) { Log 'WARN: selfcheck failed on an existing install' }
        exit 0
    }
}

# --- 2. download + verify checksum -------------------------------------------
$tmp = Join-Path $env:TEMP ("peephole-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $assetPath = Join-Path $tmp $Asset
    $sumsPath  = Join-Path $tmp 'SHA256SUMS'

    if ($env:PEEPHOLE_BASE_URL) {
        $base = $env:PEEPHOLE_BASE_URL.TrimEnd('/')
        Log "downloading $Asset @ $Version from $base"
        Invoke-WebRequest -Uri "$base/$Asset"     -OutFile $assetPath -UseBasicParsing
        Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sumsPath  -UseBasicParsing
    }
    else {
        if (-not $env:GH_TOKEN) {
            Die 1 'the repo is private: set PEEPHOLE_BASE_URL to an internal mirror, or GH_TOKEN for the GitHub fallback'
        }
        $auth = @{ Authorization = "Bearer $($env:GH_TOKEN)" }
        Log "resolving $Version from GitHub (private repo fallback)"
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/tags/$Version" -Headers $auth
        $aid = ($rel.assets | Where-Object name -EQ $Asset).id
        $sid = ($rel.assets | Where-Object name -EQ 'SHA256SUMS').id
        if (-not $aid -or -not $sid) { Die 2 "cannot resolve asset ids for $Version" }
        $dl = $auth.Clone(); $dl['Accept'] = 'application/octet-stream'
        $api = "https://api.github.com/repos/$Repo/releases/assets"
        Invoke-WebRequest -Uri "$api/$aid" -Headers $dl -OutFile $assetPath -UseBasicParsing
        Invoke-WebRequest -Uri "$api/$sid" -Headers $dl -OutFile $sumsPath  -UseBasicParsing
    }

    # SHA256SUMS is "<hash>  <name>" per line, as produced by sha256sum.
    $expected = (Get-Content $sumsPath | Where-Object { $_ -match "\s$([regex]::Escape($Asset))$" } |
                 ForEach-Object { ($_ -split '\s+')[0] } | Select-Object -First 1)
    if (-not $expected) { Die 2 "no checksum entry for $Asset in SHA256SUMS" }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $assetPath).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        Die 2 "CHECKSUM MISMATCH - refusing to install (expected $expected, got $actual)"
    }
    Log 'checksum verified'

    # --- 3. install ----------------------------------------------------------
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    # Mark-of-the-Web: Invoke-WebRequest can attach a Zone.Identifier stream.
    Unblock-File -Path $assetPath -ErrorAction SilentlyContinue
    Copy-Item $assetPath $Bin -Force

    # Machine PATH, only if absent (idempotent, and never duplicates entries).
    $p = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($p -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$p;$InstallDir", 'Machine')
        Log "added $InstallDir to the machine PATH (new sessions only)"
    }

    # --- 4. managed hook config (admin-owned, not user-editable) -------------
    # NB verify this path on a pilot host before fleet rollout: the macOS and Linux
    # locations are confirmed, the Windows one follows the ProgramData convention.
    $mdir = Join-Path $env:ProgramData 'ClaudeCode\managed-settings.d'
    New-Item -ItemType Directory -Path $mdir -Force | Out-Null
    $cmd  = ($Bin -replace '\\','\\\\') + ' hook'
    $json = @"
{
  "hooks": {
    "SessionStart":     [{ "hooks": [{ "type": "command", "command": "$cmd", "timeout": 10 }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "$cmd", "timeout": 10 }] }],
    "PreToolUse":       [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*",
                           "hooks": [{ "type": "command", "command": "$cmd", "timeout": 10 }] }],
    "PostToolUse":      [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                           "hooks": [{ "type": "command", "command": "$cmd", "timeout": 10 }] }],
    "Stop":             [{ "hooks": [{ "type": "command", "command": "$cmd", "timeout": 10 }] }]
  }
}
"@
    # ASCII, no BOM - a UTF-8 BOM breaks strict JSON parsers.
    [IO.File]::WriteAllText((Join-Path $mdir '10-peephole.json'), $json, [Text.UTF8Encoding]::new($false))

    # --- 5. verify the install we just made ---------------------------------
    $got = & $Bin version 2>$null | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or -not $got) { Die 4 'installed binary will not execute' }
    & $Bin selfcheck *> $null
    if ($LASTEXITCODE -ne 0) { Die 4 'selfcheck failed after install' }
    if ($got -notmatch "^peephole $([regex]::Escape($Want)) ") { Die 4 "version mismatch: $got" }

    Log "OK - $got"
    Log "mode default: $Mode (per-project; '$Bin mode <m>' to change)"
    Log "hooks: $mdir\10-peephole.json"
    Log 'REMINDER: exclude **\.peephole\ from Defender on-access scanning'
    exit 0
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
