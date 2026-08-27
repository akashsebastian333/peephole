<#
    peephole fleet installer - Windows. Run as SYSTEM (Intune, JumpCloud, GPO).

    Intune platform / remediation script (defaults are the opposite):
      Run using logged-on credentials = No   (SYSTEM)
      Run script in 64-bit PowerShell host = Yes
      Enforce script signature check = No    (this script is unsigned)
    32-bit SYSTEM writes Program Files (x86) / WOW64; Claude Code reads
    C:\Program Files\ClaudeCode\ only.

    Idempotent: exits 0 if already at the pinned version, so it is safe to schedule
    on every check-in rather than run once.

    Environment:
      PEEPHOLE_VERSION   pinned release tag, e.g. v0.5.1   (REQUIRED - never "latest")
      PEEPHOLE_REPO      owner/repo - default akashsebastian333/peephole
      PEEPHOLE_BASE_URL  optional. If unset, downloads from
                         https://github.com/$REPO/releases/download/$VERSION/
                         Set this only if you already host a copy of that directory.
      GH_TOKEN           only for a private fork (GitHub assets API)

    Public GitHub releases download unauthenticated. See docs/ENTERPRISE.md.

    Exit codes: 0 ok/already current | 1 usage | 2 download/checksum | 3 install
                4 verification
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Log  { param($m) Write-Output "[peephole-install] $m" }
function Die  { param([int]$c,$m) Log "ERROR: $m"; exit $c }

function Write-PeepholeHooks {
    param($BinPath)
    $mdir = 'C:\Program Files\ClaudeCode\managed-settings.d'
    New-Item -ItemType Directory -Path $mdir -Force | Out-Null
    $exe  = $BinPath -replace '\\','\\\\'
    $json = @"
{
  "hooks": {
    "SessionStart":       [{ "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }],
    "SubagentStart":      [{ "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }],
    "UserPromptSubmit":   [{ "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }],
    "PreToolUse":         [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*",
                             "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }],
    "PostToolUse":        [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                             "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }],
    "Stop":               [{ "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }],
    "ConfigChange":       [{ "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }],
    "InstructionsLoaded": [{ "hooks": [{ "type": "command", "command": "$exe", "args": ["hook"], "timeout": 10 }] }]
  }
}
"@
    [IO.File]::WriteAllText((Join-Path $mdir '10-peephole.json'), $json, [Text.UTF8Encoding]::new($false))
    return $mdir
}

function Write-PeepholePin {
    param($BinPath)
    $h = (Get-FileHash -Algorithm SHA256 -Path $BinPath).Hash.ToLower()
    $name = [IO.Path]::GetFileName($BinPath)
    $pin = "{`"$name`":`"$h`"}"
    [IO.File]::WriteAllText((Join-Path (Split-Path $BinPath) 'manifest.sha256'), $pin, [Text.UTF8Encoding]::new($false))
}

$Version = $env:PEEPHOLE_VERSION
if (-not $Version) { Die 1 'set PEEPHOLE_VERSION to a pinned tag, e.g. v0.5.1' }
if (-not [Environment]::Is64BitProcess) {
    Die 1 'must run in 64-bit PowerShell (Intune: Run script in 64-bit PowerShell host = Yes)'
}
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
        Log "already at $Want; refreshing hooks"
        Write-PeepholeHooks $Bin | Out-Null
        $pin = Join-Path $InstallDir 'manifest.sha256'
        if (-not (Test-Path $pin)) { Write-PeepholePin $Bin }
        & $Bin selfcheck *> $null
        if ($LASTEXITCODE -ne 0) { Die 4 'selfcheck failed on an existing install' }
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
    elseif ($env:GH_TOKEN) {
        $auth = @{ Authorization = "Bearer $($env:GH_TOKEN)" }
        Log "resolving $Version from GitHub assets API (private fork)"
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/tags/$Version" -Headers $auth
        $aid = ($rel.assets | Where-Object name -EQ $Asset).id
        $sid = ($rel.assets | Where-Object name -EQ 'SHA256SUMS').id
        if (-not $aid -or -not $sid) { Die 2 "cannot resolve asset ids for $Version" }
        $dl = $auth.Clone(); $dl['Accept'] = 'application/octet-stream'
        $api = "https://api.github.com/repos/$Repo/releases/assets"
        Invoke-WebRequest -Uri "$api/$aid" -Headers $dl -OutFile $assetPath -UseBasicParsing
        Invoke-WebRequest -Uri "$api/$sid" -Headers $dl -OutFile $sumsPath  -UseBasicParsing
    }
    else {
        $base = "https://github.com/$Repo/releases/download/$Version"
        Log "downloading $Asset @ $Version from $base"
        Invoke-WebRequest -Uri "$base/$Asset"     -OutFile $assetPath -UseBasicParsing
        Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sumsPath  -UseBasicParsing
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
    Write-PeepholePin $Bin

    # Machine PATH, only if absent (idempotent, and never duplicates entries).
    $p = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($p -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$p;$InstallDir", 'Machine')
        Log "added $InstallDir to the machine PATH (new sessions only)"
    }

    # --- 4. managed hook config (admin-owned, not user-editable) -------------
    $mdir = Write-PeepholeHooks $Bin

    # --- 5. verify the install we just made ---------------------------------
    $got = & $Bin version 2>$null | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or -not $got) { Die 4 'installed binary will not execute' }
    & $Bin selfcheck *> $null
    if ($LASTEXITCODE -ne 0) { Die 4 'selfcheck failed after install' }
    if ($got -notmatch "^peephole $([regex]::Escape($Want)) ") { Die 4 "version mismatch: $got" }

    Log "OK - $got"
    Log "hooks: $mdir\10-peephole.json"
    Log 'mode is per-project; org floor is .peephole-policy.json in the repo'
    Log 'REMINDER: exclude **\.peephole\ from Defender on-access scanning'
    Log 'REMINDER: if Claude Code /status shows (remote) or (HKLM), this drop-in is ignored — put hooks in that source (docs/ENTERPRISE.md)'
    exit 0
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
