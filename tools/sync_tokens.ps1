# Windows token -> GitHub Secrets sync.
# Mirrors the macOS sync_tokens.sh logic. Log file excludes token values.
param()

$ErrorActionPreference = 'Stop'
$Project = Split-Path -Parent $PSScriptRoot
$Log = Join-Path $Project 'token_sync.log'
$Repo = $env:GH_REPO
if (-not $Repo) {
    $remote = & git -C $Project remote get-url origin 2>$null
    if ($remote -match 'github\.com[:/](.+?/.+?)(\.git)?$') { $Repo = $Matches[1] }
}
if (-not $Repo) { Write-Error 'Set GH_REPO=owner/repo'; exit 1 }
$Python = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { 'python' }
$Node = if ($env:NODE_BIN) { $env:NODE_BIN } else { 'node' }

function Log([string]$msg) {
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ' + $msg
    Add-Content -Path $Log -Value $line -Encoding UTF8
}

function Set-GhSecret([string]$name, [string]$value) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'gh'
    $psi.Arguments = "secret set $name --repo $Repo"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Write($value)
    $p.StandardInput.Close()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw ('gh secret set failed: ' + $stderr.Trim()) }
    return $true
}

function Get-JwtExpUtc([string]$token) {
    try {
        $parts = $token.Split('.')
        if ($parts.Count -lt 2) { return $null }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        $payload = $payload.PadRight($payload.Length + (4 - $payload.Length % 4) % 4, '=')
        $bytes = [Convert]::FromBase64String($payload)
        $json = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        if (-not $json.exp) { return $null }
        return [DateTimeOffset]::FromUnixTimeSeconds([int64]$json.exp).UtcDateTime
    } catch { return $null }
}

Log ('START sync -> ' + $Repo)

# WorkBuddy: plaintext accessToken first, CDP fallback for encrypted envelope.
$wbToken = $null
$authDir = if ($env:WB_AUTH_DIR) { $env:WB_AUTH_DIR } else { Join-Path $env:LOCALAPPDATA 'CodeBuddyExtension\Data\Public\auth' }
foreach ($name in @('Tencent-Cloud.coding-copilot.info', 'workbuddy-desktop.info')) {
    $file = Join-Path $authDir $name
    if (-not (Test-Path $file)) { continue }
    try {
        $j = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
        $t = $j.auth.accessToken
        if ($t -is [string] -and $t.StartsWith('eyJ')) { $wbToken = $t; break }
    } catch { }
}
if (-not $wbToken) {
    try {
        $cdpPort = if ($env:WB_CDP_PORT) { $env:WB_CDP_PORT } else { '9222' }
        $cdpToken = & $Node (Join-Path $PSScriptRoot 'extract_workbuddy_token_cdp.js') $cdpPort 2>$null
        if ($cdpToken -and $cdpToken.StartsWith('eyJ')) { $wbToken = $cdpToken; Log 'WorkBuddy token via CDP' }
    } catch { }
}
if ($wbToken) {
    $exp = Get-JwtExpUtc $wbToken
    if ($exp -and $exp -le [DateTime]::UtcNow) {
        Log 'ERROR WorkBuddy token expired; skipped (re-login required)'
    } else {
        try { [void](Set-GhSecret 'WORKBUDDY_ACCESS_TOKEN' $wbToken); Log ('WORKBUDDY_ACCESS_TOKEN updated (' + $wbToken.Length + ' chars)') }
        catch { Log ('ERROR WORKBUDDY_ACCESS_TOKEN push failed: ' + $_.Exception.Message) }
    }
} else {
    Log 'ERROR WorkBuddy token unavailable (encrypted envelope; CDP off; kept old secret)'
}

# TRAE JWT
$storage = Join-Path $env:APPDATA 'Trae CN\User\globalStorage\storage.json'
if (-not (Test-Path $storage)) { $storage = Join-Path $env:APPDATA 'TRAE SOLO CN\User\globalStorage\storage.json' }
$traeToken = $null
try {
    $lines = & $Python (Join-Path $PSScriptRoot 'decrypt_trae_token.py') --storage $storage --stdout 2>$null
    $traeToken = ($lines | Where-Object { $_ -match '^eyJ' } | Select-Object -Last 1)
} catch { }
if ($traeToken) {
    $exp = Get-JwtExpUtc $traeToken
    if ($exp -and $exp -le [DateTime]::UtcNow) {
        Log 'ERROR TRAE token expired; skipped (re-login required)'
    } else {
        try { [void](Set-GhSecret 'TRAE_JWT' $traeToken); Log ('TRAE_JWT updated (' + $traeToken.Length + ' chars)') }
        catch { Log ('ERROR TRAE_JWT push failed: ' + $_.Exception.Message) }
    }
} else {
    Log 'ERROR TRAE token unavailable (check Trae CN login)'
}

# Qoder CN token
try {
    $infoJson = & $Node (Join-Path $PSScriptRoot 'decrypt_qoder_token_windows.js') --info-json 2>$null
    $info = $infoJson | ConvertFrom-Json
    $exp = [DateTimeOffset]::Parse($info.expiresAt).UtcDateTime
    if ($exp -le [DateTime]::UtcNow) {
        Log 'ERROR Qoder token expired; skipped (re-login required)'
    } else {
        $qoderToken = & $Node (Join-Path $PSScriptRoot 'decrypt_qoder_token_windows.js') --stdout 2>$null
        if ($qoderToken) {
            try { [void](Set-GhSecret 'QODER_TOKEN' $qoderToken); Log ('QODER_TOKEN updated (' + $qoderToken.Length + ' chars)') }
            catch { Log ('ERROR QODER_TOKEN push failed: ' + $_.Exception.Message) }
        } else { Log 'ERROR Qoder token unavailable' }
    }
} catch { Log ('ERROR Qoder token read failed: ' + $_.Exception.Message) }

Log 'DONE'
