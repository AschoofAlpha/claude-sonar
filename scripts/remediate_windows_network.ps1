[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Apply,
    [string]$RestoreFrom,
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$variables = @(
    'DISABLE_TELEMETRY',
    'DISABLE_ERROR_REPORTING',
    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'
)
$backupDir = Join-Path $env:USERPROFILE '.anti-claude-check\backups'

if ($SelfTest) {
    if ($variables.Count -ne 3 -or $variables -notcontains 'DISABLE_TELEMETRY' -or $variables -notcontains 'DISABLE_ERROR_REPORTING' -or $variables -notcontains 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC') {
        throw 'Remediation variable allowlist changed.'
    }
    'Self-test passed.'
    return
}

if ($Apply -and $RestoreFrom) {
    throw 'Use either -Apply or -RestoreFrom, not both.'
}

if ($RestoreFrom) {
    $resolvedBackupDir = [System.IO.Path]::GetFullPath($backupDir + [System.IO.Path]::DirectorySeparatorChar)
    $resolvedBackup = [System.IO.Path]::GetFullPath($RestoreFrom)
    if (-not $resolvedBackup.StartsWith($resolvedBackupDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Restore file must be inside $backupDir"
    }
    if (-not (Test-Path -LiteralPath $resolvedBackup -PathType Leaf)) {
        throw "Backup file not found: $resolvedBackup"
    }
    $backup = Get-Content -LiteralPath $resolvedBackup -Raw | ConvertFrom-Json
    if ($PSCmdlet.ShouldProcess('Claude Code user privacy environment variables', "Restore values from $resolvedBackup")) {
        foreach ($name in $variables) {
            $property = $backup.PSObject.Properties[$name]
            $value = if ($null -eq $property) { $null } else { $property.Value }
            [Environment]::SetEnvironmentVariable($name, $value, 'User')
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
        Write-Host "Restored user environment from $resolvedBackup" -ForegroundColor Green
    }
    exit 0
}

if (-not $Apply) {
    Write-Host 'Plan only: set these documented Claude Code user environment variables to 1:' -ForegroundColor Cyan
    $variables | ForEach-Object { Write-Host "  $_=1" }
    Write-Host 'No changes made. Re-run with -Apply after explicit approval; use -WhatIf to preview.' -ForegroundColor Yellow
    exit 0
}

if (-not $PSCmdlet.ShouldProcess('Claude Code user privacy environment variables', 'Back up current values and set documented opt-outs to 1')) {
    exit 0
}

New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$backup = [ordered]@{}
foreach ($name in $variables) {
    $backup[$name] = [Environment]::GetEnvironmentVariable($name, 'User')
}
$backupPath = Join-Path $backupDir ("privacy-env-{0}-{1}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8))
$backup | ConvertTo-Json | Set-Content -LiteralPath $backupPath -Encoding UTF8

foreach ($name in $variables) {
    [Environment]::SetEnvironmentVariable($name, '1', 'User')
    Set-Item -LiteralPath "Env:$name" -Value '1'
}

Write-Host "Applied documented privacy opt-outs. Backup: $backupPath" -ForegroundColor Green
Write-Host "Rollback: pwsh -NoProfile -File `"$PSCommandPath`" -RestoreFrom `"$backupPath`"" -ForegroundColor Cyan
