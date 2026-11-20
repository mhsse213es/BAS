# EM-01 read-only runner for Windows PowerShell 5.1 (no Python, no internet needed).
#
# Runs every step in em-01-steps.json on this host and writes:
#   results.csv   one row per step
#   results.json  steps + host context + source sha256
#   summary.txt   counts, host context, every non-PASS result
#
# Verdict rules mirror orchestrator/internal/scenario/interpreter.go (dominantVerdict):
#   FAIL > ERROR > SKIP > PASS, verdict prefix matched anywhere in the output,
#   FAIL/SKIP/PASS case-insensitive, ERROR must be uppercase. No verdict = NO_VERDICT.
#
# Read-only: the commands are the scenario's own Get-*/registry/query steps.
# Overrides are read by the commands from the environment (BAS_EM01_*).
#
# Usage (elevated PowerShell, from the folder that holds this script and the JSON):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\em01_readonly_run.ps1 -OutDir C:\em01-results\<label>

[CmdletBinding()]
param(
    [string]$StepsJson,
    [Parameter(Mandatory = $true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'
$PS_EXE = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Get-HostContext {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $ptMeaning = switch ([int]$os.ProductType) { 1 { 'Client' } 2 { 'Domain controller' } 3 { 'Server' } default { 'unknown' } }
    [ordered]@{
        hostname          = $env:COMPUTERNAME
        caption           = $os.Caption
        version           = $os.Version
        productType       = [int]$os.ProductType
        productTypeMeaning = $ptMeaning
        manufacturer      = $cs.Manufacturer
        model             = $cs.Model
        partOfDomain      = [bool]$cs.PartOfDomain
        domain            = $cs.Domain
        isAdmin           = [bool]$isAdmin
        runAt             = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        psVersion         = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-Verdict {
    param([string]$Output)
    $fail = $null; $err = $null; $skip = $null; $pass = $null
    foreach ($raw in ($Output -split "`r?`n")) {
        $line = $raw.Trim()
        if ($line -eq '') { continue }
        $low = $line.ToLowerInvariant()
        if ($null -eq $fail -and $low.StartsWith('fail:')) { $fail = $line }
        elseif ($null -eq $err -and $line.StartsWith('ERROR:', [StringComparison]::Ordinal)) { $err = $line }
        elseif ($null -eq $skip -and $low.StartsWith('skip:')) { $skip = $line }
        elseif ($null -eq $pass -and $low.StartsWith('pass:')) { $pass = $line }
    }
    if ($fail) { return @('FAIL', $fail) }
    if ($err)  { return @('ERROR', $err) }
    if ($skip) { return @('SKIP', $skip) }
    if ($pass) { return @('PASS', $pass) }
    return @('NO_VERDICT', '')
}

function Invoke-Step {
    param([string]$Command, [int]$TimeoutSec)
    # UTF-8 with BOM so Windows PowerShell 5.1 reads non-ASCII text in the scenario correctly.
    $tmp = Join-Path $env:TEMP ('em01_' + [guid]::NewGuid().ToString('N') + '.ps1')
    [IO.File]::WriteAllText($tmp, $Command, (New-Object Text.UTF8Encoding($true)))
    try {
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $PS_EXE
        $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$tmp`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $p = [Diagnostics.Process]::Start($psi)
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(($TimeoutSec + 30) * 1000)) {
            try { $p.Kill() } catch {}
            return @{ Output = 'TIMEOUT'; ExitCode = -1 }
        }
        $p.WaitForExit()
        return @{ Output = ($outTask.Result + $errTask.Result); ExitCode = $p.ExitCode }
    } finally {
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}

# ---- main ----
if (-not $StepsJson) { $base = $PSScriptRoot; if (-not $base) { $base = (Get-Location).Path }; $StepsJson = Join-Path $base 'em-01-steps.json' }
if (-not (Test-Path -LiteralPath $StepsJson)) { throw "Steps file not found: $StepsJson" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$doc = Get-Content -LiteralPath $StepsJson -Raw -Encoding UTF8 | ConvertFrom-Json
$hostCtx = Get-HostContext

$rows = New-Object System.Collections.ArrayList
foreach ($s in $doc.steps) {
    $r = Invoke-Step -Command $s.command -TimeoutSec ([int]$s.timeout_sec)
    $pair = Get-Verdict -Output $r.Output
    [void]$rows.Add([pscustomobject]@{
        index        = [int]$s.index
        verdict      = $pair[0]
        name         = $s.name
        technique    = $s.technique_id
        exit_code    = $r.ExitCode
        verdict_line = $pair[1]
        output       = $r.Output.Trim()
    })
    Write-Host ('[{0:00}] {1,-10} {2}' -f [int]$s.index, $pair[0], $s.name)
}

$names = 'PASS', 'FAIL', 'SKIP', 'ERROR', 'NO_VERDICT', 'TIMEOUT'
$counts = [ordered]@{}
foreach ($n in $names) { $counts[$n] = @($rows | Where-Object { $_.verdict -eq $n }).Count }

$rows | Select-Object index, verdict, name, technique, exit_code, verdict_line |
    Export-Csv -LiteralPath (Join-Path $OutDir 'results.csv') -NoTypeInformation -Encoding UTF8

[ordered]@{
    meta    = [ordered]@{
        scenario       = $doc.scenario
        source_file    = $doc.source_file
        source_sha256  = $doc.source_sha256
        steps          = $rows.Count
        counts         = $counts
        host           = $hostCtx
    }
    results = $rows
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutDir 'results.json') -Encoding UTF8

$lines = @(
    "EM-01 read-only run: $($doc.source_file)"
    "Source sha256 (must match the commit): $($doc.source_sha256)"
    "Host: $($hostCtx.hostname) | $($hostCtx.caption) | ProductType=$($hostCtx.productType) ($($hostCtx.productTypeMeaning)) | $($hostCtx.manufacturer) $($hostCtx.model)"
    "Domain: $($hostCtx.domain) (PartOfDomain=$($hostCtx.partOfDomain)) | admin=$($hostCtx.isAdmin) | PowerShell $($hostCtx.psVersion)"
    "Run at: $($hostCtx.runAt)"
    "Counts: " + (($counts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')
    ''
    'Non-PASS results:'
)
foreach ($r in $rows) {
    if ($r.verdict -ne 'PASS') {
        $lines += ('  [{0:00}] {1,-10} {2}' -f $r.index, $r.verdict, $r.name)
        if ($r.verdict_line) { $lines += ('        ' + $r.verdict_line.Substring(0, [Math]::Min(240, $r.verdict_line.Length))) }
    }
}
$lines | Set-Content -LiteralPath (Join-Path $OutDir 'summary.txt') -Encoding UTF8

Write-Host ''
Write-Host ($lines[0..5] -join "`n")
Write-Host "Wrote $OutDir (results.csv, results.json, summary.txt)"
if ($counts['NO_VERDICT'] -gt 0 -or $counts['TIMEOUT'] -gt 0) { exit 2 }
exit 0
