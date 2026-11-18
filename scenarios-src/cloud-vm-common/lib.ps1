# Cloud VM mastery shared library. ASCII only, no here-strings. Minified into every step by appctlgen.
# Verdicts: PASS = the cloud control refused the action. FAIL = the action succeeded where the operator did not expect it.
# SKIP = a prerequisite is missing (not a cloud VM, no identity, no CLI, gate not set, target not configured).
# ERROR = the call could not be classified as a control result.
# Tokens, keys and secret values live in process memory only. They are never printed, recorded or written to disk.
$ErrorActionPreference = 'SilentlyContinue'
$script:CvRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:CvTag = 'bas_cv_' + $script:CvRun

function Test-CvGate { param([string]$Name) return ([string](Get-Item -Path ('env:' + $Name) -ErrorAction SilentlyContinue).Value -ceq 'true') }
function Get-CvEnv { param([string]$Name) return [string](Get-Item -Path ('env:' + $Name) -ErrorAction SilentlyContinue).Value }
function Write-CvVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-SIM-' + $Id + ']')
}
function Complete-CvStep { param($Res, [string]$Id) Write-CvVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

function Get-CvAzureInstance {
  try { return Invoke-RestMethod -Headers @{ Metadata = 'true' } -Method GET -Uri 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' -TimeoutSec 2 -ErrorAction Stop } catch { return $null }
}
function Get-CvAzureToken { param([string]$Resource)
  $r = @{ Token = ''; Code = 0 }
  try {
    $t = Invoke-RestMethod -Headers @{ Metadata = 'true' } -Method GET -Uri ('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=' + [uri]::EscapeDataString($Resource)) -TimeoutSec 5 -ErrorAction Stop
    $r.Token = [string]$t.access_token; $r.Code = 200
  } catch { try { $r.Code = [int]$_.Exception.Response.StatusCode } catch {} }
  return $r
}
function Invoke-CvHttp { param([string]$Method, [string]$Uri, [string]$Token, [string]$Body = '', [string]$Version = '')
  $h = @{ Authorization = ('Bearer ' + $Token) }
  if ($Version -ne '') { $h['x-ms-version'] = $Version }
  try {
    if ($Body -ne '') { $b = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType 'application/json' -TimeoutSec 15 -ErrorAction Stop }
    else { $b = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $h -TimeoutSec 15 -ErrorAction Stop }
    return @{ Code = 200; Body = $b; Text = '' }
  } catch {
    $code = 0; $text = ''
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    try { $text = [string]$_.ErrorDetails.Message } catch {}
    return @{ Code = $code; Body = $null; Text = $text }
  }
}
function Resolve-CvHttp { param($Res, [string]$What, [string]$ExpectGate = 'BAS_CLOUD_EXPECT_ENUMERATION')
  if ($Res.Code -ge 200 -and $Res.Code -lt 300) {
    if (Test-CvGate $ExpectGate) { return @{ Outcome = 'skip'; Reason = ($What + ' succeeded, which the operator documents as expected for this workload, so no control verdict is scored') } }
    return @{ Outcome = 'fail'; Reason = ($What + ' succeeded for an identity the operator did not expect to have this access') }
  }
  if ($Res.Code -eq 401 -or $Res.Code -eq 403) { return @{ Outcome = 'pass'; Reason = ($What + ' was refused by the cloud control (HTTP ' + $Res.Code + ')') } }
  return @{ Outcome = 'error'; Reason = ($What + ' returned HTTP ' + $Res.Code + ', which cannot be classified as a control result') }
}

function Get-CvJson { param([string]$Text)
  $i = $Text.IndexOf('{'); $j = $Text.LastIndexOf('}')
  if ($i -lt 0 -or $j -le $i) { return $null }
  try { return ($Text.Substring($i, $j - $i + 1) | ConvertFrom-Json) } catch { return $null }
}
function Test-CvAwsCli { return [bool](Get-Command aws -ErrorAction SilentlyContinue) }
function Invoke-CvAws { param([string[]]$CliArgs)
  $out = (& aws @CliArgs --output json 2>&1 | Out-String)
  return @{ Code = $LASTEXITCODE; Text = $out.Trim() }
}
function Resolve-CvAws { param($Res, [string]$What, [string]$ExpectGate = 'BAS_CLOUD_EXPECT_ENUMERATION')
  if ($Res.Code -eq 0) {
    if (Test-CvGate $ExpectGate) { return @{ Outcome = 'skip'; Reason = ($What + ' succeeded, which the operator documents as expected for this workload, so no control verdict is scored') } }
    return @{ Outcome = 'fail'; Reason = ($What + ' succeeded for an identity the operator did not expect to have this access') }
  }
  if ($Res.Text -match 'Unable to locate credentials|NoCredentialProviders|NoCredentials') { return @{ Outcome = 'skip'; Reason = ('no AWS identity is available to this host, so ' + $What + ' was not attempted') } }
  if ($Res.Text -match 'AccessDenied|UnauthorizedOperation|AuthFailure|not authorized|Forbidden') { return @{ Outcome = 'pass'; Reason = ($What + ' was refused by the cloud control') } }
  return @{ Outcome = 'error'; Reason = ($What + ' failed without a classifiable control answer') }
}

function Get-CvAwsToken { try { return [string](Invoke-RestMethod -Method PUT -Uri 'http://169.254.169.254/latest/api/token' -Headers @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '60' } -TimeoutSec 2 -ErrorAction Stop) } catch { return '' } }
function Get-CvAwsMeta { param([string]$Path)
  $t = Get-CvAwsToken
  if ($t -eq '') { return $null }
  try { return [string](Invoke-RestMethod -Headers @{ 'X-aws-ec2-metadata-token' = $t } -Uri ('http://169.254.169.254/latest/meta-data/' + $Path) -TimeoutSec 2 -ErrorAction Stop) } catch { return $null }
}
function Set-CvAwsRegion { if (-not $env:AWS_DEFAULT_REGION) { $r = Get-CvAwsMeta 'placement/region'; if ($r) { $env:AWS_DEFAULT_REGION = $r.Trim() } } }
function Get-CvAwsRoleName { $r = Get-CvAwsMeta 'iam/security-credentials/'; if (-not $r) { return '' }; return ((($r -split "`n")[0]).Trim()) }

# Undo records. A step writes its record before any cloud object is created, so a run that dies part way can still be
# undone by the step's cleanup, which reads the record and needs nothing from the run's memory. One record per step,
# in the TEMP directory of the run user. New-CvUndoRecord is exclusive: a record left by an earlier run blocks the step.
function Get-CvUndoPath { param([string]$Id) return (Join-Path $env:TEMP ('bas-cv-undo\' + $Id + '.json')) }
function New-CvUndoRecord { param([string]$Id, $Data)
  $p = Get-CvUndoPath $Id
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
  $fs = [IO.File]::Open($p, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
  try { $b = [Text.Encoding]::ASCII.GetBytes(($Data | ConvertTo-Json -Depth 6 -Compress)); $fs.Write($b, 0, $b.Length) } finally { $fs.Close() }
}
function Set-CvUndoRecord { param([string]$Id, $Data)
  [IO.File]::WriteAllText((Get-CvUndoPath $Id), ($Data | ConvertTo-Json -Depth 6 -Compress), [Text.Encoding]::ASCII)
}
function Read-CvUndoRecord { param([string]$Id)
  $p = Get-CvUndoPath $Id
  if (-not (Test-Path -LiteralPath $p)) { return $null }
  try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { return 'unreadable' }
}
function Remove-CvUndoRecord { param([string]$Id) Remove-Item -LiteralPath (Get-CvUndoPath $Id) -Force -ErrorAction SilentlyContinue }
