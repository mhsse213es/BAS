# Cobalt Group BFSI C2-variants shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = technique succeeded on this unenforced host (real result, not simulated). FAIL = blocked. ERROR = unclassifiable. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }

function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-C2-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

function Get-CgUndoPath { param([string]$Id) return (Join-Path $env:TEMP ('bas-cg-undo\' + $Id + '.json')) }
function New-CgUndoRecord { param([string]$Id, $Data)
  $p = Get-CgUndoPath $Id
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
  $fs = [IO.File]::Open($p, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
  try { $b = [Text.Encoding]::ASCII.GetBytes(($Data | ConvertTo-Json -Depth 6 -Compress)); $fs.Write($b, 0, $b.Length) } finally { $fs.Close() }
}
function Read-CgUndoRecord { param([string]$Id)
  $p = Get-CgUndoPath $Id
  if (-not (Test-Path -LiteralPath $p)) { return $null }
  try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { return 'unreadable' }
}
function Remove-CgUndoRecord { param([string]$Id) Remove-Item -LiteralPath (Get-CgUndoPath $Id) -Force -ErrorAction SilentlyContinue }

function Get-BfsiSimulatorHost { $h = $env:BFSI_SIMULATOR_HOST; if ($h) { return $h }; return 'localhost' }
function Get-BfsiSimulatorPort { $p = $env:BFSI_SIMULATOR_PORT; if ($p) { return [int]$p }; return 9999 }
function Test-BfsiSimulatorConnectivity {
  $simHost = Get-BfsiSimulatorHost
  $port = Get-BfsiSimulatorPort
  try { $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect($simHost, $port); $tcp.Close(); return $true } catch { return $false }
}

function New-CgLoopbackTlsCertificate {
  $cert = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddMinutes(10) -KeyExportPolicy NonExportable
  return $cert.Thumbprint
}
function Remove-CgLoopbackTlsCertificate { param([string]$Thumbprint)
  $cert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $Thumbprint) -ErrorAction SilentlyContinue
  if ($cert) {
    try { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert).Key.Delete() } catch {}
  }
  Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $Thumbprint) -Force -ErrorAction SilentlyContinue
}
function Wait-CgTask { param($Task, [int]$Ms = 5000)
  return [bool]$Task.Wait($Ms)
}
function Test-CgLoopbackTlsCertificate { param([string]$Thumbprint)
  return ((Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $Thumbprint) -ErrorAction SilentlyContinue) -ne $null)
}
