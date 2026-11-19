# Cobalt Group BFSI lateral-movement scenarios shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = control blocked access attempt. FAIL = access succeeded unexpectedly. ERROR = unclassifiable result. SKIP = prerequisite unmet.
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }
$script:CgTag = 'bas_cg_lat_' + $script:CgRun

function Test-CgGate { param([string]$Name) return ([string](Get-Item -Path ('env:' + $Name) -ErrorAction SilentlyContinue).Value -ceq 'true') }
function Write-CgVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-LAT-' + $Id + ']')
}
function Complete-CgStep { param($Res, [string]$Id) Write-CgVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

# Undo records (identical to cloud-vm pattern for consistency)
function Get-CgUndoPath { param([string]$Id) return (Join-Path $env:TEMP ('bas-cg-undo\' + $Id + '.json')) }
function New-CgUndoRecord { param([string]$Id, $Data)
  $p = Get-CgUndoPath $Id
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
  $fs = [IO.File]::Open($p, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
  try { $b = [Text.Encoding]::ASCII.GetBytes(($Data | ConvertTo-Json -Depth 6 -Compress)); $fs.Write($b, 0, $b.Length) } finally { $fs.Close() }
}
function Set-CgUndoRecord { param([string]$Id, $Data)
  [IO.File]::WriteAllText((Get-CgUndoPath $Id), ($Data | ConvertTo-Json -Depth 6 -Compress), [Text.Encoding]::ASCII)
}
function Read-CgUndoRecord { param([string]$Id)
  $p = Get-CgUndoPath $Id
  if (-not (Test-Path -LiteralPath $p)) { return $null }
  try { return (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json) } catch { return 'unreadable' }
}
function Remove-CgUndoRecord { param([string]$Id) Remove-Item -LiteralPath (Get-CgUndoPath $Id) -Force -ErrorAction SilentlyContinue }

# Lateral movement helpers
function Test-RdpConnectivity { param([string]$TargetHost, [int]$Port = 3389)
  $res = @{ Outcome = 'error'; Reason = "RDP connectivity test to $TargetHost : $Port failed"; Connected = $false }
  try {
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect($TargetHost, $Port)
    $tcp.Close()
    $res.Connected = $true
    $res.Outcome = 'fail'
    $res.Reason = "RDP port $Port on $TargetHost is reachable and accepting connections"
  } catch {
    if ($_.Exception -match 'refused|timeout|not available') {
      $res.Outcome = 'pass'
      $res.Reason = "RDP port $Port on $TargetHost is blocked or unreachable"
    }
  }
  return $res
}
function Test-SmbShareAccess { param([string]$TargetHost, [string]$Share)
  $res = @{ Outcome = 'error'; Reason = "SMB share access test to \\$TargetHost\$Share failed"; Accessible = $false }
  try {
    $root = "\\$TargetHost\$Share"
    $items = Get-ChildItem -Path $root -Force -ErrorAction Stop | Select-Object -First 5
    $res.Accessible = $true
    $res.Outcome = 'fail'
    $res.Reason = "SMB share \\$TargetHost\$Share is accessible and contains files"
  } catch {
    if ($_.Exception -match 'Access is denied|unauthorized') {
      $res.Outcome = 'pass'
      $res.Reason = "SMB share \\$TargetHost\$Share access was blocked"
    }
  }
  return $res
}
function Test-WinrmAvailability { param([string]$TargetHost, [int]$Port = 5985)
  $res = @{ Outcome = 'error'; Reason = "WinRM availability test to $TargetHost : $Port failed"; Available = $false }
  try {
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect($TargetHost, $Port)
    $tcp.Close()
    $res.Available = $true
    $res.Outcome = 'fail'
    $res.Reason = "WinRM port $Port on $TargetHost is reachable"
  } catch {
    if ($_.Exception -match 'refused|timeout|not available') {
      $res.Outcome = 'pass'
      $res.Reason = "WinRM port $Port on $TargetHost is blocked or unreachable"
    }
  }
  return $res
}
function Invoke-ToolTransferSimulation { param([string]$SourcePath, [string]$DestHost, [string]$DestPath)
  $res = @{ Outcome = 'error'; Reason = "Tool transfer simulation to \\$DestHost\$DestPath failed"; Transferred = $false }
  try {
    $dest = "\\$DestHost\$DestPath"
    Copy-Item -Path $SourcePath -Destination $dest -Force -ErrorAction Stop
    $res.Transferred = $true
    $res.Outcome = 'fail'
    $res.Reason = "File successfully transferred to $dest"
  } catch {
    if ($_.Exception -match 'Access is denied|unauthorized|not found') {
      $res.Outcome = 'pass'
      $res.Reason = "File transfer to $dest was blocked"
    }
  }
  return $res
}
