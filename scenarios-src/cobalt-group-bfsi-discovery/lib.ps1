# Cobalt Group BFSI discovery scenarios shared library. ASCII only. Minified by appctlgen.
# Verdicts: PASS = control blocked discovery. FAIL = discovery succeeded unexpectedly. ERROR = unclassifiable result. SKIP = prerequisite unmet (simulator not running).
$ErrorActionPreference = 'SilentlyContinue'
$script:CgRun = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0, [Math]::Min(8, $env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 2147483647) }

function Write-BfsiVerdict { param([string]$Outcome, [string]$Reason, [string]$Id)
  $p = 'SKIP'
  if ($Outcome -eq 'pass') { $p = 'PASS' } elseif ($Outcome -eq 'fail') { $p = 'FAIL' } elseif ($Outcome -eq 'error') { $p = 'ERROR' }
  Write-Output ($p + ': ' + $Reason + ' [BAS-BFSI-' + $Id + ']')
}
function Complete-BfsiStep { param($Res, [string]$Id) Write-BfsiVerdict $Res.Outcome $Res.Reason $Id; exit 0 }

# Banking simulator helpers
function Get-BankingSimulatorHost {
  $h = $env:BFSI_SIMULATOR_HOST; if ($h) { return $h }
  return 'localhost'
}
function Get-BankingSimulatorPort {
  $p = $env:BFSI_SIMULATOR_PORT; if ($p) { return [int]$p }
  return 9999
}
function Test-BankingSimulatorConnectivity {
  $simHost = Get-BankingSimulatorHost
  $port = Get-BankingSimulatorPort
  $res = @{ Outcome = 'skip'; Reason = "Banking simulator not reachable at ${simHost}:${port}"; Connected = $false }
  try {
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect($simHost, $port)
    $tcp.Close()
    $res.Connected = $true
    $res.Outcome = 'available'
  } catch {
    $res.Outcome = 'skip'
    $res.Reason = "Banking simulator not reachable at ${simHost}:${port} - prerequisite not met"
  }
  return $res
}
function Invoke-BankingSimulatorQuery { param([string]$Endpoint)
  $simHost = Get-BankingSimulatorHost
  $port = Get-BankingSimulatorPort
  $res = @{ Code = 0; Body = $null; Error = '' }
  try {
    $uri = "http://${simHost}:${port}${Endpoint}"
    $res.Body = Invoke-RestMethod -Method GET -Uri $uri -TimeoutSec 5 -ErrorAction Stop
    $res.Code = 200
  } catch {
    try { $res.Code = [int]$_.Exception.Response.StatusCode } catch {}
    $res.Error = $_.Exception.Message
  }
  return $res
}
function Invoke-BankingAppDiscovery {
  $res = @{ Outcome = 'error'; Reason = 'Banking app discovery: query failed'; Apps = @() }
  $sim = Test-BankingSimulatorConnectivity
  if ($sim.Outcome -eq 'skip') { return @{ Outcome = 'skip'; Reason = $sim.Reason } }
  $q = Invoke-BankingSimulatorQuery '/api/banking/apps'
  if ($q.Code -eq 200 -and $q.Body) {
    $res.Apps = @($q.Body | Select-Object -ExpandProperty id -ErrorAction SilentlyContinue)
    if ($res.Apps.Count -gt 0) {
      $res.Outcome = 'fail'
      $res.Reason = "Banking app discovery succeeded: found $($res.Apps.Count) applications"
    } else {
      $res.Outcome = 'error'
      $res.Reason = 'Banking app discovery returned empty list'
    }
  } else {
    if ($q.Code -eq 403) { $res.Outcome = 'pass'; $res.Reason = 'Banking app discovery was blocked (HTTP 403)' }
    else { $res.Reason = "Banking app discovery failed: HTTP $($q.Code) - $($q.Error)" }
  }
  return $res
}
function Invoke-PaymentGatewayDiscovery {
  $res = @{ Outcome = 'error'; Reason = 'Payment gateway discovery: query failed'; Gateways = @() }
  $sim = Test-BankingSimulatorConnectivity
  if ($sim.Outcome -eq 'skip') { return @{ Outcome = 'skip'; Reason = $sim.Reason } }
  $q = Invoke-BankingSimulatorQuery '/api/payments/gateways'
  if ($q.Code -eq 200 -and $q.Body) {
    $res.Gateways = @($q.Body | Select-Object -ExpandProperty id -ErrorAction SilentlyContinue)
    if ($res.Gateways.Count -gt 0) {
      $res.Outcome = 'fail'
      $res.Reason = "Payment gateway discovery succeeded: found $($res.Gateways.Count) gateways"
    } else {
      $res.Outcome = 'error'
      $res.Reason = 'Payment gateway discovery returned empty list'
    }
  } else {
    if ($q.Code -eq 403) { $res.Outcome = 'pass'; $res.Reason = 'Payment gateway discovery was blocked (HTTP 403)' }
    else { $res.Reason = "Payment gateway discovery failed: HTTP $($q.Code) - $($q.Error)" }
  }
  return $res
}
function Invoke-AtmSwitchDiscovery {
  $res = @{ Outcome = 'error'; Reason = 'ATM switch discovery: query failed'; Switches = @() }
  $sim = Test-BankingSimulatorConnectivity
  if ($sim.Outcome -eq 'skip') { return @{ Outcome = 'skip'; Reason = $sim.Reason } }
  $q = Invoke-BankingSimulatorQuery '/api/atm/switches'
  if ($q.Code -eq 200 -and $q.Body) {
    $res.Switches = @($q.Body | Select-Object -ExpandProperty id -ErrorAction SilentlyContinue)
    if ($res.Switches.Count -gt 0) {
      $res.Outcome = 'fail'
      $res.Reason = "ATM switch discovery succeeded: found $($res.Switches.Count) switches"
    } else {
      $res.Outcome = 'error'
      $res.Reason = 'ATM switch discovery returned empty list'
    }
  } else {
    if ($q.Code -eq 403) { $res.Outcome = 'pass'; $res.Reason = 'ATM switch discovery was blocked (HTTP 403)' }
    else { $res.Reason = "ATM switch discovery failed: HTTP $($q.Code) - $($q.Error)" }
  }
  return $res
}
function Invoke-CardholderDataDiscovery {
  $res = @{ Outcome = 'error'; Reason = 'Cardholder data discovery: query failed'; DataStores = @() }
  $sim = Test-BankingSimulatorConnectivity
  if ($sim.Outcome -eq 'skip') { return @{ Outcome = 'skip'; Reason = $sim.Reason } }
  $q = Invoke-BankingSimulatorQuery '/api/data/cardholder-locations'
  if ($q.Code -eq 200 -and $q.Body) {
    $res.DataStores = @($q.Body | Select-Object -ExpandProperty id -ErrorAction SilentlyContinue)
    if ($res.DataStores.Count -gt 0) {
      $res.Outcome = 'fail'
      $res.Reason = "Cardholder data discovery succeeded: found $($res.DataStores.Count) data stores"
    } else {
      $res.Outcome = 'error'
      $res.Reason = 'Cardholder data discovery returned empty list'
    }
  } else {
    if ($q.Code -eq 403) { $res.Outcome = 'pass'; $res.Reason = 'Cardholder data discovery was blocked (HTTP 403)' }
    else { $res.Reason = "Cardholder data discovery failed: HTTP $($q.Code) - $($q.Error)" }
  }
  return $res
}
