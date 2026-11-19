$script:K3Listen = Get-Random -Minimum 40000 -Maximum 44999
$script:K3Connect = $script:K3Listen + 1
Invoke-A29Test -Id 'k3' -Technique 'T1090.001' -Needle "listenport=$($script:K3Listen)" -Telemetry @('sysmon:1', 'sec:4688') -Summary 'a local port proxy is configured, used once and removed (T1090.001)' -Attempt {
  if ($env:BAS_CONFIRM_APT29_PORTPROXY -cne 'true') { return @{ Ran = $false; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APT29_PORTPROXY is not set to true; this step adds and removes a netsh port proxy rule and is skipped without it' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Note = 'not_admin'; NotApplicable = 'a netsh port proxy needs an administrator identity' } }
  $lp = $script:K3Listen; $cp = $script:K3Connect
  $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
  $added = $false; $relayed = $false
  $srv = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse('127.0.0.1'), $cp)
  try {
    $srv.Start()
    & $netsh interface portproxy add v4tov4 listenport=$lp listenaddress=127.0.0.1 connectport=$cp connectaddress=127.0.0.1 2>&1 | Out-Null
    $added = (($LASTEXITCODE -eq 0) -and ((& $netsh interface portproxy show v4tov4 | Out-String) -like "*$lp*"))
    if ($added) {
      $c = New-Object Net.Sockets.TcpClient
      $iar = $c.BeginConnect('127.0.0.1', $lp, $null, $null)
      if ($iar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) {
        $acc = $srv.BeginAcceptTcpClient($null, $null)
        $relayed = $acc.AsyncWaitHandle.WaitOne(4000)
      }
      $c.Close()
    }
  } catch {} finally {
    & $netsh interface portproxy delete v4tov4 listenport=$lp listenaddress=127.0.0.1 2>&1 | Out-Null
    $srv.Stop()
  }
  $left = ((& $netsh interface portproxy show v4tov4 | Out-String) -like "*$lp*")
  return @{ Ran = $added; Note = "portproxy_rule_added=$added connection_relayed=$relayed rule_removed=$(-not $left) listen=127.0.0.1:$lp connect=127.0.0.1:$cp"; CleanupOk = (-not $left); NotApplicable = '' }
}
