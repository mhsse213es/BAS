$script:K1Port = Get-Random -Minimum 30000 -Maximum 39999
Invoke-A36Test -Id 'k1' -Technique 'T1071.001' -Mode Telemetry -Needle "DestinationPort: $($script:K1Port)" -Require @('sysmon:3') -Summary 'five HTTP beacons with jitter to a loopback server, with an uncommon user agent (T1071.001)' -Attempt {
  $port = $script:K1Port
  $server = {
    param($port, $n)
    $l = New-Object Net.HttpListener
    $l.Prefixes.Add("http://127.0.0.1:$port/")
    try { $l.Start() } catch { return -1 }
    $served = 0
    try {
      for ($i = 0; $i -lt $n; $i++) {
        $ar = $l.BeginGetContext($null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(15000)) { break }
        $ctx = $l.EndGetContext($ar)
        $rd = New-Object IO.StreamReader($ctx.Request.InputStream); [void]$rd.ReadToEnd()
        $ok = [Text.Encoding]::UTF8.GetBytes('{"task":"sleep","seconds":2}')
        $ctx.Response.ContentLength64 = $ok.Length
        $ctx.Response.OutputStream.Write($ok, 0, $ok.Length)
        $ctx.Response.Close()
        $served++
      }
    } finally { $l.Stop(); $l.Close() }
    return $served
  }
  $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
  $ps = [powershell]::Create(); $ps.Runspace = $rs
  [void]$ps.AddScript($server).AddArgument($port).AddArgument(5)
  $h = $ps.BeginInvoke()
  Start-Sleep -Milliseconds 700
  if ($h.IsCompleted) { $served = [int]($ps.EndInvoke($h) | Select-Object -Last 1); try { $ps.Dispose(); $rs.Close() } catch {}; if ($served -lt 0) { return @{ Ran = $false; Note = 'listener_start_failed'; NotApplicable = 'a loopback HTTP listener could not be started on this host' } } }
  $answered = 0; $rng = New-Object Random
  for ($i = 1; $i -le 5; $i++) {
    $body = '{"id":"' + $script:A36Tag + '","seq":' + $i + ',"host":"BAS-SIM"}'
    try { $null = Invoke-WebRequest -Uri "http://127.0.0.1:$port/$($script:A36Tag)/beacon" -Method Post -Body $body -ContentType 'application/json' -UserAgent 'Mozilla/5.0 (BAS-SIM-APT36 beacon)' -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop; $answered++ } catch {}
    if ($i -lt 5) { Start-Sleep -Milliseconds (1500 + $rng.Next(0, 700)) }
  }
  $served = 0
  try { if ($h.AsyncWaitHandle.WaitOne(10000)) { $served = [int]($ps.EndInvoke($h) | Select-Object -Last 1) } } catch {}
  try { $ps.Dispose(); $rs.Close() } catch {}
  if ($served -lt 0) { return @{ Ran = $false; Note = 'listener_start_failed'; NotApplicable = 'a loopback HTTP listener could not be started on this host' } }
  return @{ Ran = ($answered -eq 5 -and $served -eq 5); Note = "beacons_answered=$answered requests_served=$served interval_ms=1500-2200 destination=127.0.0.1:$port no_external_egress=true. Beacon analytics and SIEM ingestion are not verified."; NotApplicable = '' }
}
