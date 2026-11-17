Invoke-A29Test -Id 's2a' -Technique 'T1105' -Summary 'encoded PowerShell fetches a payload from a loopback server and saves it without executing it (T1105, T1059.001, T1027)' -Telemetry @('sysmon:1', 'ps:4104') -Attempt {
  $port = Get-Random -Minimum 20000 -Maximum 29999
  $url = "http://127.0.0.1:$port/$($script:A29Tag)/payload.txt"
  $dst = Join-Path $script:A29Work 'downloaded.txt'
  $l = New-Object Net.HttpListener
  $l.Prefixes.Add("http://127.0.0.1:$port/")
  try { $l.Start() } catch { return @{ Ran = $false; Note = 'listener_start_failed'; NotApplicable = 'a loopback HTTP listener could not be started on this host' } }
  try {
    $ar = $l.BeginGetContext($null, $null)
    $script = "(New-Object Net.WebClient).DownloadString('" + $url + "') | Set-Content -LiteralPath '" + $dst + "'"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $child = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $enc" -WorkingDirectory $script:A29Work -WindowStyle Hidden -PassThru
    $served = $false
    if ($ar.AsyncWaitHandle.WaitOne(15000)) {
      $ctx = $l.EndGetContext($ar)
      $bytes = [Text.Encoding]::UTF8.GetBytes($script:A29Marker + ' benign payload text, not executed')
      $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
      $ctx.Response.Close()
      $served = $true
    }
    if ($child) { [void]$child.WaitForExit(20000) }
  } finally { $l.Stop(); $l.Close() }
  $landed = Test-A29Marker $dst
  return @{ Ran = $landed; Note = "request_served=$served payload_landed=$landed payload_executed=false"; NotApplicable = '' }
}
