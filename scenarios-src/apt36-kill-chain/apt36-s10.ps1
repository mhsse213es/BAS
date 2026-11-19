Invoke-A36Test -Id 's10' -Technique 'T1105' -Summary 'a download cradle fetches a payload from a loopback server and its SHA-256 is verified; the payload is not executed (T1105)' -Telemetry @('sysmon:1', 'sysmon:3', 'ps:4104') -Attempt {
  $port = Get-Random -Minimum 20000 -Maximum 29999
  $payload = [Text.Encoding]::UTF8.GetBytes($script:A36Marker + ' benign payload bytes, not executed')
  $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($payload)).Replace('-', '')
  $dst = Join-Path $script:A36Work 'stage2.bin'
  $l = New-Object Net.HttpListener
  $l.Prefixes.Add("http://127.0.0.1:$port/")
  try { $l.Start() } catch { return @{ Ran = $false; Note = 'listener_start_failed'; NotApplicable = 'a loopback HTTP listener could not be started on this host' } }
  $served = $false
  try {
    $ar = $l.BeginGetContext($null, $null)
    $cmd = '(New-Object Net.WebClient).DownloadFile(''http://127.0.0.1:' + $port + '/' + $script:A36Tag + '/update.bin'', ''' + $dst + ''')'
    $child = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList ('-NoProfile -NonInteractive -WindowStyle Hidden -Command "' + $cmd + '"') -WindowStyle Hidden -PassThru
    if ($ar.AsyncWaitHandle.WaitOne(15000)) { $ctx = $l.EndGetContext($ar); $ctx.Response.OutputStream.Write($payload, 0, $payload.Length); $ctx.Response.Close(); $served = $true }
    if ($child) { [void]$child.WaitForExit(20000) }
  } finally { try { $l.Stop() } catch {}; try { $l.Close() } catch {} }
  $match = $false
  if (Test-Path -LiteralPath $dst) { $match = ((Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash -eq $sha) }
  return @{ Ran = $match; Note = "request_served=$served payload_sha256_matches=$match payload_executed=false destination=127.0.0.1:$port no_external_egress=true"; NotApplicable = '' }
}
