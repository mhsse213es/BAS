Invoke-A36Test -Id 's5' -Technique 'T1071.004' -Mode Telemetry -Require @('sysmon:22') -Telemetry @('dns:3008') -Summary 'a DNS beacon: five A queries at jittered intervals to run-tagged .invalid names (T1071.004; the earlier mapping T1071.001 was an HTTP technique)' -Attempt {
  $rng = New-Object Random
  $sent = 0; $resolved = 0
  for ($i = 1; $i -le 5; $i++) {
    $name = "$($script:A36Tag)-$i-$($rng.Next(10000000, 99999999)).invalid"
    $ans = $null
    try { $ans = @(Resolve-DnsName -Name $name -DnsOnly -ErrorAction Stop) } catch {}
    $sent++
    if (@($ans | Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' }).Count -gt 0) { $resolved++ }
    if ($i -lt 5) { Start-Sleep -Milliseconds (1500 + $rng.Next(0, 800)) }
  }
  return @{ Ran = ($sent -eq 5); Note = "queries_sent=$sent names_resolved=$resolved interval_ms=1500-2300. Validates host DNS telemetry only; beaconing analytics and SIEM ingestion are not verified."; NotApplicable = '' }
}
