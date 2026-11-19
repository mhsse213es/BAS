Invoke-A29Test -Id 's5' -Technique 'T1071.004' -Mode Telemetry -Require @('sysmon:22') -Telemetry @('dns:3008') -Summary 'periodic DNS beacon pattern to unique non-resolving names (T1071.004)' -Attempt {
  $count = 6
  $resolved = 0; $sent = 0; $failed = 0
  $rng = New-Object Random
  for ($i = 1; $i -le $count; $i++) {
    $label = ('{0:x8}' -f $rng.Next())
    $name = "$($script:A29Tag)_$i" + "_$label.invalid"
    $ans = $null
    try { $ans = @(Resolve-DnsName -Name $name -DnsOnly -ErrorAction Stop) } catch { $failed++ }
    $sent++
    if (@($ans | Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' }).Count -gt 0) { $resolved++ }
    if ($i -lt $count) { Start-Sleep -Milliseconds (1800 + $rng.Next(0, 800)) }
  }
  return @{ Ran = ($sent -eq $count); Note = "queries_sent=$sent queries_failed=$failed names_resolved=$resolved (expected 0 for .invalid) interval_ms=1800-2600 name_pattern=run_index_random8.invalid. This validates host DNS telemetry only; beaconing analytics and SIEM ingestion are not verified."; NotApplicable = '' }
}
