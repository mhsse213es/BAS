Invoke-A36Test -Id 's9' -Technique 'T1071.004' -Mode Telemetry -Require @('sysmon:22') -Telemetry @('dns:3008') -Summary 'DNS TXT queries to run-tagged .invalid names, the record type used for C2 registration (T1071.004)' -Attempt {
  $sent = 0; $answered = 0
  for ($i = 1; $i -le 4; $i++) {
    $name = "$($script:A36Tag)-txt$i.invalid"
    $ans = $null
    try { $ans = @(Resolve-DnsName -Name $name -Type TXT -DnsOnly -ErrorAction Stop) } catch {}
    $sent++
    if (@($ans | Where-Object { $_.Type -eq 'TXT' }).Count -gt 0) { $answered++ }
    if ($i -lt 4) { Start-Sleep -Milliseconds 1200 }
  }
  return @{ Ran = ($sent -eq 4); Note = "txt_queries_sent=$sent txt_answers=$answered record_type=TXT. Validates host DNS telemetry only."; NotApplicable = '' }
}
