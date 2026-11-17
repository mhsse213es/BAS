Invoke-A36Test -Id 'k7' -Technique 'T1071.004' -Mode Telemetry -Needle 'bas_a36_' -Require @('sysmon:22') -Telemetry @('dns:3008') -Summary 'a DNS tunneling volume pattern: forty queries in a burst, each carrying a synthetic encoded label under a run-tagged .invalid parent (T1071.004, telemetry only)' -Attempt {
  $rng = New-Object Random
  $alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
  $sent = 0; $answered = 0
  for ($i = 1; $i -le 40; $i++) {
    $label = -join (1..(20 + $rng.Next(0, 20)) | ForEach-Object { $alphabet[$rng.Next(0, $alphabet.Length)] })
    $name = "$label.$($script:A36Tag).invalid"
    $ans = $null
    try { $ans = @(Resolve-DnsName -Name $name -Type TXT -DnsOnly -ErrorAction Stop) } catch {}
    $sent++
    if (@($ans | Where-Object { $_.Type -eq 'TXT' }).Count -gt 0) { $answered++ }
    Start-Sleep -Milliseconds 150
  }
  return @{ Ran = ($sent -eq 40); Note = "queries_sent=$sent txt_answers=$answered label_length=20-39 burst_interval_ms=150 parent=run-tagged.invalid. Validates host DNS telemetry for a volume pattern only; tunneling detection analytics and SIEM ingestion are not verified."; NotApplicable = '' }
}
