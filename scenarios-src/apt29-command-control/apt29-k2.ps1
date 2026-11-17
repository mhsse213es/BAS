Invoke-A29Test -Id 'k2' -Technique 'T1568' -Mode Telemetry -Require @('sysmon:22') -Telemetry @('dns:3008') -Summary 'a burst of generated non-resolving names, the shape of domain generation (T1568)' -Attempt {
  $seed = [int](($script:A29Run.GetHashCode() -band 0x7fffffff) % 100000)
  $rng = New-Object Random($seed)
  $alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
  $sent = 0; $resolved = 0; $failed = 0
  for ($i = 1; $i -le 12; $i++) {
    $len = 14 + $rng.Next(0, 8)
    $label = -join (1..$len | ForEach-Object { $alphabet[$rng.Next(0, $alphabet.Length)] })
    $name = "$($script:A29Tag)-$label.invalid"
    $ans = $null
    try { $ans = @(Resolve-DnsName -Name $name -DnsOnly -ErrorAction Stop) } catch { $failed++ }
    $sent++
    if (@($ans | Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' }).Count -gt 0) { $resolved++ }
  }
  return @{ Ran = ($sent -eq 12); Note = "generated_names=$sent label_length=14-21 charset=base32 queries_failed=$failed names_resolved=$resolved seed_from_run_id=true. Validates host DNS telemetry for an NXDOMAIN burst; DGA classification is not verified."; NotApplicable = '' }
}
