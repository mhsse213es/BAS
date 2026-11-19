Invoke-A36Test -Id 'd3' -Technique 'T1083' -Telemetry @('sysmon:11') -Summary 'a synthetic user profile is built and searched by extension, the discovery precondition to collection (T1083)' -Attempt {
  $prof = Join-Path $script:A36Work 'profile'
  $names = @('Documents\report.docx', 'Documents\budget.xlsx', 'Desktop\contract.pdf', 'Downloads\notes.txt')
  foreach ($n in $names) {
    $p = Join-Path $prof $n
    New-Item -ItemType Directory -Path (Split-Path $p) -Force | Out-Null
    Set-Content -LiteralPath $p -Value ($script:A36Marker + ' synthetic document ' + $n) -Encoding ASCII
  }
  $ext = @('.docx', '.xlsx', '.pdf', '.txt')
  $found = @(Get-ChildItem -LiteralPath $prof -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $ext -contains $_.Extension.ToLower() })
  return @{ Ran = ($found.Count -eq $names.Count); Note = "files_created=$($names.Count) matched_by_extension=$($found.Count) search_scope=synthetic_profile_only"; NotApplicable = '' }
}
