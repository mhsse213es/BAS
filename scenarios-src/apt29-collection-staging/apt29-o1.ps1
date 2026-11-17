Invoke-A29Test -Id 'o1' -Technique 'T1005' -Summary 'documents are located across a synthetic user profile and copied into a collection folder (T1005, T1083)' -Telemetry @('sysmon:11') -Attempt {
  $prof = Join-Path $script:A29Work 'profile'
  $names = @('Documents\budget.xlsx', 'Documents\plan.docx', 'Documents\notes.txt', 'Desktop\contract.pdf', 'Desktop\readme.md', 'Downloads\export.csv', 'Downloads\slides.pptx', 'Downloads\image.png')
  foreach ($n in $names) {
    $p = Join-Path $prof $n
    New-Item -ItemType Directory -Path (Split-Path $p) -Force | Out-Null
    Set-Content -LiteralPath $p -Value ($script:A29Marker + ' synthetic document ' + $n) -Encoding ASCII
  }
  $ext = @('.docx', '.xlsx', '.pdf', '.pptx', '.csv', '.txt')
  $found = @(Get-ChildItem -LiteralPath $prof -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $ext -contains $_.Extension.ToLower() })
  $collect = Join-Path $script:A29Work 'collection'
  New-Item -ItemType Directory -Path $collect -Force | Out-Null
  $copied = 0
  foreach ($f in $found) { try { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $collect ($f.Directory.Name + '_' + $f.Name)) -ErrorAction Stop; $copied++ } catch {} }
  $match = @(Get-ChildItem -LiteralPath $collect -File).Count
  return @{ Ran = ($found.Count -gt 0 -and $copied -eq $found.Count -and $match -eq $copied); Note = "files_in_profile=$($names.Count) matched_by_extension=$($found.Count) copied=$copied collection_count=$match search_scope=synthetic_profile_only"; NotApplicable = '' }
}
