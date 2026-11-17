Invoke-A29Test -Id 'c2' -Technique 'T1552.004' -Summary 'a synthetic private key is planted and a recursive key-file search finds it (T1552.004)' -Telemetry @('sysmon:11') -Attempt {
  $root = Join-Path $script:A29Work 'profile'
  $ssh = Join-Path $root '.ssh'
  New-Item -ItemType Directory -Path $ssh -Force | Out-Null
  Set-Content -LiteralPath (Join-Path $ssh 'id_rsa') -Value ('-----BEGIN SYNTHETIC KEY-----' + [Environment]::NewLine + $script:A29Marker + ' not a real key' + [Environment]::NewLine + '-----END SYNTHETIC KEY-----') -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $root 'cert.pfx') -Value ($script:A29Marker + ' synthetic container') -Encoding ASCII
  Set-Content -LiteralPath (Join-Path $root 'notes.txt') -Value 'not a key' -Encoding ASCII
  $patterns = @('id_rsa*', 'id_ed25519*', '*.pfx', '*.pem', '*.key', '*.ppk')
  $hits = @()
  foreach ($pt in $patterns) { $hits += @(Get-ChildItem -LiteralPath $root -Recurse -Force -Filter $pt -File -ErrorAction SilentlyContinue) }
  $marked = @($hits | Where-Object { ([string](Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue)) -like "*$($script:A29Marker)*" }).Count
  return @{ Ran = ($marked -ge 2); Note = "key_file_patterns=$($patterns.Count) files_found=$($hits.Count) synthetic_files_identified=$marked real_keys_read=false search_scope=synthetic_profile_only"; NotApplicable = '' }
}
