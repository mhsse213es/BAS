Invoke-A29Test -Id 'c3' -Technique 'T1555.003' -Summary 'a synthetic browser credential store is copied the way stealers do to avoid file locks (T1555.003)' -Telemetry @('sysmon:11') -Attempt {
  $profileDir = Join-Path $script:A29Work 'User Data\Default'
  New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
  $src = Join-Path $profileDir 'Login Data'
  $bytes = [Text.Encoding]::ASCII.GetBytes('SQLite format 3') + [byte]0 + [Text.Encoding]::ASCII.GetBytes($script:A29Marker + ' synthetic logins table, no real credentials')
  [IO.File]::WriteAllBytes($src, $bytes)
  Set-Content -LiteralPath (Join-Path $script:A29Work 'User Data\Local State') -Value ('{"os_crypt":{"synthetic":"' + $script:A29Marker + '"}}') -Encoding ASCII
  $dst = Join-Path $script:A29Work 'staged_login_copy.db'
  $copied = $false
  try { Copy-Item -LiteralPath $src -Destination $dst -ErrorAction Stop; $copied = ((Get-FileHash -LiteralPath $src).Hash -eq (Get-FileHash -LiteralPath $dst).Hash) } catch {}
  $hdr = ''
  if ($copied) { $b = [IO.File]::ReadAllBytes($dst); $hdr = [Text.Encoding]::ASCII.GetString($b, 0, 15) }
  return @{ Ran = ($copied -and $hdr -eq 'SQLite format 3'); Note = "store_copied=$copied header_read=$hdr real_browser_profile_touched=false decryption_attempted=false"; NotApplicable = '' }
}
