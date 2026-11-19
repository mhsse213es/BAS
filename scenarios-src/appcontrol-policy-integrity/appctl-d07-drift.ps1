Invoke-AppCtlTest -Family 'policy_lifecycle' -Collection 'Exe' -Needle 'PolicyDrift' -Technique 'T1562.001' -Direct -Attempt {
  $parts = @()
  try { $x = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop; $parts += "applocker:$x" } catch { $parts += 'applocker:unreadable' }
  $dir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
  if (Test-Path $dir) { foreach ($f in @(Get-ChildItem -Path $dir -Filter *.cip -ErrorAction SilentlyContinue | Sort-Object Name)) { $parts += "cip:$($f.Name):$((Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash)" } }
  $legacy = Join-Path $env:SystemRoot 'System32\CodeIntegrity\SiPolicy.p7b'
  if (Test-Path $legacy) { $parts += "sipolicy:$((Get-FileHash -Path $legacy -Algorithm SHA256).Hash)" }
  $sha = [Security.Cryptography.SHA256]::Create()
  $cur = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))) -replace '-', '').ToLower()
  $base = ([string]$env:BAS_APPCTL_BASELINE_SHA256).Trim().ToLower()
  $note = "current_policy_sha256=$cur components=$($parts.Count) baseline_supplied=$([bool]$base)"
  if ($parts.Count -le 1 -and $parts[0] -eq 'applocker:unreadable') { return @{ NotApplicable = 'no readable application control policy exists on this host'; Note = $note } }
  if (-not $base) { return @{ Verdict = @{ Outcome = 'inconclusive'; Reason = "no baseline was supplied (BAS_APPCTL_BASELINE_SHA256), so drift cannot be judged; record the current value $cur as the approved baseline" }; Note = $note } }
  if ($base -eq $cur) { return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'the effective application control policy matches the approved baseline; no drift' }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'allowed_unexpectedly'; Reason = 'the effective application control policy differs from the approved baseline; policy drift or an unreviewed update is present' }; Note = $note }
}
