Invoke-A36Test -Id 'pe5' -Technique 'T1562.001' -Mode Direct -Telemetry @('sysmon:13') -Summary 'adding a Defender path exclusion is attempted and independently verified against live Defender state, not just the command exit code; gated because it touches live AV configuration (T1562.001)' -Attempt {
  if ($env:BAS_CONFIRM_APT36_DEFENDER_EXCLUSION -cne 'true') { return @{ Ran = $false; Note = 'lab_gate_not_set'; Verdict = @{ Outcome = 'not_applicable'; Reason = 'lab gate BAS_CONFIRM_APT36_DEFENDER_EXCLUSION is not set to true; this step adds and removes a live Defender exclusion and is skipped without it' }; NotApplicable = '' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Note = 'not_admin'; Verdict = @{ Outcome = 'not_applicable'; Reason = 'modifying Defender preferences needs an administrator identity' }; NotApplicable = '' } }
  $path = Join-Path $script:A36Work 'excl-probe'
  New-Item -ItemType Directory -Path $path -Force | Out-Null
  $before = @()
  try { $before = @((Get-MpPreference -ErrorAction Stop).ExclusionPath) } catch { return @{ Ran = $false; Note = 'defender_preference_unreadable'; Verdict = @{ Outcome = 'not_applicable'; Reason = 'Get-MpPreference is not available on this host' }; NotApplicable = '' } }
  if ($before -contains $path) { return @{ Ran = $false; Note = 'path_already_excluded'; Verdict = @{ Outcome = 'inconclusive'; Reason = 'the run-tagged path was already in the exclusion list before this step ran, which should not happen' }; NotApplicable = '' } }
  $invoked = $false; $err = ''
  try { Add-MpPreference -ExclusionPath $path -ErrorAction Stop; $invoked = $true } catch { $err = ([string]$_.Exception.Message).Substring(0, [Math]::Min(80, ([string]$_.Exception.Message).Length)) }
  Start-Sleep -Milliseconds 500
  $after = @()
  try { $after = @((Get-MpPreference -ErrorAction Stop).ExclusionPath) } catch {}
  $actuallyExcluded = ($after -contains $path)
  try { if ($actuallyExcluded) { Remove-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue } } catch {}
  Start-Sleep -Milliseconds 500
  $after2 = @()
  try { $after2 = @((Get-MpPreference -ErrorAction Stop).ExclusionPath) } catch {}
  $removed = -not ($after2 -contains $path)
  $outcome = if ($actuallyExcluded) { 'allowed_unexpectedly' } elseif ($invoked) { 'prevented' } else { 'inconclusive' }
  $reason = if ($actuallyExcluded) { 'the command succeeded and live Defender state confirms the exclusion took effect' } elseif ($invoked) { 'the command returned success but live Defender state shows no exclusion was added (command success is not proof of effect)' } else { "the command failed to modify Defender preferences: $err" }
  return @{ Ran = $invoked; Note = "command_invoked=$invoked command_error=$err exclusion_confirmed_live=$actuallyExcluded exclusion_removed=$removed verification_method=Get-MpPreference_not_exit_code only_the_run_tagged_temp_path_was_ever_touched=true"; Verdict = @{ Outcome = $outcome; Reason = $reason }; CleanupOk = $removed; NotApplicable = '' }
}
