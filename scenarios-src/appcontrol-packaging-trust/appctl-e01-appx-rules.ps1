Invoke-AppCtlTest -Family 'packaged_app_rules' -Collection 'Exe' -Needle 'Appx' -Technique 'T1553' -Direct -Attempt {
  $st = Get-AppCtlState
  if (-not $st.AlReadable) { return @{ NotApplicable = 'the effective AppLocker policy is not readable on this host'; Note = 'policy_unreadable' } }
  $enforcing = @('Exe', 'Script', 'Dll', 'Msi' | Where-Object { $st.Al[$_] -eq 'Enabled' })
  $mode = 'NotConfigured'
  try { $c = @((Get-AppLockerPolicy -Effective -ErrorAction Stop).RuleCollections | Where-Object { [string]$_.RuleCollectionType -eq 'Appx' }); if ($c.Count -gt 0) { $mode = [string]$c[0].EnforcementMode } } catch {}
  $pkgs = 0; try { $pkgs = @(Get-AppxPackage -ErrorAction Stop).Count } catch {}
  $note = "appx_collection=$mode other_collections_enforced=$($enforcing -join ',') installed_packages=$pkgs. Posture only: no package is installed or launched."
  if ($enforcing.Count -eq 0) { return @{ NotApplicable = 'no AppLocker collection is enforced, so packaged-app rules have nothing to extend'; Note = $note } }
  if ($mode -eq 'Enabled') { return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'packaged-app rules are enforced alongside the other collections' }; Note = $note } }
  if ($mode -eq 'AuditOnly') { return @{ Verdict = @{ Outcome = 'audited_only'; Reason = 'packaged-app rules are in audit mode; audit records but does not prevent' }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'not_enforced'; Reason = "AppLocker enforces $($enforcing -join ', ') but has no enforced packaged-app rules, so packaged apps are not governed" }; Note = $note }
}
