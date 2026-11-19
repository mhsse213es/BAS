Invoke-AppCtlTest -Family 'policy_downgrade' -Collection 'Exe' -Needle 'EnforcementMode' -Technique 'T1562.001' -Direct -Attempt {
  $st = Get-AppCtlState
  $alModes = @('Exe', 'Script', 'Dll', 'Msi' | ForEach-Object { "$_=$($st.Al[$_])" }) -join ' '
  $cfg = @('Exe', 'Script', 'Dll', 'Msi' | Where-Object { $st.Al[$_] -ne 'NotConfigured' })
  $audit = @($cfg | Where-Object { $st.Al[$_] -eq 'AuditOnly' })
  $wd = $st.Wd
  $note = "applocker_readable=$($st.AlReadable) $alModes wdac_umci=$wd wdac_kernel=$($st.WdKernel)"
  if (-not $st.AlReadable -and -not $st.WdReadable) { return @{ NotApplicable = 'neither AppLocker nor WDAC policy state is readable on this host'; Note = $note } }
  if ($cfg.Count -eq 0 -and $wd -eq 'NotConfigured') { return @{ NotApplicable = 'no application control policy is configured, so there is nothing to downgrade'; Note = $note } }
  if ($audit.Count -gt 0 -or $wd -eq 'AuditOnly') { return @{ Verdict = @{ Outcome = 'audited_only'; Reason = "policy is in audit mode ($(@($audit | ForEach-Object { "applocker $_" }) + $(if ($wd -eq 'AuditOnly') { 'wdac user mode' }) -join ', ')); audit mode records but does not prevent" }; Note = $note } }
  $gaps = @('Exe', 'Script', 'Dll', 'Msi' | Where-Object { $cfg.Count -gt 0 -and $st.Al[$_] -eq 'NotConfigured' })
  if ($gaps.Count -gt 0) { return @{ Verdict = @{ Outcome = 'not_enforced'; Reason = "AppLocker enforces $($cfg -join ', ') but has no rules for $($gaps -join ', '), so those paths are not governed" }; Note = $note } }
  return @{ Verdict = @{ Outcome = 'blocked_as_expected'; Reason = 'every configured collection and the WDAC user-mode policy is in enforced mode; no audit-mode downgrade found' }; Note = $note }
}
