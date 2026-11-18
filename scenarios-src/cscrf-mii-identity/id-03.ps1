# CSCRF-ID-03: logon events are recorded in the Security log (read only)
try {
  $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 500 -ErrorAction Stop
  $n = @($events).Count
} catch {
  if ($_.Exception.Message -match 'No events') { $n = 0 } else { Complete-CgStep @{ Outcome = 'error'; Reason = 'Security log could not be read (privilege or audit configuration) [CSCRF-ID-03]' } 'id-03' }
}
if ($n -gt 0) { Complete-CgStep @{ Outcome = 'pass'; Reason = "$n logon event(s) (EID 4624) recorded in the last 24h [CSCRF-ID-03]" } 'id-03' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'no logon event (EID 4624) recorded in the last 24h; logon auditing may be off or the host was idle [CSCRF-ID-03]' } 'id-03'
