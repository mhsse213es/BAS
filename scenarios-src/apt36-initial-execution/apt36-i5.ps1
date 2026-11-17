Invoke-A36Test -Id 'i5' -Technique 'T1047' -Telemetry @('sysmon:1', 'sec:4688', 'wmi:5857') -Summary 'WMI Win32_Process.Create runs a benign command, an alternate execution path to a direct process launch (T1047)' -Attempt {
  $mk = Join-Path $script:A36Work 'wmi-marker.txt'
  $cmd = 'cmd.exe /c echo ' + $script:A36Marker + '> "' + $mk + '"'
  $r = $null
  try { $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop } catch {}
  for ($i = 0; $i -lt 10 -and -not (Test-A36Marker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  $rv = if ($r) { [int]$r.ReturnValue } else { -1 }
  return @{ Ran = (Test-A36Marker $mk); Note = "wmi_return_value=$rv parent_expected=WmiPrvSE.exe"; NotApplicable = '' }
}
