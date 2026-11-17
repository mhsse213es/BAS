Invoke-A36Test -Id 's4' -Technique 'T1547.001' -Summary 'HKCU Run key written, read back and removed (T1547.001)' -Telemetry @('sysmon:13', 'sec:4657') -Attempt {
  $key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
  $name = $script:A36Tag
  $data = 'cmd.exe /c echo ' + $script:A36Marker
  $wrote = $false
  try { Set-ItemProperty -Path $key -Name $name -Value $data -ErrorAction Stop; $wrote = ((Get-ItemProperty -Path $key -Name $name -ErrorAction Stop).$name -eq $data) } catch {}
  Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
  $gone = ($null -eq (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue).$name)
  return @{ Ran = $wrote; Note = "value_written_and_read_back=$wrote value_removed=$gone"; CleanupOk = $gone; NotApplicable = '' }
}
