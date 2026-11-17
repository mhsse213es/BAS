Invoke-A36Test -Id 'pe4' -Technique 'T1546.015' -Telemetry @('sysmon:13', 'sec:4657') -Summary 'a per-user COM InprocServer32 override is written for a run-tagged CLSID, read back and removed; no existing CLSID is touched (T1546.015)' -Attempt {
  $clsid = '{' + [guid]::NewGuid().ToString() + '}'
  $key = 'HKCU:\SOFTWARE\Classes\CLSID\' + $clsid + '\InprocServer32'
  $dll = Join-Path $script:A36Work 'bas-com-test.dll'
  Set-Content -LiteralPath $dll -Value ($script:A36Marker + ' not a real DLL') -Encoding ASCII
  $wrote = $false
  try { New-Item -Path $key -Force -ErrorAction Stop | Out-Null; Set-ItemProperty -Path $key -Name '(default)' -Value $dll -ErrorAction Stop; $wrote = ((Get-ItemProperty -Path $key -Name '(default)' -ErrorAction Stop).'(default)' -eq $dll) } catch {}
  Remove-Item -Path ('HKCU:\SOFTWARE\Classes\CLSID\' + $clsid) -Recurse -Force -ErrorAction SilentlyContinue
  $gone = -not (Test-Path -LiteralPath $key)
  return @{ Ran = $wrote; Note = "clsid=$clsid override_written_and_read_back=$wrote override_removed=$gone existing_clsid_touched=false"; CleanupOk = $gone; NotApplicable = '' }
}
