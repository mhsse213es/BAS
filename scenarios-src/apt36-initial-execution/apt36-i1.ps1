Invoke-A36Test -Id 'i1' -Technique 'T1204.002' -Telemetry @('sysmon:1', 'sysmon:11', 'sec:4688') -Summary 'a shortcut file (.lnk) is created and opened the way a user would, launching cmd.exe (T1204.002)' -Attempt {
  $mk = Join-Path $script:A36Work 'lnk-marker.txt'
  $lnk = Join-Path $script:A36Work 'Invoice_Q3.pdf.lnk'
  $sh = New-Object -ComObject WScript.Shell
  $s = $sh.CreateShortcut($lnk)
  $s.TargetPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
  $s.Arguments = '/c echo ' + $script:A36Marker + ' > "' + $mk + '"'
  $s.WindowStyle = 7
  $s.IconLocation = (Join-Path $env:SystemRoot 'System32\shell32.dll') + ',1'
  $s.Save()
  $built = Test-Path -LiteralPath $lnk
  $started = $false
  try { Start-Process -FilePath $lnk -WindowStyle Hidden -ErrorAction Stop; $started = $true } catch {}
  for ($i = 0; $i -lt 15 -and -not (Test-A36Marker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  return @{ Ran = (Test-A36Marker $mk); Note = "shortcut_built=$built opened=$started double_extension=true target=cmd.exe window_style=minimized"; NotApplicable = '' }
}
