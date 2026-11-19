Invoke-A29Test -Id 'p2' -Technique 'T1547.009' -Summary 'a Startup-folder shortcut is created then its target is modified (T1547.009)' -Telemetry @('sysmon:11') -Attempt {
  $dir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
  if (-not (Test-Path -LiteralPath $dir)) { return @{ Ran = $false; Note = 'startup_folder_missing'; NotApplicable = 'the per-user Startup folder does not exist on this host' } }
  $f = Join-Path $dir ($script:A29Tag + '.lnk')
  $created = $false; $modified = $false
  try {
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut($f)
    $lnk.TargetPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $lnk.Arguments = '/c echo ' + $script:A29Marker + ' original'
    $lnk.Save()
    $created = (Test-Path -LiteralPath $f)
    $lnk2 = $sh.CreateShortcut($f)
    $lnk2.Arguments = '/c echo ' + $script:A29Marker + ' modified'
    $lnk2.Save()
    $modified = ($sh.CreateShortcut($f).Arguments -like '*modified*')
  } catch {}
  Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
  $gone = -not (Test-Path -LiteralPath $f)
  return @{ Ran = ($created -and $modified); Note = "shortcut_created=$created target_arguments_modified=$modified shortcut_removed=$gone executed_at_logon=false"; CleanupOk = $gone; NotApplicable = '' }
}
