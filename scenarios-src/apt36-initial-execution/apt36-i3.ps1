Invoke-A36Test -Id 'i3' -Technique 'T1059.005' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'a VBScript file is run by wscript.exe, the document-to-script step (T1059.005)' -Attempt {
  $mk = Join-Path $script:A36Work 'vbs-marker.txt'
  $vbs = Join-Path $script:A36Work 'update.vbs'
  $q = [string][char]34
  Set-Content -LiteralPath $vbs -Encoding ASCII -Value @(('Set f = CreateObject(' + $q + 'Scripting.FileSystemObject' + $q + ').CreateTextFile(' + $q + $mk + $q + ', True)'), ('f.Write ' + $q + $script:A36Marker + $q), 'f.Close')
  $p = Invoke-A36Proc -File (Join-Path $env:SystemRoot 'System32\wscript.exe') -ArgLine ('//B //Nologo "' + $vbs + '"') -TimeoutSec 20 -NoShell
  for ($i = 0; $i -lt 10 -and -not (Test-A36Marker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  return @{ Ran = (Test-A36Marker $mk); Note = "wscript_started=$($p.Started) timed_out=$($p.TimedOut) host=wscript.exe silent=true"; NotApplicable = '' }
}
