Invoke-AppCtlTest -Family 'xsl_script_processing' -Collection 'Exe' -Needle 'wmic.exe' -Technique 'T1220' -Attempt {
  $w = Join-Path $env:SystemRoot 'System32\wbem\WMIC.exe'
  if (-not (Test-Path $w)) { return @{ Ran = $false; Exit = -1; Note = 'wmic_absent'; NotApplicable = 'WMIC.exe is not present on this host (removed from newer Windows builds), so XSL processing through it cannot be tested' } }
  $mk = Join-Path $script:AppCtlWork 'xsl-marker.txt'
  $xsl = Join-Path $script:AppCtlWork 'proxy.xsl'
  $mkj = $mk.Replace([string][char]92, '/')
  $body = "<?xml version=`"1.0`"?><stylesheet xmlns=`"http://www.w3.org/1999/XSL/Transform`" xmlns:ms=`"urn:schemas-microsoft-com:xslt`" xmlns:user=`"urn:bas`" version=`"1.0`"><output method=`"text`"/><ms:script implements-prefix=`"user`" language=`"JScript`"><![CDATA[var f=new ActiveXObject('Scripting.FileSystemObject').CreateTextFile('$mkj',true);f.Write('$($script:AppCtlMarker)');f.Close();]]></ms:script><template match=`"/`"><value-of select=`"user:x()`"/></template></stylesheet>"
  Set-Content -Path $xsl -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File $w -ArgLine "os get Caption /format:`"$xsl`"" -TimeoutSec 30
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
