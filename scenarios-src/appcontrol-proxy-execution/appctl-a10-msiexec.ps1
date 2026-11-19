$msiName = "bas_$($script:AppCtlTid.Substring(0,8)).msi"
Invoke-AppCtlTest -Family 'msiexec_proxy' -Collection 'Msi' -Needle $msiName -Technique 'T1218.007' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'msiexec-marker.txt'
  $msi = Join-Path $script:AppCtlWork $msiName
  if (-not (New-AppCtlMsi -Path $msi -MarkerPath $mk)) { return @{ Ran = $false; Exit = -1; Note = 'msi_build_failed'; NotApplicable = 'the test package could not be built on this host' } }
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgLine "/i `"$msi`" /qn /norestart"
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
