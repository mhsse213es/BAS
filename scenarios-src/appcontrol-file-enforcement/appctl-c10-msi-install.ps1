$msiName = "bas_$($script:AppCtlTid.Substring(0,8)).msi"
Invoke-AppCtlTest -Family 'msi_installation' -Collection 'Msi' -Needle $msiName -Technique 'T1218.007' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'msi-install-marker.txt'
  $msi = Join-Path $script:AppCtlWork $msiName
  if (-not (New-AppCtlMsi -Path $msi -MarkerPath $mk)) { return @{ Ran = $false; Exit = -1; Note = 'msi_build_failed'; NotApplicable = 'the test package could not be built on this host' } }
  $code = -1; $err = ''
  try { $wi = New-Object -ComObject WindowsInstaller.Installer; $wi.UILevel = 2; $wi.InstallProduct($msi, 'ACTION=INSTALL'); $code = 0 } catch { $code = [int]($_.Exception.HResult -band 0xFFFF); $err = ([string]$_.Exception.Message -replace '[^A-Za-z0-9 :._-]', ''); if ($err.Length -gt 50) { $err = $err.Substring(0, 50) } }
  for ($i = 0; $i -lt 8 -and -not (Test-AppCtlMarker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $code; Note = "api=WindowsInstaller.InstallProduct (no msiexec.exe) error=$err"; NotApplicable = '' }
}
