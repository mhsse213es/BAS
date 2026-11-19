$msiName = "bas_$($script:AppCtlTid.Substring(0,8)).msi"
Invoke-AppCtlTest -Family 'msi_installation' -Collection 'Msi' -Needle $msiName -Technique 'T1218.007' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'msi-install-marker.txt'
  $msi = Join-Path $script:AppCtlWork $msiName
  if (-not (New-AppCtlMsi -Path $msi -MarkerPath $mk)) { return @{ Ran = $false; Exit = -1; Note = 'msi_build_failed'; NotApplicable = 'the test package could not be built on this host' } }
  $child = Join-Path $script:AppCtlWork 'install.ps1'
  $res = Join-Path $script:AppCtlWork 'install-result.txt'
  Set-Content -Path $child -Value ('try { $wi = New-Object -ComObject WindowsInstaller.Installer; $wi.UILevel = 2; $wi.InstallProduct(''' + $msi + ''', ''ACTION=INSTALL''); Set-Content -Path ''' + $res + ''' -Value ok } catch { Set-Content -Path ''' + $res + ''' -Value (''err '' + ($_.Exception.HResult -band 0xFFFF)) }') -Encoding ASCII
  # The install runs in a child process so a hung installer can be killed at the timeout.
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgLine "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$child`"" -TimeoutSec 60
  $code = if ($p.TimedOut) { -1 } else { $p.Exit }
  $err = ((Get-Content -Path $res -ErrorAction SilentlyContinue) -join ' ') -replace '[^A-Za-z0-9 ]', ''
  for ($i = 0; $i -lt 8 -and -not (Test-AppCtlMarker $mk); $i++) { Start-Sleep -Milliseconds 300 }
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $code; Note = "api=WindowsInstaller.InstallProduct (no msiexec.exe) installer_result=$err timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
