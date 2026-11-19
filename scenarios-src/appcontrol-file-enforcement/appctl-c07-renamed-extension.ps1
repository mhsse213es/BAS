$tmpName = "bas_$($script:AppCtlTid.Substring(0,8)).tmp"
Invoke-AppCtlTest -Family 'renamed_extension' -Collection 'Exe' -Needle $tmpName -Technique 'T1036.008' -Attempt {
  $real = Join-Path $script:AppCtlWork 'bas_real.exe'
  if (-not (New-AppCtlExe -Path $real)) { return @{ Ran = $false; Exit = -1; Note = 'compile_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  $exe = Join-Path $script:AppCtlWork $tmpName
  Copy-Item -Path $real -Destination $exe -Force
  Remove-Item -Path $real -Force -ErrorAction SilentlyContinue
  $mk = Join-Path $script:AppCtlWork 'renamed-marker.txt'
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $exe; $psi.Arguments = "`"$mk`""; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $started = $false; $code = -1
  try { $p = [Diagnostics.Process]::Start($psi); $started = $true; if ($p.WaitForExit(15000)) { $code = $p.ExitCode } else { try { $p.Kill() } catch {} } } catch {}
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $code; Note = "started=$started file_extension=.tmp content=PE"; NotApplicable = '' }
}
