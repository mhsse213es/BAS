$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
Invoke-AppCtlTest -Family 'tampered_signature' -Collection 'Exe' -Needle $exeName -Technique 'T1553.002' -Attempt {
  $src = Join-Path $env:SystemRoot 'System32\hostname.exe'
  $exe = Join-Path $script:AppCtlWork $exeName
  Copy-Item -Path $src -Destination $exe -Force
  $before = (Get-AuthenticodeSignature -FilePath $exe).Status
  $bytes = [IO.File]::ReadAllBytes($exe)
  $i = [Array]::IndexOf($bytes, [byte]0x4D, 0x300)
  $bytes[0x200] = $bytes[0x200] -bxor 0xFF
  [IO.File]::WriteAllBytes($exe, $bytes)
  $after = (Get-AuthenticodeSignature -FilePath $exe).Status
  if ($before -ne 'Valid' -or $after -eq 'Valid') { return @{ Ran = $false; Exit = -1; Note = "signature_before=$before signature_after=$after"; NotApplicable = 'the signed system binary could not be tampered into an invalid signature on this host' } }
  $out = Join-Path $script:AppCtlWork 'tamper-out.txt'
  $p = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -ErrorAction SilentlyContinue
  $done = $p -and $p.WaitForExit(15000)
  if ($p -and -not $done) { try { $p.Kill() } catch {} }
  $txt = (Get-Content $out -ErrorAction SilentlyContinue) -join ''
  return @{ Ran = [bool]($done -and $txt.Length -gt 0); Exit = $(if ($done -and $null -ne $p.ExitCode) { $p.ExitCode } else { -1 }); Note = "signature_before=$before signature_after=$after"; NotApplicable = '' }
}
