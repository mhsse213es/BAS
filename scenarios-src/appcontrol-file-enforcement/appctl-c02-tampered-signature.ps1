$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
Invoke-AppCtlTest -Family 'tampered_signature' -Collection 'Exe' -Needle $exeName -Technique 'T1553.002' -Attempt {
  $src = Join-Path $env:SystemRoot 'System32\hostname.exe'
  $exe = Join-Path $script:AppCtlWork $exeName
  Copy-Item -Path $src -Destination $exe -Force
  $before = (Get-AuthenticodeSignature -FilePath $exe).Status
  $bytes = [IO.File]::ReadAllBytes($exe)
  # Flip one byte inside the resource (or, failing that, data) section so the Authenticode hash no
  # longer matches while the program headers and code stay intact and the copy still runs.
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  $nsec = [BitConverter]::ToUInt16($bytes, $pe + 6)
  $optSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
  $target = -1
  for ($k = 0; $k -lt $nsec; $k++) {
    $o = $pe + 24 + $optSize + 40 * $k
    $nm = [Text.Encoding]::ASCII.GetString($bytes, $o, 8).TrimEnd([char]0)
    $raw = [BitConverter]::ToInt32($bytes, $o + 20); $rsz = [BitConverter]::ToInt32($bytes, $o + 16)
    if (($nm -eq '.rsrc' -or ($nm -eq '.data' -and $target -lt 0)) -and $rsz -gt 64) { $target = $raw + [int]($rsz / 2); if ($nm -eq '.rsrc') { break } }
  }
  if ($target -lt 0) { return @{ Ran = $false; Exit = -1; Note = 'no_resource_section'; NotApplicable = 'the signed system binary has no section that can be altered without breaking its headers' } }
  $bytes[$target] = $bytes[$target] -bxor 0xFF
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
