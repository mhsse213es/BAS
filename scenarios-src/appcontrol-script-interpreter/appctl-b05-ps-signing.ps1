$sn = "bas_$($script:AppCtlTid.Substring(0,8)).ps1"
Invoke-AppCtlTest -Family 'powershell_script_signing' -Collection 'Script' -Needle $sn -Technique 'T1059.001' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'ps1-marker.txt'
  $ps1 = Join-Path $script:AppCtlWork $sn
  Set-Content -Path $ps1 -Value "Set-Content -Path '$mk' -Value '$($script:AppCtlMarker)'" -Encoding ASCII
  $sig = (Get-AuthenticodeSignature -FilePath $ps1).Status
  $pol = @(Get-ExecutionPolicy -List | ForEach-Object { "$($_.Scope)=$($_.ExecutionPolicy)" }) -join '/'
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgLine "-NoProfile -NonInteractive -File `"$ps1`""
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "script_signature=$sig execution_policy=$pol timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
