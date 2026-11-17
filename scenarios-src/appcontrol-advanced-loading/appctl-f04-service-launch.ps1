$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
Invoke-AppCtlTest -Family 'service_launch' -Collection 'Exe' -Needle $exeName -Technique 'T1543.003' -Attempt {
  if ($env:BAS_CONFIRM_APPCONTROL_SERVICE_CREATE -cne 'true') { return @{ Ran = $false; Exit = -1; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APPCONTROL_SERVICE_CREATE is not set to true; this step creates and removes a temporary service and is skipped without it' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Exit = -1; Note = 'not_admin'; NotApplicable = 'creating a service needs an administrator identity' } }
  $exe = Join-Path $script:AppCtlWork $exeName
  if (-not (New-AppCtlExe -Path $exe)) { return @{ Ran = $false; Exit = -1; Note = 'compile_failed'; NotApplicable = (Get-AppCtlCompileReason) } }
  $mk = Join-Path $script:AppCtlWork 'service-marker.txt'
  $svc = "BASSIM$($script:AppCtlTid.Substring(0,8))"
  $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
  $cmd = '"' + $exe + '" "' + $mk + '"'
  $made = $false
  try {
    & $sc create $svc binPath= $cmd start= demand | Out-Null
    $made = ($LASTEXITCODE -eq 0)
    if ($made) { & $sc start $svc | Out-Null; for ($i = 0; $i -lt 25 -and -not (Test-AppCtlMarker $mk); $i++) { Start-Sleep -Milliseconds 400 } }
  } finally {
    & $sc stop $svc 2>&1 | Out-Null
    & $sc delete $svc 2>&1 | Out-Null
  }
  Start-Sleep -Milliseconds 500
  & $sc query $svc 2>&1 | Out-Null
  $gone = ($LASTEXITCODE -eq 1060)
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = 0; Note = "service_created=$made service_removed=$gone. The program is not a real service, so the service manager reports a start timeout; only the launch matters."; NotApplicable = '' }
}
