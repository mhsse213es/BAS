$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
Invoke-AppCtlTest -Family 'exec_from_temp' -Collection 'Exe' -Needle $exeName -Technique 'T1204.002' -ExtraCleanup @((Join-Path $env:TEMP $exeName), (Join-Path $env:TEMP "$exeName.marker.txt")) -Attempt {
  Invoke-AppCtlExeAt -Dir $env:TEMP -Name $exeName
}
