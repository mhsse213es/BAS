$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
$dir = Join-Path $env:APPDATA "bas-appctl-$($script:AppCtlTid)"
Invoke-AppCtlTest -Family 'exec_from_appdata' -Collection 'Exe' -Needle $exeName -Technique 'T1204.002' -ExtraCleanup @($dir) -Attempt {
  Invoke-AppCtlExeAt -Dir $dir -Name $exeName
}
