$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
$dir = Join-Path (Join-Path $env:USERPROFILE 'Downloads') "bas-appctl-$($script:AppCtlTid)"
Invoke-AppCtlTest -Family 'exec_from_downloads' -Collection 'Exe' -Needle $exeName -Technique 'T1204.002' -ExtraCleanup @($dir) -Attempt {
  Invoke-AppCtlExeAt -Dir $dir -Name $exeName -MarkOfTheWeb
}
