$exeName = "bas_$($script:AppCtlTid.Substring(0,8)).exe"
Invoke-AppCtlTest -Family 'unsigned_executable' -Collection 'Exe' -Needle $exeName -Technique 'T1204.002' -Attempt {
  Invoke-AppCtlExeAt -Dir $script:AppCtlWork -Name $exeName
}
