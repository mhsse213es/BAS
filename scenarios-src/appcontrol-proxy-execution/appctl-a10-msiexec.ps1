$msiName = "bas_$($script:AppCtlTid.Substring(0,8)).msi"
Invoke-AppCtlTest -Family 'msiexec_proxy' -Collection 'Msi' -Needle $msiName -Technique 'T1218.007' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'msiexec-marker.txt'
  $msi = Join-Path $script:AppCtlWork $msiName
  $wi = New-Object -ComObject WindowsInstaller.Installer
  $db = $wi.OpenDatabase($msi, 3)
  $sql = @(
    'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)',
    'CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`)',
    'CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)',
    ('INSERT INTO `Property` (`Property`, `Value`) VALUES (''BASCMD'', ''' + (Join-Path $env:SystemRoot 'System32\cmd.exe') + ''')'),
    ('INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductCode'', ''{' + [guid]::NewGuid().ToString().ToUpper() + '}'')'),
    'INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductName'', ''BAS SIM'')',
    'INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductVersion'', ''1.0.0'')',
    'INSERT INTO `Property` (`Property`, `Value`) VALUES (''ProductLanguage'', ''1033'')',
    'INSERT INTO `Property` (`Property`, `Value`) VALUES (''Manufacturer'', ''BAS SIM'')',
    ('INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES (''RunIt'', 50, ''BASCMD'', ''/c echo ' + $script:AppCtlMarker + '> "' + $mk + '"'')'),
    'INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES (''RunIt'', '''', 1)'
  )
  foreach ($q in $sql) { $v = $db.OpenView($q); $v.Execute(); $v.Close() }
  $si = $db.SummaryInformation(20)
  $si.Property(2) = 'BAS SIM'
  $si.Property(4) = 'BAS SIM'
  $si.Property(7) = 'Intel;1033'
  $si.Property(9) = ('{' + [guid]::NewGuid().ToString().ToUpper() + '}')
  $si.Property(14) = 200
  $si.Property(15) = 2
  $si.Persist()
  $db.Commit()
  foreach ($o in @($si, $v, $db, $wi)) { if ($o) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($o) } }
  $si = $null; $v = $null; $db = $null; $wi = $null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  if (-not (Test-Path $msi)) { return @{ Ran = $false; Exit = -1; Note = 'msi_build_failed'; NotApplicable = 'the test package could not be built on this host' } }
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgLine "/i `"$msi`" /qn /norestart"
  return @{ Ran = (Test-AppCtlMarker $mk); Exit = $p.Exit; Note = "timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
