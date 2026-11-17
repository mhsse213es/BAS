Invoke-A29Test -Id 'p3' -Technique 'T1546.003' -Summary 'a WMI permanent event subscription is created, read back and removed (T1546.003)' -Telemetry @('sysmon:19', 'sysmon:20', 'sysmon:21', 'wmi:5861') -Attempt {
  if ($env:BAS_CONFIRM_APT29_WMI_SUBSCRIPTION -cne 'true') { return @{ Ran = $false; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APT29_WMI_SUBSCRIPTION is not set to true; this step creates and removes a WMI permanent event subscription and is skipped without it' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Note = 'not_admin'; NotApplicable = 'a WMI permanent subscription needs an administrator identity' } }
  $ns = 'root\subscription'
  $n = $script:A29Tag
  $filter = $null; $consumer = $null; $bind = $null; $created = $false
  try {
    $filter = New-CimInstance -Namespace $ns -ClassName __EventFilter -Property @{ Name = $n; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Year = 1999" } -ErrorAction Stop
    $consumer = New-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -Property @{ Name = $n; CommandLineTemplate = ('cmd.exe /c echo ' + $script:A29Marker) } -ErrorAction Stop
    $bind = New-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -Property @{ Filter = [Ref]$filter; Consumer = [Ref]$consumer } -ErrorAction Stop
    $created = $true
  } catch {}
  $readBack = ($created -and [bool](Get-CimInstance -Namespace $ns -ClassName __EventFilter -Filter "Name='$n'" -ErrorAction SilentlyContinue))
  if ($bind) { Remove-CimInstance -InputObject $bind -ErrorAction SilentlyContinue }
  if ($consumer) { Remove-CimInstance -InputObject $consumer -ErrorAction SilentlyContinue }
  if ($filter) { Remove-CimInstance -InputObject $filter -ErrorAction SilentlyContinue }
  $left = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -Filter "Name='$n'" -ErrorAction SilentlyContinue).Count + @(Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -Filter "Name='$n'" -ErrorAction SilentlyContinue).Count
  return @{ Ran = $created; Note = "filter_consumer_binding_created=$created read_back=$readBack trigger=never_fires_year_1999 objects_remaining=$left"; CleanupOk = ($left -eq 0); NotApplicable = '' }
}
