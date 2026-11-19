# Cobalt Group BFSI - WMI Event Subscription Persistence (pers-02)
$tag = $script:CgTag + '-wmi'
$undo_data = @{ scenario = 'pers-02'; tag = $tag }
try { New-CgUndoRecord 'pers-02' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'pers-02' }

try {
  $filterArgs = @{ Name = "$tag-filter"; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'" }
  Set-WmiInstance -Namespace 'root\subscription' -Class '__EventFilter' -Arguments $filterArgs -ErrorAction Stop | Out-Null
  Set-WmiInstance -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Arguments @{ Name = "$tag-consumer"; CommandLineTemplate = 'powershell.exe -NoProfile -Command exit' } -ErrorAction Stop | Out-Null
  $filter = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -Filter "Name='$tag-filter'" -ErrorAction Stop
  $consumer = Get-WmiObject -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Filter "Name='$tag-consumer'" -ErrorAction Stop
  Set-WmiInstance -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -Arguments @{ Filter = $filter.__RELPATH; Consumer = $consumer.__RELPATH } -ErrorAction Stop | Out-Null
} catch {
  Complete-CgStep @{ Outcome = 'error'; Reason = "Could not create WMI subscription: $($_.Exception.Message)" } 'pers-02'
}

$state = Test-CgWmiSubscriptionExists -Tag $tag
if ($state.Filter -and $state.Consumer -and $state.Binding) {
  $res = @{ Outcome = 'pass'; Reason = 'WMI event subscription filter, consumer, and binding were all created and confirmed present' }
} else {
  $res = @{ Outcome = 'fail'; Reason = "WMI subscription incomplete (filter=$($state.Filter) consumer=$($state.Consumer) binding=$($state.Binding))" }
}
Complete-CgStep $res 'pers-02'
