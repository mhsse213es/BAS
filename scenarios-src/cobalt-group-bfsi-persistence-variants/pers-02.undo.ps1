# Undo: WMI Event Subscription Persistence (reverse creation order: binding, consumer, filter)
$rec = Read-CgUndoRecord 'pers-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

$tag = $rec.tag
Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -ErrorAction SilentlyContinue | Where-Object { $_.Filter -like "*$tag-filter*" } | Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -Filter "Name='$tag-consumer'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -Filter "Name='$tag-filter'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue

$state = Test-CgWmiSubscriptionExists -Tag $tag
Remove-CgUndoRecord 'pers-02'
if ($state.Filter -or $state.Consumer -or $state.Binding) {
  Write-Output "FAIL: WMI subscription objects still present after undo (filter=$($state.Filter) consumer=$($state.Consumer) binding=$($state.Binding))"
  exit 0
}
Write-Output 'PASS: Cleanup complete'
exit 0
