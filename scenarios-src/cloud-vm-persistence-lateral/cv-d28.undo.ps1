$rec = Read-CvUndoRecord 'cv-d28'
if ($null -eq $rec) { Write-Output 'UNDO CV-D28: no undo record, nothing to remove' }
elseif ($rec -eq 'unreadable') { Write-Output 'UNDO CV-D28: undo record is unreadable; left in place for manual review' }
else {
  $user = [string]$rec.user
  $base = @($rec.baseline | ForEach-Object { [string]$_ })
  $lst = Invoke-CvAws @('iam', 'list-access-keys', '--user-name', $user)
  $lj = Get-CvJson $lst.Text
  if ($lst.Code -ne 0 -or $null -eq $lj -or -not ($lj.PSObject.Properties.Name -contains 'AccessKeyMetadata')) { Write-Output 'UNDO CV-D28: could not list the test user keys; undo record kept' }
  else {
    $extra = @($lj.AccessKeyMetadata | ForEach-Object { [string]$_.AccessKeyId } | Where-Object { $base -notcontains $_ })
    foreach ($k in $extra) { $null = Invoke-CvAws @('iam', 'delete-access-key', '--user-name', $user, '--access-key-id', $k) }
    $again = Invoke-CvAws @('iam', 'list-access-keys', '--user-name', $user)
    $aj = Get-CvJson $again.Text
    if ($again.Code -eq 0 -and $null -ne $aj -and ($aj.PSObject.Properties.Name -contains 'AccessKeyMetadata')) {
      $left = @($aj.AccessKeyMetadata | ForEach-Object { [string]$_.AccessKeyId } | Where-Object { $base -notcontains $_ })
      if ($left.Count -eq 0) { Remove-CvUndoRecord 'cv-d28'; Write-Output ('UNDO CV-D28: removed ' + $extra.Count + ' key(s) outside the pre-run baseline; none remains; undo record removed') }
      else { Write-Output ('UNDO CV-D28: ' + $left.Count + ' key(s) outside the baseline remain; undo record kept') }
    } else { Write-Output 'UNDO CV-D28: could not re-list the test user keys; undo record kept' }
  }
}
