$rec = Read-CvUndoRecord 'cv-d29'
if ($null -eq $rec) { Write-Output 'UNDO CV-D29: no undo record, nothing to remove' }
elseif ($rec -eq 'unreadable') { Write-Output 'UNDO CV-D29: undo record is unreadable; left in place for manual review' }
else {
  $appUri = 'https://graph.microsoft.com/v1.0/applications/' + [string]$rec.app
  $base = @($rec.baseline | ForEach-Object { [string]$_ })
  $t = Get-CvAzureToken 'https://graph.microsoft.com/'
  if ($t.Token -eq '') { Write-Output 'UNDO CV-D29: no Graph token; undo record kept' }
  else {
    $cur = Invoke-CvHttp 'GET' ($appUri + '?$select=passwordCredentials') $t.Token
    if ($cur.Code -ne 200 -or $null -eq $cur.Body -or -not ($cur.Body.PSObject.Properties.Name -contains 'passwordCredentials')) { Write-Output 'UNDO CV-D29: could not read the test application credentials; undo record kept' }
    else {
      $extra = @($cur.Body.passwordCredentials | ForEach-Object { [string]$_.keyId } | Where-Object { $base -notcontains $_ })
      foreach ($k in $extra) { $null = Invoke-CvHttp 'POST' ($appUri + '/removePassword') $t.Token ('{"keyId":"' + $k + '"}') }
      $again = Invoke-CvHttp 'GET' ($appUri + '?$select=passwordCredentials') $t.Token
      if ($again.Code -eq 200 -and $null -ne $again.Body -and ($again.Body.PSObject.Properties.Name -contains 'passwordCredentials')) {
        $left = @($again.Body.passwordCredentials | ForEach-Object { [string]$_.keyId } | Where-Object { $base -notcontains $_ })
        if ($left.Count -eq 0) { Remove-CvUndoRecord 'cv-d29'; Write-Output ('UNDO CV-D29: removed ' + $extra.Count + ' secret(s) outside the pre-run baseline; none remains; undo record removed') }
        else { Write-Output ('UNDO CV-D29: ' + $left.Count + ' secret(s) outside the baseline remain; undo record kept') }
      } else { Write-Output 'UNDO CV-D29: could not re-read the test application; undo record kept' }
    }
  }
}
