# Undo: Encrypted channel over loopback TLS (removes the recorded certificate; tolerates it already gone)
$rec = Read-CgUndoRecord 'c2-02'
if ($rec -eq $null -or $rec -eq 'unreadable') { Write-Output 'SKIP: Undo record not found'; exit 0 }

Remove-CgLoopbackTlsCertificate -Thumbprint $rec.thumbprint
if (Test-CgLoopbackTlsCertificate -Thumbprint $rec.thumbprint) {
  Write-Output 'FAIL: Loopback TLS certificate still present after undo'
  exit 0
}
Remove-CgUndoRecord 'c2-02'
Write-Output 'PASS: Cleanup complete'
exit 0
