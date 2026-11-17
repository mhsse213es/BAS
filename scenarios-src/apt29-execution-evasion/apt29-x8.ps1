Invoke-A29Test -Id 'x8' -Technique 'T1553.005' -Summary 'a Mark-of-the-Web stream is added to a file and then removed (T1553.005)' -Telemetry @('sysmon:15') -Attempt {
  $f = Join-Path $script:A29Work 'downloaded.txt'
  Set-Content -LiteralPath $f -Value $script:A29Marker
  $added = $false; $stripped = $false
  try { Set-Content -LiteralPath $f -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3" -ErrorAction Stop; $added = [bool](Get-Item -LiteralPath $f -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue) } catch {}
  try { Unblock-File -LiteralPath $f -ErrorAction Stop; $stripped = -not [bool](Get-Item -LiteralPath $f -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue) } catch {}
  return @{ Ran = ($added -and $stripped); Note = "zone_identifier_added=$added zone_identifier_removed=$stripped method=Unblock-File (stripping, not an ISO or container bypass)"; NotApplicable = '' }
}
