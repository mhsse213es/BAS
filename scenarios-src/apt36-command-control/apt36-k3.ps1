Invoke-A36Test -Id 'k3' -Technique 'T1021.002' -Needle 'bas_a36_' -Telemetry @('sec:5145', 'sec:5140', 'sysmon:11') -Summary 'a run-tagged folder is written through the loopback C$ administrative share, the lateral-movement validation step (T1021.002)' -Attempt {
  if ($env:BAS_CONFIRM_APT36_REMOTE_STAGING -cne 'true') { return @{ Ran = $false; Note = 'lab_gate_not_set'; NotApplicable = 'lab gate BAS_CONFIRM_APT36_REMOTE_STAGING is not set to true; this step writes a folder through the loopback administrative share and is skipped without it' } }
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return @{ Ran = $false; Note = 'not_admin'; NotApplicable = 'the administrative share needs an administrator identity' } }
  $unc = '\\localhost\C$\Users\Public\' + $script:A36Tag
  $made = $false; $copied = 0
  $src = Join-Path $script:A36Work 'collection'
  New-Item -ItemType Directory -Path $src -Force | Out-Null
  1..3 | ForEach-Object { Set-Content -LiteralPath (Join-Path $src "doc$_.txt") -Value ($script:A36Marker + " synthetic $_") -Encoding ASCII }
  try { New-Item -ItemType Directory -Path $unc -Force -ErrorAction Stop | Out-Null; $made = $true; Get-ChildItem -LiteralPath $src -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $unc -ErrorAction Stop; $copied++ } } catch {}
  $verified = ($made -and @(Get-ChildItem -LiteralPath $unc -File -ErrorAction SilentlyContinue).Count -eq 3)
  Remove-Item -LiteralPath $unc -Recurse -Force -ErrorAction SilentlyContinue
  $gone = -not (Test-Path -LiteralPath $unc)
  return @{ Ran = $verified; Note = "share=C$ via loopback host=localhost staging_folder_created=$made files_copied=$copied verified_on_share=$verified staging_folder_removed=$gone"; CleanupOk = $gone; NotApplicable = '' }
}
