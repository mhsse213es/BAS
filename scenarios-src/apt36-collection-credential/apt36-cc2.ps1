Invoke-A36Test -Id 'cc2' -Technique 'T1555.004' -Telemetry @('sysmon:1', 'sec:4688') -Summary 'Windows Credential Manager is enumerated with vaultcmd/cmdkey; no credential is unlocked or read (T1555.004)' -Attempt {
  $out = Join-Path $script:A36Work 'cred.txt'
  $ck = Join-Path $env:SystemRoot 'System32\cmdkey.exe'
  $p = Invoke-A36Proc -File $ck -ArgLine ('/list') -TimeoutSec 15 -NoShell
  $captured = $false
  try {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $ck; $psi.Arguments = '/list'; $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
    $proc = [Diagnostics.Process]::Start($psi)
    $text = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit(10000)
    Set-Content -LiteralPath $out -Value $text -Encoding ASCII
    $captured = (Test-Path -LiteralPath $out)
  } catch {}
  $count = 0
  if ($captured) { $count = @((Get-Content -LiteralPath $out) | Select-String -Pattern 'Target:').Count }
  return @{ Ran = $captured; Note = "cmdkey_started=$($p.Started) enumeration_captured=$captured stored_targets_listed=$count credential_values_unlocked=false"; NotApplicable = '' }
}
