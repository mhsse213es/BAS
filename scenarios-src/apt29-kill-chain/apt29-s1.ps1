Invoke-A29Test -Id 's1' -Technique 'T1482' -Summary 'domain trust and local account discovery (T1482, T1087.001)' -Telemetry @('sysmon:1', 'sec:4688') -Attempt {
  $t = Join-Path $script:A29Work 'trusts.txt'
  $u = Join-Path $script:A29Work 'users.txt'
  $cmdLine = '/c nltest.exe /domain_trusts /all_trusts > "' + $t + '" 2>&1 & net.exe user > "' + $u + '" 2>&1'
  $p = Invoke-A29Proc -File (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgLine $cmdLine -TimeoutSec 30 -NoShell
  $to = [string](Get-Content -LiteralPath $t -Raw -ErrorAction SilentlyContinue)
  $uo = [string](Get-Content -LiteralPath $u -Raw -ErrorAction SilentlyContinue)
  $domain = [bool]($to -match 'Trusted DC Name|List of domain trusts|Trust Direction')
  $ran = ($p.Started -and $to.Trim().Length -gt 0 -and $uo.Trim().Length -gt 0)
  return @{ Ran = $ran; Note = "nltest_output_chars=$($to.Length) net_user_output_chars=$($uo.Length) domain_trust_data=$domain started=$($p.Started)"; NotApplicable = '' }
}
