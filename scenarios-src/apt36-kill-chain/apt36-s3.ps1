Invoke-A36Test -Id 's3' -Technique 'T1056.001' -Mode Direct -Telemetry @('sysmon:1') -Summary 'keyboard-hook API capability probe (T1056.001); it checks reachability only and installs no hook, see the controlled hook step in apt36-collection-credential' -Attempt {
  $mods = @([Diagnostics.Process]::GetCurrentProcess().Modules | ForEach-Object { $_.ModuleName.ToLower() })
  $user32 = ($mods -contains 'user32.dll')
  $pat = @('mfehidk', 'cyoptics', 'epdrv', 'atrsdfw', 'cbk7', 'cbstream', 'psinject', 'hmpalert', 'amsi', 'sentinel', 'crowdstrike', 'cylance')
  $edr = @($mods | Where-Object { $m = $_; ($pat | Where-Object { $m -match $_ }).Count -gt 0 })
  $edrStr = if ($edr.Count -gt 0) { $edr -join ',' } else { 'none' }
  return @{ Ran = $user32; Note = "user32_loaded=$user32 hook_installed=false keystrokes_captured=false security_modules_in_process=$edrStr capability_probe_only=true"; Verdict = @{ Outcome = 'inconclusive'; Reason = 'API capability probe only; no hook was installed, so no control outcome exists and it is not scored' }; NotApplicable = '' }
}
