$sn = "bas_$($script:AppCtlTid.Substring(0,8)).ps1"
Invoke-AppCtlTest -Family 'powershell_language_mode' -Collection 'Script' -Needle $sn -Technique 'T1059.001' -Attempt {
  $mk = Join-Path $script:AppCtlWork 'langmode-marker.txt'
  $ps1 = Join-Path $script:AppCtlWork $sn
  $body = "`$m = `$ExecutionContext.SessionState.LanguageMode`r`n`$full = `$false`r`ntry { Add-Type -TypeDefinition 'public class BasLm { public static int V() { return 7; } }' -ErrorAction Stop; `$full = ([BasLm]::V() -eq 7) } catch { }`r`nSet-Content -Path '$mk' -Value ('$($script:AppCtlMarker) mode=' + `$m + ' fulllang=' + `$full)"
  Set-Content -Path $ps1 -Value $body -Encoding ASCII
  $p = Invoke-AppCtlProc -File (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgLine "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ps1`""
  $txt = (Get-Content -Path $mk -ErrorAction SilentlyContinue) -join ' '
  $full = ($txt -like '*fulllang=True*')
  $constrained = ($txt -like '*mode=ConstrainedLanguage*' -or $txt -like '*mode=RestrictedLanguage*' -or ($txt -like "*$($script:AppCtlMarker)*" -and -not $full))
  return @{ Ran = $full; Constrained = $constrained; Exit = $p.Exit; Note = "script_output=[$(($txt -replace '[^A-Za-z0-9 =_.-]', ''))] timed_out=$($p.TimedOut)"; NotApplicable = '' }
}
