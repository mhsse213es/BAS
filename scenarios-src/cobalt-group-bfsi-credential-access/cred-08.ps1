# Cobalt Group BFSI - Unsecured credential file discovery (cred-08)
$undo_data = @{ scenario = 'cred-08'; timestamp = (Get-Date -Format 'o'); description = 'Unsecured credential file discovery' }
try { New-CgUndoRecord 'cred-08' $undo_data } catch { Complete-CgStep @{ Outcome = 'error'; Reason = 'Undo record creation failed' } 'cred-08' }

$res = try { $paths = @($env:USERPROFILE, $env:APPDATA); $found = 0; foreach ($p in $paths) { $files = Get-ChildItem -Path $p -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10; $found += $files.Count }; if ($found -gt 0) { @{ Outcome = 'fail'; Reason = "Found $found PowerShell files with potential credentials" } } else { @{ Outcome = 'pass'; Reason = 'No credential files found' } } } catch { @{ Outcome = 'error'; Reason = 'Credential file discovery failed' } }
Complete-CgStep $res 'CRED-08'
