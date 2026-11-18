# CSCRF-IR-04: a local account can be disabled and the state verified. Gated. Synthetic account only.
if (-not (Test-CgIrGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_IR_TEST not true; no account created [CSCRF-IR-04]' } 'ir-04' }
$name = 'bas-ir-' + $script:CgRun
New-CgUndoRecord 'ir-04' @{ scenario = 'ir-04'; accountName = $name }
try {
  New-LocalUser -Name $name -Password (ConvertTo-SecureString ([Guid]::NewGuid().ToString('N') + 'Aa1!') -AsPlainText -Force) -AccountNeverExpires -ErrorAction Stop | Out-Null
  Disable-LocalUser -Name $name -ErrorAction Stop
} catch { Complete-CgStep @{ Outcome = 'error'; Reason = "could not create or disable synthetic account: $($_.Exception.Message) [CSCRF-IR-04]" } 'ir-04' }
$u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
if ($u -and -not $u.Enabled) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'synthetic account disabled and state verified; who acts and how fast is not tested [CSCRF-IR-04]' } 'ir-04' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'synthetic account is still enabled after the disable action [CSCRF-IR-04]' } 'ir-04'
