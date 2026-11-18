# Cobalt Group BFSI - Windows Command Shell Execution (exe-01)
$marker = 'BAS-SIM-EXE-' + $script:CgRun
$out = & "$env:SystemRoot\System32\cmd.exe" /c "echo $marker" 2>&1
if (($out | Out-String) -match [regex]::Escape($marker)) {
  $res = @{ Outcome = 'pass'; Reason = 'cmd.exe executed and returned the expected marker' }
} else {
  $res = @{ Outcome = 'fail'; Reason = 'cmd.exe did not return the expected marker' }
}
Complete-CgStep $res 'exe-01'
