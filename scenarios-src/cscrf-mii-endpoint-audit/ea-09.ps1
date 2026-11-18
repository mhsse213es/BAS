# CSCRF-EA-09: execution of an unsigned, renamed binary from a temp path must be blocked. Gated.
if (-not (Test-CgEndpointGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_ENDPOINT_CHANGE not true; no file copied or run [CSCRF-EA-09]' } 'ea-09' }
$dir = Join-Path $env:TEMP ('bas-ea-' + $script:CgRun)
New-CgUndoRecord 'ea-09' @{ scenario = 'ea-09'; dir = $dir }
try { New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null } catch { Complete-CgStep @{ Outcome = 'error'; Reason = "temp folder could not be created: $($_.Exception.Message) [CSCRF-EA-09]" } 'ea-09' }
$marker = Join-Path $dir 'bas-ea-marker.exe'
try { Copy-Item -LiteralPath "$env:SystemRoot\System32\cmd.exe" -Destination $marker -ErrorAction Stop } catch {
  Complete-CgStep @{ Outcome = 'pass'; Reason = "copy of a renamed binary to a temp path was refused: $($_.Exception.Message) [CSCRF-EA-09]" } 'ea-09'
}
$out = & $marker /c "echo BAS-EA-MARKER-$script:CgRun" 2>&1
if (($out | Out-String) -match "BAS-EA-MARKER-$script:CgRun") {
  Complete-CgStep @{ Outcome = 'fail'; Reason = 'renamed binary ran from a temp path; no execution control applied [CSCRF-EA-09]' } 'ea-09'
}
Complete-CgStep @{ Outcome = 'pass'; Reason = 'renamed binary did not run from the temp path [CSCRF-EA-09]' } 'ea-09'
