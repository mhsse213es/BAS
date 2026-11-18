# CSCRF-SIEM-03: a tagged event written on this host arrives at the SIEM query API (gated; writes one event).
# ASSUMED API CONTRACT (confirm when the endpoint is named): GET <BAS_SIEM_ENDPOINT>?q=<tag> returns HTTP 200 with the tag in the body once ingested.
if (-not (Test-CgSiemGate)) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_CONFIRM_SIEM_TEST not true; no event written [CSCRF-SIEM-03]' } 'siem-03' }
$ep = $env:BAS_SIEM_ENDPOINT
if (-not $ep) { Complete-CgStep @{ Outcome = 'skip'; Reason = 'BAS_SIEM_ENDPOINT not set; no collector named, ingestion not tested [CSCRF-SIEM-03]' } 'siem-03' }
$tag = 'BAS-SIEM-' + $script:CgRun + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
New-CgUndoRecord 'siem-03' @{ scenario = 'siem-03'; tag = $tag }
& eventcreate.exe /L APPLICATION /T INFORMATION /SO BAS-SIEM /ID 4242 /D "$tag synthetic test event; no real data" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Complete-CgStep @{ Outcome = 'error'; Reason = "eventcreate failed (exit $LASTEXITCODE) [CSCRF-SIEM-03]" } 'siem-03' }
$found = $false; $lastErr = $null
for ($i = 0; $i -lt 12 -and -not $found; $i++) {
  Start-Sleep -Seconds 5
  try {
    $r = Invoke-WebRequest -Uri ($ep + '?q=' + $tag) -UseBasicParsing -TimeoutSec 10
    if ($r.StatusCode -eq 200 -and $r.Content -match [regex]::Escape($tag)) { $found = $true }
  } catch { $lastErr = $_.Exception.Message }
}
if ($found) { Complete-CgStep @{ Outcome = 'pass'; Reason = 'tagged event arrived at the SIEM query API. Alert handling by the SOC is not tested [CSCRF-SIEM-03]' } 'siem-03' }
if ($lastErr) { Complete-CgStep @{ Outcome = 'error'; Reason = "SIEM query API unreachable or failing: $lastErr [CSCRF-SIEM-03]" } 'siem-03' }
Complete-CgStep @{ Outcome = 'fail'; Reason = 'tagged event did not arrive at the SIEM within 60 s [CSCRF-SIEM-03]' } 'siem-03'
