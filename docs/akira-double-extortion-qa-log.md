# Akira Double-Extortion Assessment: QA log

Scenario `akira-double-extortion-assessment` v1.0.0, 5 steps, Windows. Design: `docs/superpowers/specs/2026-11-17-akira-double-extortion-design.md` (approved; implemented directly from it, no separate plan document).

| Step | Technique / profile | Verdict logic |
|---|---|---|
| D1 discovery | T1083 / windows_file_discovery | Plants 8 synthetic files (5 sensitive), scans for PAN/Aadhaar/card patterns; FAIL if identified |
| D2 archiving | T1560.001 / windows_archive_staging | Zips the 5 sensitive files, verifies entry count and SHA-256; reports (does not run) rclone/WinSCP/7-Zip/WinRAR/FileZilla presence; FAIL if archive verified |
| D3 staging | T1074.001 / windows_archive_staging | Copies archive to a staging area, hash-verified; network staging only with `BAS_CONFIRM_NETWORK_STAGING=true` plus `BAS_STAGING_SHARE`, copy removed and verified |
| D4 exfil | T1041 / windows_dlp_exfiltration | Reachability probe then HTTPS POST of the base64 archive to `{{SINK_URL}}`; SKIP if placeholders unresolved; FAIL if the request completes |
| D5 correlation | T1657 / windows_dlp_exfiltration | Reads ledger, timeline, checks D2/D4 hash match; FAIL = whole chain unblocked; PASS names first interrupted link; SKIP if a step recorded nothing; removes work dir and verifies |

Registered in the same touchpoints as Part B; T1657 mapped to the exfiltration domain; scenario-count pin 128 -> 129.

## Evidence (build host, run locally as 5 separate script runs, local stub HTTP server as the sink)

- Full chain, sink up: D1-D4 FAIL (each unblocked), D5 FAIL "chain viable", archive hash consistent, cleanup verified, no `bas_dxe*` left in %TEMP%.
- Sink down: D4 PASS (blocked), D5 PASS naming D4 as the interrupted link.
- Placeholders unresolved: D4 SKIP, D5 SKIP (D4 recorded nothing).
- Edges: D5 without a ledger SKIPs; D2 without fixture SKIPs; D3 without archive SKIPs; D1 over a stale work dir recreates cleanly; `BAS_DATA_SCAN_PATHS` returned counts only (scanned=2, matching=1) and ignored a missing path.
- YAML commands are byte-identical to the scripts that were run. `verify-all` ok=158 fail=0; scenario, rwevidence, rwtaxonomy, rwdetect, rwrecover, admatrix tests pass; `internal/api` corpus tests pass under `-short`.

## NOT verified

- Never run through the real agent or orchestrator, so `{{SINK_URL}}`/`{{SINK_TOKEN}}` substitution and server-side sink receipt were not exercised (the sink was a local stub that accepts any POST).
- No PASS branch for D1-D3 was observed (needs an endpoint control that blocks scanning, zipping or staging); only D4/D5 PASS was observed, by making the sink unreachable.
- Network staging (D3) was never run; `BAS_STAGING_SHARE` path untested.
- `rwevidence` models T1560.001 (D2): how that row grades for this scenario was not exercised. `contentregistry` and the rest of `internal/api` tests need Docker and were not run; `ransomware.js` not browser-checked.
- The ledger and work directory persist between steps; an aborted run leaves `%TEMP%\bas_dxe_<run>` until the run id is reused or D5's cleanup runs. The ledger is endpoint-local and forgeable by an attacker on the host.
- Tool presence uses a bounded search (PATH plus Program Files depth 2); tools installed elsewhere are missed.
- DLP content matching cannot inspect the zip, so D4 does not test content-aware DLP.
