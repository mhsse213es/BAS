# Akira Double-Extortion Assessment: design (approved 2026-11-17)

Sub-project 2 of the Akira programme. Spec parent: `2026-11-17-akira-expansion-part1-design.md`.

## Intent
Prove whether sensitive data can be identified, collected, archived, staged and moved off a Windows host through an approved controlled channel, using only synthetic fixtures, and give one correlated verdict on whether the double-extortion chain is viable. Maps the user's stages 30-34.

## Goals / non-goals
- Goals: 5-step scenario `akira-double-extortion-assessment`; reproducible (BAS plants and removes its own fixture); every step verifies its own outcome and cleanup; per-run evidence ledger; honest verdicts (PASS/FAIL/SKIP with stated reason).
- Non-goals: no real customer data is read or sent; no real Rclone/WinSCP execution (tool presence only); no orchestrator-side correlator (belongs to the later detection/response efficacy sub-project); no cloud-provider uploads.
- Anti-goal: a chain verdict that implies detection or sink receipt the endpoint cannot see.

## Steps
D1 discovery (T1083, `windows_file_discovery`); D2 collection and archiving (T1560.001, `windows_archive_staging`); D3 staging (T1074.001, `windows_archive_staging`); D4 exfiltration to the platform sink over HTTPS (T1041, `windows_dlp_exfiltration`); D5 chain correlation (T1657, `windows_dlp_exfiltration`).

## Decisions
- Work area `%TEMP%\bas_dxe_<run>\` holds fixture, stage dir and `ledger.jsonl`. It persists across D1-D4 and is removed and verified by D5 (and by D5's cleanup). An aborted run leaves it; D1 clears a stale one of the same run id.
- Optional `BAS_DATA_SCAN_PATHS`: counts of pattern-matching files only; no names or content in output.
- Network staging only with `BAS_CONFIRM_NETWORK_STAGING=true` (exact) and `BAS_STAGING_SHARE`.
- D4 uses `{{SINK_URL}}`/`{{SINK_TOKEN}}`; unresolved placeholders mean SKIP. Sink receipt is verified server-side and is not visible to the endpoint; D4 says so.
- D5 verdict: FAIL if every link ran unblocked (chain viable); PASS naming the first blocked link; SKIP if the ledger is missing.
- T1657 is mapped to the exfiltration domain; T1041, T1083, T1560.001, T1074.001 are already mapped. Registered in the same ransomware touchpoints as Part B.

## Approaches
A (chosen) hand-written scenario with local ledger; B plus orchestrator correlator (deferred to the efficacy sub-project); C fold into existing scenarios (rejected).

## Honest limits
Nothing lab-verified through the real agent; DLP content matching cannot inspect a zip; ledger is endpoint-local and forgeable by an attacker on the host.
