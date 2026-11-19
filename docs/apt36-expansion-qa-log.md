# APT36 Expansion - QA Log

## What was verified (2026-11-17, Windows 10 Pro build host, no EDR, no Sysmon, no enforcement)
- All 30 non-gated steps were run for real from the final generated, minified YAML (not just the source scripts): every one reports `cleanup_verified=True`; no `bas_a36_*` leftovers in TEMP, Startup folder, C:\Users\Public, or WinRM/service/WMI state.
- Gated steps `apt36-pe1` (WMI subscription), `apt36-pe3` (service lifecycle) and `apt36-k3` (admin-share staging) were individually verified earlier in the build with their gates set and as administrator: all ran, all verified clean removal.
- `apt36-pe5` (Defender exclusion) was reviewed but intentionally never run live in this session — the harness itself refused a batch run that would have exercised it, which is the correct behavior for a step that changes live AV configuration. It is covered by a Go test that confirms it refuses to run without its gate.
- `apt36-k4` (WinRM exposure check) was rewritten mid-build from an active start/stop sequence to a pure read of current state, after review raised that starting/stopping a system service is a real (if temporary) behavior change. A dedicated Go test (`TestAPT36_K4NeverChangesWinRMState`) greps its generated command for any state-changing verb and fails if one appears.
- `apt36-i2` (execution from a mounted VHD, a Mark-of-the-Web bypass route) was written and then withheld entirely after review; it never shipped.
- Go tests: decision table, well-formedness (counts, ASCII, cleanup, technique tagging) across all 6 scenarios, four gate-skip matrices, the k4 read-only guarantee; scenario package green (292s); product_line count pin 145 -> 150; step-contract ledger regenerated; `verify-all` 180 ok.

## Lateral movement step k5 (built, not tested)
- `apt36-k5` (T1569.002, remote service execution over the Service Control Manager) was added after the 2026-11-17 verification above. It is gated by `BAS_CONFIRM_APT36_LATERAL_MOVEMENT=true` (exact), requires administrator, and acts only on hosts named in `BAS_LATERAL_TARGETS` (invalid names are ignored). Per target it creates a run-tagged demand-start service, starts and stops it, deletes it and verifies the deletion with a separate query.
- **Status: built and statically checked only.** The Go gate test passes and the signature verifies, but the step has NOT been run against any lab target. The user has asked that it be tested after the build, so no verdict is claimed.
- Review fixes that came with it: the `k1` listener start is now guarded; `d5` derives its pass flag from output; `i6` cleanup stops only `hh.exe` processes launched with this run's tag.
- Review findings deliberately not acted on (duplication and tidiness, no change to behavior or gating): repeated listener and process-launch boilerplate across steps, a repeated `cmdkey` launch in `cc2`, an unconditional 800 ms sleep in every mode, and a hand-written gated-step list in the test. A shared gate check in `lib.ps1` is the one worth doing before testing.

## Pack completion (built, NOT tested)
- Added after the k5 entry: `apt36-k6` (T1053.005 remote scheduled task, gated like k5, targets only from `BAS_LATERAL_TARGETS`, built not run) and `apt36-k7` (T1071.004 forty-query DNS tunneling volume pattern, telemetry mode, `.invalid` names only).
- `k7` was run once on this host with no gate (it is safe): it sent 40 queries and reported the expected SKIP because Sysmon is absent here.
- `k6` and `k5` have NOT been run against any target. Their gate and cleanup were checked statically (gate skip tests pass; cleanup UNC path verified in the generated YAML).
- `lib.ps1` gained `Test-A36Gate` and `Test-A36Admin`. The new steps use them. The older gated steps still carry their own inline checks; they were not refactored, to avoid changing already-verified behavior.
- Totals: 37 steps across six scenarios (10 kill chain, 5, 5, 5, 5, 7). Go tests pass; `verify-all` 180 ok.
- Not built, with reasons: keystroke collection, macro-enabled document chain, Android, HTTPS exfiltration (see test contracts).

## Honest limits
- Same block-attribution and Defender-presence-as-failure limits documented for the APT29 pack apply here (`docs/apt29-expansion-qa-log.md`): a real block of a System32 binary may not carry the run tag, and a step that ran is scored FAIL whenever Defender is merely on, not because Defender specifically covers that behavior.
- `k3`/lateral-movement steps only prove this host can reach itself over its own admin share and WinRM; no second host was available to test real cross-host movement.
- `cc1` (LSASS handle) and `cc4` (clipboard) are posture/capability probes; neither proves credential extraction or real keystroke/clipboard capture is possible.
- `i6` (CHM) correctly reported `not_applicable` on this host because the HTML Help compiler is not installed; it has not been observed to actually compile and run a .chm anywhere in this session.
- Vendor EDR other than Microsoft Defender, SIEM ingestion, and beaconing/DGA analytics are not verified, as with the APT29 pack.
