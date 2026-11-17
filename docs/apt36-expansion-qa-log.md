# APT36 Expansion - QA Log

## What was verified (2026-11-17, Windows 10 Pro build host, no EDR, no Sysmon, no enforcement)
- All 30 non-gated steps were run for real from the final generated, minified YAML (not just the source scripts): every one reports `cleanup_verified=True`; no `bas_a36_*` leftovers in TEMP, Startup folder, C:\Users\Public, or WinRM/service/WMI state.
- Gated steps `apt36-pe1` (WMI subscription), `apt36-pe3` (service lifecycle) and `apt36-k3` (admin-share staging) were individually verified earlier in the build with their gates set and as administrator: all ran, all verified clean removal.
- `apt36-pe5` (Defender exclusion) was reviewed but intentionally never run live in this session — the harness itself refused a batch run that would have exercised it, which is the correct behavior for a step that changes live AV configuration. It is covered by a Go test that confirms it refuses to run without its gate.
- `apt36-k4` (WinRM exposure check) was rewritten mid-build from an active start/stop sequence to a pure read of current state, after review raised that starting/stopping a system service is a real (if temporary) behavior change. A dedicated Go test (`TestAPT36_K4NeverChangesWinRMState`) greps its generated command for any state-changing verb and fails if one appears.
- `apt36-i2` (execution from a mounted VHD, a Mark-of-the-Web bypass route) was written and then withheld entirely after review; it never shipped.
- Go tests: decision table, well-formedness (counts, ASCII, cleanup, technique tagging) across all 6 scenarios, four gate-skip matrices, the k4 read-only guarantee; scenario package green (292s); product_line count pin 145 -> 150; step-contract ledger regenerated; `verify-all` 180 ok.

## Honest limits
- Same block-attribution and Defender-presence-as-failure limits documented for the APT29 pack apply here (`docs/apt29-expansion-qa-log.md`): a real block of a System32 binary may not carry the run tag, and a step that ran is scored FAIL whenever Defender is merely on, not because Defender specifically covers that behavior.
- `k3`/lateral-movement steps only prove this host can reach itself over its own admin share and WinRM; no second host was available to test real cross-host movement.
- `cc1` (LSASS handle) and `cc4` (clipboard) are posture/capability probes; neither proves credential extraction or real keystroke/clipboard capture is possible.
- `i6` (CHM) correctly reported `not_applicable` on this host because the HTML Help compiler is not installed; it has not been observed to actually compile and run a .chm anywhere in this session.
- Vendor EDR other than Microsoft Defender, SIEM ingestion, and beaconing/DGA analytics are not verified, as with the APT29 pack.
