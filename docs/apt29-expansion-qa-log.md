# APT29 Expansion - QA Log

## What was verified (2026-11-17, Windows 10 Pro build host, no EDR, no Sysmon, no enforcement)
- Every one of the 28 steps in the 6 generated, minified YAMLs was run for real (`runall`): all report `cleanup_verified=True`; no `bas_a29_*` leftovers in TEMP, Startup folder, registry Run, scheduled tasks, WMI, C:\Users\Public. Pre-existing portproxy rule (0.0.0.0:9090) untouched.
- Ungated results: execution/persistence/credential/collection steps FAIL as `not_enforced` (behavior ran, nothing blocked). That is the correct finding for this host.
- Gated steps were also run with their gate set and as administrator: x9 PASS (System EID 104 visible), p3 FAIL not_enforced (WMI 5861 visible), k3 FAIL (relay confirmed, rule removed), o2 FAIL (4 files verified on share, folder removed).
- Telemetry-mode steps (s5, k1, k2) are SKIP here: Sysmon and DNS-Client logs are unavailable, so visibility cannot be judged.
- Go tests: decision table, well-formedness (counts, ASCII, cleanup, technique attribution), detection_profiles preserved, four gate-skip matrices; scenario package and step-contract ledger green; count pin 140 -> 145; `verify-all` 175 ok.

## Honest limits
- Block/prevented paths and telemetry-visible paths for Defender/AppLocker/Sysmon are exercised by decision-table fixtures only; no real blocking control was observed.
- Vendor EDR other than Microsoft Defender is not queried. SIEM ingestion and beaconing/DGA analytics are not verified.
- x9: the Event Log service holds the test log's .evtx open, so one small residual `BASSIM_APT29.evtx` remains until the service restarts; the fixed name means it is reused, not accumulated.
- c1: the build host had no Kerberos tickets (workgroup), so ticket listing was 0 and the step only proves klist ran.
- p4 and x1 ran as the current user; WMI/scheduled-task telemetry (4702, 140, 5857) was not_visible without auditing enabled.
- Cloud identity pack, domain-joined/AD-dependent behavior and non-Windows hosts untested.
