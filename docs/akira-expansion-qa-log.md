# INTEGRATION NOTE (read first): what actually landed on main

This log was written on branch `akira-expansion`. When merging, `origin/main` had independently reworked the same Akira stages (verdict semantics, lab-only labels, an allow-listed sink, step-contract tests). Per the standing rule for concurrent-session collisions, main's version of those stages was kept and the colliding Part A rewrites were NOT merged. The branch `akira-expansion` still holds them.

| Part A item | On main |
|---|---|
| Stage 3 gate/private dir/cleanup_verified, 3b split handle facts, 4 state check with gated exclusion test, 5b retag T1041, 6 hash-verified transform, 6b retag, 9 EID 104 checks, 9b extra checks | NOT merged (main's rework kept) |
| Stage 8: shadow copies matched by volume DeviceID (old `-match 'C:'` could never match), `targeted_copy_id`/`deletion_verified` | only the DeviceID matching fix ported; re-query evidence not ported |
| Stage 9b SRUM path `System32\sru` (old path was wrong) | ported |
| Stage 5a local staging (T1074.001) | ported |
| Part B scenario, double-extortion scenario, lateral-containment scenario | merged unchanged |
| Part C stages 17-25 | merged (akira-kill-chain v2.1.0 on main, 26 steps) |

Mapping consequences on main: `T1567` stays mapped (main's stage 5b still uses it); `T1036.008` is NOT added (stage 6b unchanged). Added only the techniques the merged content uses.

Integration verification: `verify-all` ok=162 fail=0; scenario (incl. step-contract ratchet; its ledger was regenerated, only index shifts and new entries, the three new scenarios and akira have zero gap counts), rwevidence, rwtaxonomy, rwdetect, rwrecover, rwcontain, rwpropagation, compliance, adcoverage pass; `internal/api` corpus tests pass under `-short`. Failures that exist identically on a pristine `origin/main` checkout and are unrelated: `internal/killchain` (signing and vertical-slice tests), `internal/connector` (DB-backed test panics without Postgres), `internal/admatrix` (two tests expect exactly one step in the ADCS and delegation scenarios, which main now has 18 steps). Ported stage 8 was exercised only with the gate off and its volume resolution in isolation (found 2 shadow copies); its gated delete path was NOT run on the merged text (the earlier branch dry run covered different text).

---

# Akira Kill Chain expansion, Part A: QA log

Scenario `akira-kill-chain` v2.0.0 -> v2.1.0 (16 -> 17 steps). Branch `akira-expansion`.
Spec: `docs/superpowers/specs/2026-11-17-akira-expansion-part1-design.md`. Plan: `docs/superpowers/plans/2026-11-17-akira-expansion-part-a.md`.
Part B (`ransomware-backup-recovery-assurance`) is NOT built.

## What changed

| Stage | Change |
|---|---|
| 3 SAM/SYSTEM | Gate `BAS_CONFIRM_CREDENTIAL_ARTIFACTS` (exact `true`); elevation required else SKIP; private dir `bas_akira_cred_<run>` with owner-only ACL; hives overwritten then deleted; `cleanup_verified=`; `production_safe: false` |
| 3b LSASS | Reports `process_query_access=` and `vm_read_handle=` separately; VM_READ handle behind `BAS_CONFIRM_LSASS_HANDLE`; elevation required; states no memory read; `production_safe: false` |
| 4 Defender | Verdict from Defender state (`Get-MpComputerStatus`), not a command line; optional add/read-back/remove behind `BAS_CONFIRM_DEFENDER_TAMPER`; renamed (engine_test pin updated) |
| 5a (new) | Local staging, 5 synthetic files, hash check, cleanup verified (T1074.001) |
| 5b | Re-tagged T1567 -> T1041; now depends on 5a |
| 6 | 6 synthetic files, XOR transform verified by SHA-256 (original differs, decode equals original), `cleanup_verified` |
| 6b | Re-tagged T1486 -> T1036.008 (rename alone is not encryption) |
| 8 | Bug fix: shadow copies matched by volume DeviceID (old `-match 'C:'` could never match); `targeted_copy_id`, before/after, re-query `deletion_verified`; SKIP states `recovery_protection=not_evaluated`; pinned SKIP text kept |
| 9 | EID 104 check, retention, `siem_ingestion=unverified`, test log removal verified |
| 9b | Added Sysmon service and audit-policy checks; bug fix: SRUM path was `LogFiles\SRU`, real path is `System32\sru` |

Also: `rwtaxonomy/mapping.go` gains T1074.001, T1041, T1036.008; T1567 removed.

## Evidence (run on the Windows build host, elevated, Defender real-time OFF)

Executed for real: stage 5a (5/5 staged, hashes ok, cleanup verified), stage 6 (6/6 transformed and verified, cleanup verified), stage 9 (clear succeeded, EID 104 recorded, test log removed), stage 9b, stage 4 read-only path (reported FAIL because tamper protection and real-time monitoring are off on this host; correct for this host), stage 3b query-handle path.
Gate checks: stages 3, 3b, 4, 8 with values `TRUE`, `1`, `yes`, empty, `false`, ` true` all stayed gated; only exact `true` enables. Stage 3 and 8 gate-off output is SKIP. No `bas_akira*` residue left in `%TEMP%` after the runs.
Stage 8 resolution: dry run (Delete() replaced by a no-op) found 2 shadow copies on C: by DeviceID and reported deletion_verified=False. Shadow copy count stayed 2.
Automated: `signer verify-all` ok=156 fail=0; `go test -short` ok for scenario, rwevidence, rwtaxonomy, rwdetect, rwrecover, admatrix. Every step script parses cleanly (with the UTF-8 BOM the agent adds; old and new both fail to parse without it, so no regression).
Destructive-guard classification compared old vs new for every step: unchanged (only stage 8 is destructive).

## NOT verified (do not claim)

- Stage 3 with the gate on: would save real SAM/SYSTEM hives; not run on the build host.
- Stage 3b VM_READ handle, stage 4 exclusion add/remove: not run (gated; would touch lsass handle and Defender exclusions).
- Stage 8 real `Delete()`: never executed; only resolution and read-back logic were exercised.
- Control-blocked paths (PASS verdicts for 3, 5a, 6, 8, 9) were never observed: this host has no active protection, so only the FAIL/unblocked branches ran.
- Sysmon/SIEM: `siem_ingestion=unverified` by design; nothing confirms events reached a SIEM.
- `internal/contentregistry` corpus test and `internal/api` tests need Docker Postgres: not run.
- Nothing run through the real agent/orchestrator; no live run.

## Findings from the review

1. `id:` and `depends_on:` are not parsed by the scenario engine (the Step type has no such fields); order in the list is what counts. So the 5a/5b dependency edits are documentation only.
2. Pre-existing: stages 1, 2, 3 and 4 `depends_on: akira-s0-preflight`, which does not exist. Not changed (out of scope), flagged.
3. Re-tagging 6b away from T1486 means it no longer counts as encryption evidence in ransomware scoring (intended, but a visible scoring change). T1074.001, T1041, T1036.008 are not modeled by `rwevidence`, so 5a/5b/6b are reported but not graded as ransomware capabilities.
4. T1036.008 is the closest available tactic mapping for a mass rename; sub-technique choice is flagged for review.

---

# Part B: `ransomware-backup-recovery-assurance` v1.0.0 (7 steps, Windows, vendor-neutral)

Hand-written YAML (no generator). Registered in: `ransomwareScenarioIDs` (`internal/api/rwevidence_dispatch.go`), the corpus lists in `rwevidence`, `rwdetect`, `rwtaxonomy`, `contentregistry`, `internal/api/rwevidence_dispatch_corpus_test.go`, and `web/src/features/ransomware.js`. The scenario-count pin in `internal/scenario/product_line_test.go` went 127 -> 128. New mappings: T1007 (data discovery), T1555 (credential access), T1485 (encryption and destruction). Detection profiles reuse `windows_backup_tampering` and `windows_recovery_inhibition` (no new profile).

Technique choice: T1490 is deliberately NOT used. `rwevidence` models T1490 and grades it from VSS enumerate/delete/survival step names; assurance steps would be misread. The new techniques are unmodeled by `rwevidence`, so they appear as not-tested evidence rows, not as graded ransomware capabilities.

| Step | Verdict logic | Notes |
|---|---|---|
| B1 discovery | PASS if a vendor product, registry key, wbadmin backup version or shadow copy exists; FAIL if none (elevated); SKIP if none and not elevated | Windows Server Backup service alone does not count (it exists on every install) |
| B2 credential exposure | FAIL on extra Backup Operators members, admin-level backup service accounts or broadly writable repository ACEs; SKIP if nothing to assess | Credential target names only; domain-group nesting not resolved |
| B3 deletion resistance | Gate off: ACL approximation (deny-aware). Gate on (exact `true`): create/append/delete one canary per path | Canary may remain on retention-locked repositories (reported) |
| B4 immutability | Only from B3's canary result (state file in %TEMP%); SKIP without gate or result | Never guesses from product names |
| B5 restore | 3 reference files from newest C: shadow copy to scratch, hash-verified twice, scratch removed; no recovery point = FAIL | VSS only; `vendor_restore=not_exercised` |
| B6 service impact | Volumes of running critical/non-Windows services with zero VSS recovery points = FAIL; SKIP when a third-party product is present (coverage unknown) | Volume taken from service binary path; data locations not resolved |
| B7 RPO/RTO | RPO vs `BAS_RPO_TARGET_HOURS` (24), estimated restore vs `BAS_RTO_TARGET_MINUTES` (240); invalid values ignored with a note | Restore time is labelled ESTIMATE (64 MB sequential sample) |

## Part B evidence (build host: elevated, 2 old shadow copies, no backup product, Windows Server Backup service only)

Run for real: B1 (PASS via shadow copies), B2 (PASS; with a test repo granting Everyone Modify it FAILed and listed the ACE), B5 (3/3 restored and verified, cleanup verified), B6 (PASS, C: has 2 recovery points), B7 (sampled 65.6 MB at about 380 MB/s, estimate 13 min, FAIL because the newest recovery point is 491 h old vs 24 h target), B3 and B4 against throwaway folders under the scratchpad: gate wrong-case (`TRUE`) behaved as gate off; writable repo -> canary create/modify/delete ok -> FAIL, B4 FAIL; a folder with an inherited Delete deny -> modify denied, delete ok (admin) -> FAIL (partial denial detected); missing path ignored; no `bas_bra*` residue in %TEMP% afterwards.
Defects found by this review and fixed before commit: (1) B1 counted the always-present Windows Server Backup service as a backup product; (2) B5/B7 built a wrong `\?\GLOBALROOT` path (the WMI DeviceObject already carries the prefix), so B7 sampled 0 bytes.
Automated: `verify-all` ok=157 fail=0; scenario, rwevidence, rwtaxonomy, rwdetect, rwrecover, admatrix tests pass; `internal/api` corpus tests pass under `-short`.

## Part B NOT verified

- No PASS path for B3/B4 (a repository that really denies modify and delete) was observed: this host has no immutable repository and I could not construct one. Only the FAIL and gate/skip branches were exercised.
- No third-party backup product exists on this host: product discovery by service/process/registry name patterns is untested against real Veeam/Commvault/etc. installs; the name lists are from memory of those products and unverified.
- The B3 ACL check is an approximation (share permissions, product locks and token privileges not evaluated; the admin identity bypasses a delete denial through folder DeleteChild, as observed).
- B6 only inventories VSS; B5 restores only from VSS; vendor restores are not exercised. `BAS_BACKUP_REPO_PATHS` must be supplied by the operator (no repository auto-discovery).
- Not run through the real agent; `internal/contentregistry` corpus test and the rest of `internal/api` need Docker Postgres and were not run. `web/src/features/ransomware.js` was edited but not browser-checked (`hunters-international-kill-chain` was already missing from that list; left as is).
- `backupassurance` engine intentionally not wired (simulated-only by design).

---

# Part C: Windows completeness, Akira stages 17-25 (`akira-kill-chain` v2.1.0 -> v2.2.0, 26 steps)

Design: `docs/superpowers/specs/2026-11-17-akira-windows-completeness-design.md`. One technique tag per step; secondary techniques are named in evidence. Inserted in kill-chain order (list order is what the engine runs; `id`/`depends_on` are not parsed).

| Stage | Tag | Behaviour | Verdict |
|---|---|---|---|
| 17 valid accounts | T1078 | read-only local account posture, cached-logon policy, stored-credential count | FAIL on findings |
| 18 external remote services | T1133 | RDP/WinRM/SSH listeners, any-address firewall rules, VPN clients; internet reachability and MFA explicitly not claimed | FAIL if broadly exposed |
| 19 remote/domain discovery | T1482 (+T1018) | arp, net view, nltest (domain only), each capped at 20 s | FAIL if results, SKIP if timed out or off-domain with nothing found |
| 20 process/system/file discovery | T1082 (+T1057, T1083) | tasklist, systeminfo, whoami /all by full System32 path, document file count | FAIL if all three succeed |
| 21 execution telemetry | T1059.001 (+T1047, T1569.002) | encoded PowerShell, WMI create, optional gated transient service; reads 4104/4688/Sysmon 1/7045 back | FAIL = executed but no telemetry; PASS = executed and logged, or all blocked; SKIP = logs unreadable |
| 22 Kerberoast exposure | T1558.003 | LDAP read-only SPN accounts (privileged, RC4, stale counts); TGS only with two gates | FAIL on weak accounts; SKIP off-domain |
| 23 account persistence | T1136.001 | posture; gated creation of a disabled random-password local account, removed and verified | gate on: FAIL if created |
| 24 Run key | T1547.001 | inventory; gated HKCU value write, read back, removed and verified | gate on: FAIL if written |
| 25 remote access tools | T1219 | 15-tool catalogue by service/process/installed names; allow-list env | FAIL if unsanctioned present |

Tag deviation: stage 23 uses T1136.001 (local), not the requested T1136.002 (domain), because only a local account is simulated. Real detection profiles are attached only to 19, 20 and 21 (those always perform the behaviour); `windows_encoded_powershell` was added to `RansomwareRelevantProfiles`. Mappings added for T1133, T1482, T1082, T1059.001, T1558.003, T1136.001, T1547.001, T1219.

## Evidence (build host: workgroup, elevated, Defender real-time off)

Run for real: 17 (3 findings), 18 (RDP exposed to any address), 19 (32 ARP neighbours; `net view` hung and was cut at 20 s), 20, 21 (gate off and on; no 4104 or 4688 telemetry on this host, so FAIL; 7045 found for the gated service; service removed), 22 (SKIP, not domain joined), 23 gate off SKIP and gate on (account created disabled, removed, cleanup verified), 24 inventory SKIP and gate on (value written, read back, removed), 25 (found UltraViewer). Wrong-case gate values (`TRUE`) stayed SKIP. No residue: no `bas_p_*` user, no `BAS_Persist_*` Run value, no `BASAk21*` service. YAML commands are byte-identical to the scripts run; all parse with the UTF-8 BOM; destructive-guard classification of every new step is non-destructive; `verify-all` ok=159 fail=0; scenario, rwevidence, rwtaxonomy, rwdetect, rwrecover, admatrix tests pass; `internal/api` corpus tests pass under `-short`.

Defects found by this review and fixed before commit: (1) stage 19 hung on `net view` for minutes; every discovery command now has a 20 s cap and timeouts are reported; (2) stage 20 invoked Git's `whoami.exe` found first on PATH, which returned nothing and produced a false PASS; system binaries are now called by full System32 path and judged by exit code and output.

## NOT verified

- Stage 22 against a real domain: only the SKIP path ran; the LDAP query, counting and the gated TGS request were never executed.
- Stage 19 domain half (nltest trusts and DC list) never ran (workgroup host).
- Stages 17 and 18 read a single non-domain host; domain account hygiene and internet reachability are not assessed.
- Stage 21 service telemetry found 7045 here, but 4104/4688 absent here may differ on hosts with logging enabled (positive PASS path with all channels logged was not observed); the Sysmon path was never exercised (Sysmon not installed).
- No control that blocks any of these behaviours exists on the host, so no blocked-branch PASS was observed for 23, 24 and 21.
- Real agent/orchestrator not used; `contentregistry` and the rest of `internal/api` need Docker and were not run; the decorative `depends_on` references (including the pre-existing `akira-s0-preflight`) are unchanged.
- Part B steps reference detection profiles `windows_backup_tampering` and `windows_recovery_inhibition` that have no profile file (inert, as in the Akira and Rhysida scenarios); they therefore carry no detection expectations.

## Part A ported onto main (2026-11-18) and coverage check

Coverage check against the original analysis: stages 17-25 map to Akira stages 17-25 (T1078, T1133, T1482, T1082 with file discovery, T1059.001 incl. WMI/service telemetry, T1558.003, T1136.001 with a domain-account path, T1547.001, T1219); 26-29 to lateral-containment L1-L5 (T1021, T1570, T1569.002, cross-host); 30-34 to double-extortion D1-D5; 35-42 to backup assurance B1-B7 plus L5 containment; ESXi scenario separate. Gaps: T1057 process discovery is only partly covered in stage 20; T1136.002 is a path inside the T1136.001 stage, not its own technique ID; the cross-host stage proves reachability with the host as its own target.

Ported from Part A (commit 3993f400) over main's versions: stage 3 (gated credential artifacts, verified cleanup), 3b (handle-access probe, no memory read), 4 (state-based Defender verdict), 5b (T1041, own sink), 6 (hash-verified transform), 6b (T1036.008, not T1486), 9 (gated, retention/SIEM check). Main's stage 7/8/8b/8c/9b and 5/5a/5c were kept (main's rework, incl. the VSS volume fix). Mapping: T1036.008 added, stale T1567 removed. Verified: verify-all 163/0, scenario/rwtaxonomy/rwevidence/rwdetect/compliance/adcoverage, Docker contentregistry and api ransomware/corpus tests. Not re-run against a real agent after the port; the ported text is the text exercised locally in Part A.

## Gap closure: T1057 and T1136.002 (2026-11-18)
Correction to my earlier coverage note: stage 20 already ran tasklist.exe (process listing, line count only). It now also enumerates processes via Get-Process and reports a count plus which known security/backup tool processes (fixed name list) are present, as a separate EVIDENCE T1057 line; verdict requires process enumeration to succeed as well. Stage 23 gained a read-only domain posture line (T1136.002: domain-joined, token groups, Account Operators member count) and a second gate `BAS_CONFIRM_DOMAIN_ACCOUNT_CREATE` (exact) that creates one disabled domain user in CN=Users, verifies, deletes via DeleteTree and verifies removal; cleanup also sweeps `bas_pd_*`. Primary technique IDs unchanged (T1082, T1136.001).
Verified locally on a workgroup host: stage 20 FAIL with 267 processes and 3 tools seen; stage 23 no gates SKIP, domain gate only SKIP (not_domain_joined), wrong-case gate SKIP; scripts parse, ASCII-only, guard classifies non-destructive; verify-all 163/0 and unit tests pass. NOT verified: the domain create/delete path has never run (no domain); the local create path in the new combined script was not re-run (same code as before, restructured).
