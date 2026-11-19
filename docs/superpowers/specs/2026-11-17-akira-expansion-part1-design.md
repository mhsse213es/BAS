# Akira expansion, part 1: honesty corrections + Backup & Recovery Assurance (design)

Status: DRAFT, awaiting approval. Scenario #2 of the scenario-upgrade series.

## Intent
Make the Akira ransomware content prove resilience, not just run attacker-like commands. A simulated action is not proof the attack succeeded, and a command line is not proof a control detected it. This part fixes the existing Akira stages that overstate what they prove, then adds a new scenario that tests whether backups are protected and recoverable.

## Whole programme (agreed order; each part gets its own design and approval)
0+1 (this doc): corrections to the 16 existing Akira stages, and the new Backup & Recovery Assurance scenario.
2 Akira double-extortion scenario. 3 cross-host lateral movement and containment. 4 Windows kill-chain completeness (stages 17-25). 5 Akira ESXi scenario (own evidence model, content only, no Track C lab). 6 detection and response efficacy layer.

## Part A: corrections to `akira-kill-chain.yaml` (version 2.0.0 to 2.1.0)
Each row is a decision I made; none changes the scenario id.
| Stage | Today | Change |
|---|---|---|
| 3 SAM/SYSTEM | `reg save` writes real hives to %TEMP%, marked production_safe | Lab gate `BAS_CONFIRM_CREDENTIAL_ARTIFACTS=true`, otherwise SKIP; write into a private directory, overwrite then delete, verify removal and report it; production_safe false |
| 3b LSASS | Query-limited access probe, wording implies credential theft | Report two separate facts: process query access, and VM_READ-capable handle (opened and closed, no memory read). Lab-gated for the VM_READ part. Output never claims credential extraction |
| 4 Defender | Prints "EXEC" and changes nothing; no verdict | Read Defender state (tamper protection, real-time monitoring, exclusions) as the verdict. With lab gate `BAS_CONFIRM_DEFENDER_TAMPER=true`: add a unique BAS-owned path exclusion, read it back, remove it, verify removal |
| 5b exfil | Tagged T1567; no local staging step exists | Split into local staging (T1074.001, synthetic files in a BAS directory, cleanup verified) and HTTPS POST to our own sink (T1041). T1567.002 stays only for cloud-storage reachability |
| 6 simulation | XOR of one temp file; verdict is "file written or not" | Several synthetic files in a BAS-owned directory; verify content transformation by hash change and reversibility; labelled a transform simulation, not cryptographic encryption |
| 6b mass rename | Tagged T1486 | Reported separately and re-tagged T1036.008 (masquerade file type), so rename alone is not counted as encryption. Mapping to confirm |
| 8 VSS deletion | Gate exists | Keep gate; record the targeted copy ID, count before and after, and verify independently. A gate-off SKIP is never recovery protection |
| 9 log clearing | Clears a BAS custom log only | After the attempt, verify System EID 104 was written and the log state; report retention settings; SIEM ingestion reported as unverified because no endpoint can prove it |
| 9b anti-forensics | Read-only existence checks | Add audit-policy, log-size/retention and Sysmon service checks; verdict is posture, not proof of resistance |

## Part B: new scenario `ransomware-backup-recovery-assurance`
Windows, product line ransomware, vendor-neutral, read-only by default. Your stages 35-42 map to B1-B7; stage 42 (containment and response validation) moves to part 3 because it needs cross-host evidence.
- B1 Backup service and repository discovery [P0]: known backup products by service/process/registry (Veeam, Commvault, Veritas, Acronis, Rubrik, Cohesity, Azure MARS, DPM, Datto, Arcserve), Windows Server Backup, VSS writers and shadow storage, wbadmin versions.
- B2 Backup credential and access exposure [P0]: Backup Operators members, backup service logon accounts and whether they are domain/local admin, backup-named stored credentials (names only), repository share and folder ACLs.
- B3 Deletion/modification resistance [P0]: effective rights of the current identity on repository paths (read-only). With lab gate `BAS_CONFIRM_BACKUP_CANARY_WRITE=true`: create, modify and delete a uniquely named tiny canary file only.
- B4 Immutability validation [P0]: from the canary result only (delete or modify denied = immutability evidence). Without the gate it SKIPs with reason; it never guesses from vendor names. Note: on a retention-locked repository the canary stays until the lock expires.
- B5 Restoration verification [P0]: restore a reference file set from the newest recovery point to a scratch folder, compare hashes, time it. No recovery point is a FAIL, not a SKIP.
- B6 Critical service availability impact [P1]: which running critical services have data on volumes with no recovery point.
- B7 RPO/RTO measurement [P1]: newest recovery-point age (RPO) and measured restore throughput; a full-restore time is an ESTIMATE and labelled so. Targets from `BAS_RPO_TARGET_HOURS` (default 24) and `BAS_RTO_TARGET_MINUTES` (default 240).

## Verdict rules (all new and changed steps)
PASS / FAIL / ERROR / SKIPPED. Every SKIP names its reason (gate not confirmed, prerequisite missing, no product found). Every step verifies its postcondition independently of the command it ran, and verifies cleanup of anything it created.

## Constraints
- Each scenario edit re-signs the `.sig` (release key from the main checkout, absolute path).
- New ransomware scenario registration (about 7 places): `ransomwareScenarioIDs` in `internal/api/rwevidence_dispatch.go`, the corpus lists in `internal/rwevidence`, `internal/rwdetect`, `internal/rwtaxonomy`, `internal/contentregistry`, and `web/src/features/ransomware.js`. Run `internal/api` tests with `-short` (no Docker).
- Re-tagged techniques (T1036.008, T1074.001, T1041) need domain mappings in `internal/rwtaxonomy`; unmapped techniques produce SKIPPED evidence rows.
- Existing lab gates and the irreversible declaration on the VSS stage stay.
- Em-dash footgun in generated strings; Windows PowerShell 5.1.

## Non-goals and honest limits
- No wiring into `internal/backupassurance`: that engine is hard-coded `simulated = true` with a database CHECK, and a real observer needs its own reviewed change. Results flow through normal step results and the existing ransomware evidence rows.
- Nothing runs against real backup repositories except the gated canary. No vendor API calls (no immutability verdict from a vendor name).
- Nothing is lab-verified; the QA log says NOT VERIFIED.

## Approaches
1. Edit YAML by hand (chosen for Part A, small targeted edits) and hand-write Part B steps in the repo's existing style: no generator, since the steps are largely distinct, not repeated.
2. Generator plus shared library (used for the ACL scenario): rejected here because the Part B steps share little logic.
3. One 42-stage Akira scenario: rejected, as you recommended.

## Left to the builder
Exact discovery name lists, reference file set for restore tests, output field names, and the detection profiles attached to new steps.
