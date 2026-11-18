# CSCRF-MII Control Validation - QA Log

Internal control references (`CSCRF-*`) are not SEBI clause identifiers. Passing a BAS check does not establish CSCRF compliance.

## P0 Task 1: drill correction (`cscrf-mii-drill`)

Nine steps renamed so each name states what the step tests. The `CSCRF-x.y` labels are unchanged, so the coverage matrix still parses them.

| Old name | New name |
|---|---|
| Management Port Scan | Localhost Management-Port Reachability (localhost only, not perimeter) |
| Failed Auth Probe | Failed-Logon Telemetry Probe (nonexistent account, no password guessing) |
| System Discovery Recon | OS and Build Discovery (read only, no baseline comparison yet) |
| Audit Policy Enumeration | Audit Policy Read (read only, no modification) |
| Local Group Enumeration | Administrators Group Membership Read (read only, no privileged-change test) |
| Local Account Create + Delete | unchanged name; residue FAIL added |
| WinRM Lateral Movement Probe | Localhost WinRM Reachability (not lateral movement) |
| Audit Log Tamper Attempt | Security Log Clear Attempt (outcome recorded: denied, cleared or ambiguous) |
| SYSTEM Scheduled Task | SYSTEM Scheduled Task Registration (registration only, task not executed) |

Changes beyond renaming:
- **Account step:** FAIL if the synthetic account survives cleanup (residue check).
- **SYSTEM task step:** FAIL if the task survives cleanup. Only registration is validated; execution context is not.
- **Security log clear:** kept on the real Security log on purpose, gated by `BAS_CONFIRM_LOG_CLEAR=true`. Without the flag it SKIPs. The verdict logic was already correct and is unchanged.
- **OS discovery:** no baseline comparison is implemented yet. The step reports values only.

Live runs on this host (gates off): all nine steps ran. Account and task residue check: zero leftover `BAS-SIM-*` accounts and scheduled tasks. Administrator on this host could create both, so the account and task steps FAIL. That is the correct control outcome for this host.

Suite: `go test ./internal/scenario -count=1 -timeout 420s`: ok, 294.9s.

Note: an earlier run of this suite failed on the step-contract ledger (934 vs 942 steps). The cause was an unsigned network-pack YAML that was in `scenarios/` while the suite was running. It was held out of the repo, and the rerun passed clean.

Honest limits: no SEBI clause mapping. No second network zone, no SIEM endpoint. No governance validation.

## P0 Task 2: network and infrastructure pack (`cscrf-mii-network`)

Eight steps, internal labels CSCRF-NET-01..08. Live verdicts from this host:

| Step | Verdict | Basis |
|---|---|---|
| net-01 Lab subnet management-port reachability (CSCRF-NET-01) | SKIP | `BAS_LAB_SUBNET` unset. Accepts only a private /26 to /30 (at most 62 hosts). |
| net-02 Firewall rule inventory (CSCRF-NET-02) | PASS | 515 enabled rules, 302 inbound allow |
| net-03 Firewall profile policy state (CSCRF-NET-03) | PASS | Read only. All three profiles enabled, none explicitly allows inbound by default. |
| net-04 Listening service inventory (CSCRF-NET-04) | PASS | 49 listeners; no FTP or Telnet listener on all interfaces |
| net-05 DNS resolver configuration (CSCRF-NET-05) | PASS | Resolver configured on every up adapter. No approved-resolver baseline compared. |
| net-06 Cross-zone segmentation probe (CSCRF-NET-06) | SKIP | `BAS_ZONE2_TARGET` unset |
| net-07 Telnet to lab target (CSCRF-NET-07) | SKIP | `BAS_LAB_TARGET` unset |
| net-08 Egress to documentation address (CSCRF-NET-08) | PASS | 192.0.2.1:443 not established (RFC 5737, not routed) |

Rulings:
- **net-03 is read-only.** The plan's active firewall modification is deferred. A safe modify-and-restore test is not built in this pass.
- **net-03 default-action check.** The first version failed this host. Live values showed all profiles `NotConfigured`, which I first treated as non-default-deny. Windows applies its built-in inbound Block when no default is set, so the check now fails only on an explicit `Allow` or a disabled profile. The first version's failure was a bug in my check, not a control gap.
- **net-05 has no baseline.** It confirms a resolver is configured and nothing more.

Catalog: eight entries added inside existing technique blocks (T1046 x3, T1016 x2, T1562.004 x1, T1571 x2). All classes are non-destructive. `execclass_embed_test.go` pins: 3696 to 3704 entries, 246 to 254 hand-authored, hash `2d14e25c74df10fc3867be499ea4ba473cf9c0fa09fc45f9c9ca34957c071b2a`. `gofmt` realigned one existing line in the same block (whitespace only).

Step-contract ledger regenerated with `STEP_CONTRACT_WRITE=1`. The diff is additions only (77 insertions).

Limits: net-01, net-06 and net-07 probe other hosts and run only when their env variables are set. Lab hosts are needed for those verdicts. Honest limits: no SEBI clause mapping, no second network zone, no governance validation.

Suite: `go test ./internal/scenario -count=1 -timeout 420s`: ok, 294.6s.

## P0 Task 3: identity and privileged access pack (`cscrf-mii-identity`)

Eight steps, internal labels CSCRF-ID-01..08. id-09 (remote privileged login) is **deferred**: it needs a second lab host.

Gate off (`BAS_CONFIRM_IDENTITY_CHANGE` unset) on this host:

| Step | Verdict | Basis |
|---|---|---|
| id-01 Privileged group membership change (CSCRF-ID-01) | SKIP | gate not set |
| id-02 Local administrator account creation (CSCRF-ID-02) | SKIP | gate not set |
| id-03 Privileged logon monitoring (CSCRF-ID-03) | PASS | 237 logon events (EID 4624) in the last 24h |
| id-04 Excessive Administrators membership (CSCRF-ID-04) | SKIP | `BAS_ADMIN_ALLOWLIST` unset |
| id-05 Disabled account logon attempt (CSCRF-ID-05) | SKIP | gate not set |
| id-06 Local password policy baseline (CSCRF-ID-06) | FAIL | minimum password length 0, baseline 12 |
| id-07 MFA enforcement (CSCRF-ID-07) | SKIP | no identity provider integrated |
| id-08 Service account administrator rights (CSCRF-ID-08) | PASS | no non-built-in service account is an Administrators member |

Gate on (`BAS_CONFIRM_IDENTITY_CHANGE=true`), each followed by its undo:
- id-01 FAIL: adding the synthetic account to Administrators succeeded and was reverted. Verify the EID 4732 alert in the SIEM.
- id-02 FAIL: a new account placed in Administrators. Verify EID 4720 with 4732 in the SIEM.
- id-05 PASS: the disabled synthetic account was refused (Win32 error 1331).
- All three undos PASS. Zero residue users or undo records. Administrators membership unchanged.

Ruling: id-01 adds an account created in the same step. It FAILs when the change succeeds, matching the drill's account-create rule.

Catalog: eight entries (T1098, T1136.001, T1078 x4, T1078.003, and a new T1201 block). Destructive: `cscrf_id_priv_group_change`, `cscrf_id_local_admin_create`, `cscrf_id_disabled_logon`. Pins `execclass_embed_test.go`: 3704 to 3712 entries, 254 to 262 hand-authored, hash `df0377009a5c34407d0c6f11742a514375a38815ea66e1ec532b4a35272b2cfd`.

Ledger: the identity ledger entries were already in HEAD, committed inside `0ac138ba` (another session's pass-the-hash commit, which picked up this working tree's uncommitted ledger). This commit adds the matching YAML, sources and catalog.

Working-tree note: the main working tree carried another session's uncommitted `T1187` catalog hunk in `execclass.go`. It changes the ledger class for `ad-forced-auth-attempt` from destructive to non-destructive, so the ledger test fails in the main tree. That hunk is not part of this commit. The suite was verified in a clean worktree at HEAD with only these identity changes.

Suite: `go test ./internal/scenario -count=1 -timeout 420s` in the clean worktree: ok, 311.4s.

## P0 Task 4: endpoint hardening and audit integrity pack (`cscrf-mii-endpoint-audit`)

Ten steps, internal labels CSCRF-EA-01..10. Read-only steps ran live on this host (gate off). Gated steps ea-09 and ea-10 were **not** verified live. They need a lab VM.

Live results on this host (read only):

| Step | Verdict | Basis |
|---|---|---|
| ea-01 Security patch currency | FAIL | newest update KB5071959 is 360 days old (baseline 60) |
| ea-02 Supported operating system | FAIL | Windows 10 Pro build 19045 past end of mainstream support (2025-10-14), no ESU recorded |
| ea-03 Defender real-time protection | FAIL | real-time protection off; confirmed with Get-MpComputerStatus |
| ea-04 PowerShell script block logging | FAIL | not enabled by policy |
| ea-05 Sysmon presence and running | FAIL | Sysmon not installed |
| ea-06 Unnecessary services | PASS | no disallowed service running (Telnet, FTP, TFTP, Remote Registry, SNMP, Simple TCP/IP) |
| ea-07 Weak local configuration | PASS | SMB1 off, Guest disabled, UAC on |
| ea-08 Application control presence | FAIL | no effective AppLocker rules |
| ea-09 Unauthorised execution from temp path | SKIP | gate off; NOT verified live |
| ea-10 Audit policy change attempt | SKIP | gate off; NOT verified live |

Deferred to a lab VM (changes security tooling, not safe on the build host): real-time protection impairment, dedicated log clear, Sysmon service stop.

Rulings:
- **ea-10 restores in the same run.** The Process Creation setting is restored inside the step as well as in undo, so a failed undo cannot leave auditing off. The record stays for undo to re-apply the same value.
- **ea-10 with auditing already off** returns ERROR and makes no change, because the baseline is unusable.
- **ea-02 is a lifecycle baseline check.** It passes Windows 10 only with `BAS_ESU_ENROLLED=true`.

Catalog: ten entries. T1082 x4 (read-only), T1562.001 x2 (read-only), T1543.003 x1 (read-only), T1562.003 new block x1 (read-only), T1562.002 x1 (`cscrf_ea_audit_policy_change`, destructive), T1204.002 new block x1 (`cscrf_ea_unauthorized_exec`, potentially destructive). Pins `execclass_embed_test.go`: 3712 to 3722 entries, 262 to 272 hand-authored, hash `52241627be3d2453f5c05217d9578d88ecbb880166d0ab43a8cfdef88925c9c6`.

Ledger regenerated; diff is additions only (95 insertions, 0 deletions).

Drill signature fix: see commit `5915e509` (re-signed over committed bytes).

Suite: `go test ./internal/scenario -count=1 -timeout 420s` in a clean worktree at HEAD plus these changes: ok, 335.1s.

## P0 Task 4: gated steps run on the lab VM

Run by the operator on the lab VM (Windows, hostname WIN-2IP8FNO4MAD), in an elevated PowerShell with `BAS_CONFIRM_ENDPOINT_CHANGE=true`. Each step was followed by its undo.

- **Baseline:** Process Creation auditing was `No Auditing`. The test needs a non-off baseline, so the operator enabled Success auditing first. This was an approved change for the lab run.
- **ea-09 (unauthorised execution from temp path), gate on:** FAIL. A renamed copy of cmd.exe ran from a temp path with no execution control applied. Undo: PASS (Cleanup complete). Residue check: no `bas-ea-*` folder and no undo record left.
- **ea-10 (audit policy change attempt), gate on:** FAIL. Disabling Process Creation auditing was not refused. The step restored the setting in the same run, and the step reports the EID 4719 alert should be verified in the SIEM. Undo: PASS (Cleanup complete).
- **After the run:** the operator set Process Creation auditing back to `No Auditing`, the state found at the start.

Rulings:
- The ea-10 step restores the setting in-run as well as in undo. A failed undo therefore cannot leave auditing off on the lab VM.
- The operator, not the agent, decided to switch auditing on for the test. The original state was restored after the run.

Still open: the deferred lab-only steps (real-time protection impairment, dedicated log clear, Sysmon service stop). Also, the EID 4719 alert for ea-10 has not been checked in a SIEM, because this lab has none configured.

## P0 Task 5: SIEM telemetry pipeline configuration checks (`cscrf-mii-siem`)

Three configuration checks, internal labels CSCRF-SIEM-01, 02 and 04. All read only. Each raw value was confirmed directly on the build host (w32tm, the policy registry key, and `Get-WinEvent -ListLog Security`).

| Step | Verdict | Basis |
|---|---|---|
| siem-01 time source | FAIL | source is `Local CMOS Clock`, not a network source |
| siem-02 Windows Event Forwarding subscription manager | FAIL | no subscription manager configured |
| siem-04 Security log retention | FAIL | 20 MB in circular mode; baseline is at least 1 GB and not circular |

Deferred: **siem-03 ingestion verification.** It needs a named collector endpoint and its query API. Until then, nothing here shows that an event reached the SOC or was acted on. The lab VM (192.168.10.150) is the endpoint these checks describe; it has not been run there yet.

Catalog: three entries, all non-destructive. `cscrf_siem_time_sync` (T1070.006, new block), `cscrf_siem_log_retention` (T1070.001), `cscrf_siem_forwarding_config` (T1562.002). Pins `execclass_embed_test.go`: 3722 to 3725 entries, 272 to 275 hand-authored, hash `9185f4d80e1cd33397f1671f7d71b538f2757be175bdf858c98bbbd91f570102`.

Ledger regenerated; additions only.

Suite: `go test ./internal/scenario -count=1 -timeout 420s` in a clean worktree at HEAD plus these changes: ok, 372.5s.

## P1: backup, recovery and DR configuration checks (`cscrf-mii-backup-dr`)

Five steps, internal labels CSCRF-BDR-01..05. Live results on the build host:

| Step | Verdict | Basis |
|---|---|---|
| bdr-01 backup present | FAIL | no backup version on the build host (`wbadmin: No backup was found`) |
| bdr-02 recovery point age | FAIL | no recovery point, so the RPO is undefined |
| bdr-03 restore integrity, synthetic data (gated) | PASS | synthetic 1 MB file restored from its copy with a matching SHA256 |
| bdr-04 restore time, synthetic data (gated) | PASS | file-level restore took 0.01 s against a 900 s budget |
| bdr-05 DR site connectivity | SKIP | `BAS_DR_TARGET` unset |

The gated steps (bdr-03, bdr-04) ran on the build host against temp files only. Their undos reported PASS, and no residue was left.

**Scope of the restore checks:** file-level only. They prove that a synthetic file can be copied and restored with matching bytes. They do not prove a system restore.

**Defect found and fixed during the run:** the library was missing its undo-record helpers. The step ran, but its undo record was never written, so the undo had nothing to act on and left two temp folders behind. The helpers are now in the pack, and the leftover folders were removed.

Deferred: DR SOC monitoring and recovery after a simulated incident. Neither is built.

Not validated: business RTO and RPO targets, a real restore of a backup set, and backup integrity beyond recovery point age.

Catalog: five entries. T1490 x4 (`cscrf_bdr_backup_available`, `cscrf_bdr_rpo_age` non-destructive; `cscrf_bdr_restore_integrity`, `cscrf_bdr_rto_measure` potentially destructive) and T1046 x1 (`cscrf_bdr_dr_connectivity`, non-destructive). Pins `execclass_embed_test.go`: 3725 to 3730 entries, 275 to 280 hand-authored, hash `3c8323da5aa16bec9ad516a25eabbb6c9a1f67ca4aad7e382ef2cd3747ae812a`.

Ledger regenerated; additions only.

Suite: `go test ./internal/scenario -count=1 -timeout 420s` in a clean worktree at HEAD plus these changes: ok, 339.3s.

## P1: incident detection, containment and evidence checks (`cscrf-mii-incident-response`)

Four steps, internal labels CSCRF-IR-01, 03, 04, 06. Live results on the build host:

| Step | Verdict | Basis |
|---|---|---|
| ir-03 outbound block capability | FAIL | no enabled outbound block rule on the build host (read only) |
| ir-06 Security log evidence export | PASS | Security log exported (20.1 MB); export removed in undo, zero residue |
| ir-01 malware detection, EICAR (gated) | SKIP | gate off; not run live (it would write a test file under Defender, not approved on this host) |
| ir-04 compromised account disablement (gated) | SKIP | gate off; not run live (it would create and disable a local account, not approved on this host) |

The gated steps are verified by reading their code only, including their undos. Defender behaviour under EICAR has not been observed.

Defect found during the live run: ir-03 reported ERROR when no block rule existed. An empty result is a real gap, so the step now reports FAIL. ERROR is reserved for a firewall service that cannot be queried.

Catalog: four entries. T1204.002 (`cscrf_ir_malware_detect`, potentially destructive), T1562.004 (`cscrf_ir_block_capability`, non-destructive), T1078 (`cscrf_ir_account_disable`, destructive), T1070.001 (`cscrf_ir_evidence_export`, non-destructive). Pins: 3730 to 3734 entries, 280 to 284 hand-authored, hash `af0f3845156803b194ba86aa495cf9c3a726b38dc7117af30684faf2126dc938`.

Ledger regenerated; additions only.

Suite: `go test ./internal/scenario -count=1 -timeout 420s` in a clean worktree at HEAD plus these changes: ok, 341.1s.

## P1: data protection and DLP configuration checks (`cscrf-mii-data-protection`)

Five steps, internal labels CSCRF-DP-01..06. Live results on the build host:

| Step | Verdict | Basis |
|---|---|---|
| dp-01 volume encryption at rest | FAIL | C: is fully decrypted; BitLocker protection is off |
| dp-02 data path ACL exposure | SKIP | `BAS_DP_PATH` unset |
| dp-03 SMB encryption and SMB1 | FAIL | SMB encryption not required (EncryptData false) |
| dp-04 DLP agent presence | SKIP | `BAS_DLP_SERVICE` unset; no DLP product named |
| dp-05 marker egress to named share (gated) | SKIP | gate off; not run live (it needs a named share and `BAS_CONFIRM_DP_TEST=true`) |

Deferred: DLP detection and blocking of the synthetic marker (CSCRF-DP-06). That needs a named DLP product and policy.

The marker step writes one synthetic string with no real data. Its undo deletes the file. Its code is verified by reading only.

Catalog: five entries. T1005 (`cscrf_dp_bitlocker`, non-destructive), T1083 (`cscrf_dp_data_acl`, non-destructive), T1040 (`cscrf_dp_smb_encryption`, non-destructive), T1562.001 (`cscrf_dp_dlp_service`, non-destructive), T1048 (`cscrf_dp_marker_egress`, potentially destructive). Pins: 3740 to 3745 entries, 290 to 295 hand-authored, hash `c89c07fef71f1e4b893d777133ce42c9c86f2242d6801c651ef613d793ade6fe`.

Suite: `go test ./internal/scenario -count=1 -timeout 420s` ran ok at 413.5s on the second attempt. The first attempt hit the 7-minute timeout inside unrelated AppControl and APT36 tests with no failing assertion. The second run passed.
