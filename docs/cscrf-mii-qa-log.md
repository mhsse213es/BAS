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
