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
