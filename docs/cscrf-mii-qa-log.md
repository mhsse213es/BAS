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
