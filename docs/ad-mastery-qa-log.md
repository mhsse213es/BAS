# AD Mastery QA Log

Last updated: 2026-10-30. Head: `63a30fa7` (DCSync evidence and matrix) plus later fixes.

## Verified (orchestrator, automated)
- DCSync evidence persisted and read back: `f6d3c364`.
- AD matrix reflects real evidence: `63a30fa7`.
- DCSync negative and positive stages keep distinct evidence rows: `45406fc4`.
- `internal/api` suite passed on the head commit.

## Open: needs the Windows agent and a lab domain
- **Agent rebuild (1.9.8):** includes the policy grant CLI (`bas-agent --policy-grant`, `--policy-list`, `--policy-revoke`) and the split DCSync action keys.
- **Staging deploy:** `install.sh --upgrade` on the orchestrator.
- **Grants:** issue `T1003.006:negative` and `T1003.006:positive`, both scoped to `dcsync-replication-rights-live-verification`, on the Windows Server.
- **Live run:** run the scenario from the console and confirm both stages produce `ad_control_verifications` rows, and the matrix moves to `execution_attempted` or `postcondition_verified`.
- **Remaining AD.txt steps:** provisioning real lab objects for the other AD scenarios, lateral movement, and admatrix dashboard wiring.
