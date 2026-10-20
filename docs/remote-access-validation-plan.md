# Remote Access Attack Validation: plan

Status as of 2026-10-20. Based on `capability.txt` (repo root). PAN-OS first, then other VPN vendors. Scope is validation and evidence. Audspect does not exploit production systems and does not replace vendor patches.

## Goal

Answer for one remote-access entry point (a VPN gateway):

1. Is the appliance exposed to a known advisory?
2. Which exposure conditions are present, and which are confirmed absent?
3. Would the organisation's detection stages see the suspicious activity?
4. Does a fix hold after it is applied (retest)?

Every answer carries evidence, a source, and an explicit unknown when the evidence is missing.

## Principles (from the existing codebase)

- Prevention, detection, and response are separate outcomes. They are never merged into one score.
- Unknown is never safe. A missing fact produces an unknown verdict, not a pass.
- Vendor facts come from the advisory the user supplies, not from code. The code never invents an affected version or a fixed release.
- Reuse what exists: `internal/networkpath` and `internal/networktopology` for path reasoning, `internal/remoteaccess` for declared tunnels and bastion rules, the KEV feed in `internal/models/cisakev.go`, and the existing scoring and report flow.
- Agents stay dumb executors. Correlation runs server-side.
- No customer telemetry leaves the deployment. (Product telemetry is parked, see its memory note.)

## Phases

### Phase 1: exposure verdict service (in progress)

- Pure correlation logic in `orchestrator/internal/panosexposure/` (done, `48b2840e`).
- Stateless read-only API: `POST /api/panos-exposure/assess` takes one advisory and a list of PAN-OS assets, returns a verdict per asset. No database writes.
- Done when: API tests pass, RBAC matrix updated, and the route is documented.
- Needs from you: nothing beyond the advisory values (below).

### Phase 2: advisory and asset records (blocked on advisory data)

- Store advisories (CVE, source, affected ranges, conditions) with an import endpoint and audit trail.
- Store PAN-OS asset facts from a config export or manual entry, with per-field source and timestamp.
- Needs: the Palo Alto advisory for CVE-2026-0257 (affected and fixed releases, exact conditions, mitigations). Not entered by me from memory.

### Phase 3: detection and log evidence (blocked on log access)

- Ingest PAN-OS GlobalProtect logs (authentication, session creation, source address, user) through the existing SIEM or log-source path.
- Correlate suspicious successful sessions: unexpected source, unusual time, mismatch with the user's usual pattern.
- Output: a timeline finding with log references and an explicit confidence level.
- Needs: a log source from a lab or staging PAN-OS appliance, or exported logs.

### Phase 4: post-session attack-chain validation (safe simulation)

- Reuse the existing scenario engine and DAG to model the VPN entry point and downstream stages (internal discovery, AD discovery, remote execution, C2-like traffic).
- Run only safe, approved simulations against approved assets. Each stage records whether the SIEM, EDR, and response workflow saw it.
- Output: a stage-by-stage gap report, separate from the exposure verdict.
- Needs: approved test scope, a staging environment, and the phishing and network BAS modules' existing evidence path.

### Phase 5: remediation verification and regression

- After a patch or mitigation, rerun the exposure check and the relevant validation.
- Compare with the previous run and report: fixed, still open, or regressed. Keep the evidence.
- Needs: Phases 1 to 4 running on staging.

## Out of scope for this plan

- Exploiting a production VPN, or any step that establishes real unauthorised access.
- Other VPN vendors. Start after PAN-OS is done end-to-end.
- Attack-surface scanning of external addresses. Needs a written scope and an authorised target list first.
- Replacing the SIEM. Audspect tests whether the SIEM detects, it does not become the detector.

## Blockers and what they need

| Blocker | Needed from | Blocks |
|---|---|---|
| Advisory values for CVE-2026-0257 | Palo Alto advisory, or your confirmation to use the public values | Phase 2 real data |
| PAN-OS appliance or exported config | Your lab or staging environment | Phase 2 real assets, Phase 5 |
| GlobalProtect and identity logs | Log source access | Phase 3 |
| Approved simulation scope | Your written approval per asset | Phase 4 |
| Staging server | Access (currently unavailable) | Phases 3 to 5 |

## Testing

- Unit tests per package, with synthetic fixtures labelled as fixtures.
- No real vendor values in tests until the advisory is supplied and checked against the vendor page.
- Phase 4 and 5 run on staging only.

## Decisions (recorded 2026-10-20)

1. **Advisory source:** the Palo Alto advisory is the source of truth. Ranges in `orchestrator/internal/panosexposure/advisories/CVE-2026-0257.json` were checked against it on 2026-10-20. Unlisted or conflicting facts stay unknown.
2. **Lab access:** a sanitised configuration export is enough to start. A staging appliance is used for end-to-end validation when available. No invented production facts.
3. **Vendor scope:** PAN-OS only through Phase 5. Prisma Access, Cloud NGFW and Panorama are not in scope. Panorama and Cloud NGFW are not affected per the advisory. Do not submit a Panorama device as product `pan-os`.
4. **Log ingestion:** use existing SIEM connectors if they expose the required GlobalProtect events and fields. Otherwise build a dedicated parser behind a common ingestion interface.

Known advisory conflict: PAN-OS 10.2.18 base release. The product-status threshold makes it affected, and the solution table lists it as an upgrade target. It returns unknown until Palo Alto clarifies.
