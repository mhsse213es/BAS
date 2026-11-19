# SEBI CSCRF-MII Continuous Control Validation: Design

**Status:** approved by the operator on 2026-11-18 with the recommended approach (B) and defaults below.

## Intent
Turn the existing nine-step `cscrf-mii-drill.yaml` into a control-validation vertical that tests whether
MII controls actually work, not just that they are configured. Each control domain is a generated,
signed scenario pack, built with the same pipeline as the Cobalt Group packs.

## Goals
- Correct the nine existing steps where their claim is wider than what they test (per the proposal's correction table).
- Add P0 control-validation packs for network and infrastructure, identity and privileged access, endpoint and audit integrity, and the SIEM telemetry pipeline.
- Tier every step: Tier 1 configuration check, Tier 2 active control test, Tier 3 end-to-end detection and response.
- Record for each step: expected control behaviour, observed behaviour, evidence source, verdict (PASS, FAIL, ERROR, SKIP), cleanup evidence, and a remediation note.

## Non-goals
- No claim of CSCRF compliance from BAS results. BAS validates technical controls only.
- No governance, policy, board or third-party assessment items. Those stay manual.
- No live market infrastructure. MII trading, clearing and settlement are P2 and need simulators.

## Regulatory mapping (default)
- Mappings are **internal control references** (for example `CSCRF-NET-01`), not SEBI clause identifiers.
- A reference is promoted to a SEBI standard identifier only after the operator supplies the circular text and it is checked against it. Until then the drill's existing circular number is treated as unverified.

## Safety rules (default)
- Production-safe scenarios are configuration checks: read-only queries of firewall, logging, Sysmon, time-sync and forwarding state.
- Any step that changes state (firewall rule, Sysmon stop, log clear, forwarding interruption, time change, isolation) is active-tier only, runs only in the isolated lab tier, and needs an explicit environment gate and a verified undo.
- Two-zone segmentation tests are configuration checks until a second isolated zone exists.
- SIEM pipeline tests are configuration checks until a SIEM endpoint is named.

## Approach
One generated pack per control domain, following the Cobalt pattern: `header.yaml`, `stages.json`, `lib.ps1`, per-step `.ps1` and `.undo.ps1`, generated with `appctlgen` (`-common` set explicitly), signed with `orchestrator/scripts/signer.go`. Every step is run live on the build host before signing.

## Priority (from the proposal)
1. P0: network and firewall validation; identity and privileged access; endpoint hardening and audit integrity; SIEM telemetry pipeline.
2. P1: data protection and DLP; incident response and containment; backup and DR.
3. P2: MII trading, clearing and settlement simulators.
4. Dashboard: built after the P0 packs exist, showing per-control coverage, evidence, failures, and controls that cannot be validated by BAS.

## Open items
- Regulatory source text (needed to promote any internal reference).
- Second isolated network zone (needed to promote segmentation tests from configuration checks).
- Named SIEM endpoint (needed to promote pipeline tests).
