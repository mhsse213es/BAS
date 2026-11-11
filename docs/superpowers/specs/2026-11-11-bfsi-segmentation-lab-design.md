# BFSI Segmentation Lab, Phase 1 Design

Status: DRAFT, awaiting approval. Nothing here is built yet.

## Intent

REQ-015 (3 to 4): prove, not just draw, that BFSI network segmentation holds. Audspect sends real probes between security zones, records what the firewall actually did, and gives a verdict backed by that evidence. The existing topology classifier (`internal/zoneisolation`) stays unchanged in this phase.

This phase builds a self-hosted, emulated BFSI network so the logic can be proven end to end before any customer network is involved.

## Goals

- Six zones as isolated Docker networks: Corporate IT, SWIFT secure zone, CDE, ATM management, Core Banking App, Core Banking DB.
- A firewall that enforces explicit allow and deny paths between zones, and logs every decision.
- A probe runner per zone that makes controlled connection attempts.
- A verdict engine that combines probe result and firewall evidence into PASS, FAIL, UNKNOWN or ERROR.
- Scenario packs for SWIFT, CDE/ATM and core banking, each with positive controls.
- Repeatable runs with deterministic expected outcomes.
- Acceptance gates G1 to G6 proven live on staging.

## Non-goals

- No API, database or UI integration in Phase 1. That is Phase 2.
- No changes to `internal/zoneisolation`.
- No customer-network deployment, agents or real firewall vendors. That is Phase 3.
- No claim against the exact POC-19/20/21 text. The criteria here come from the notes provided, which are not the evaluator's own document.

## Zone and network design

| Zone | Docker network | Example service (probe target) |
|---|---|---|
| Corporate IT | `seg-corp` | none (source only) |
| SWIFT secure | `seg-swift` | swift-gateway, TCP 8443 |
| CDE | `seg-cde` | cde-app, TCP 8443 |
| ATM management | `seg-atm` | atm-mgmt, TCP 9000 |
| Core Banking App | `seg-app` | core-app, TCP 8080 |
| Core Banking DB | `seg-db` | core-db (Postgres), TCP 5432 |

- One firewall container, `seg-fw`, attached to all six networks and acting as the router between them. It has IP forwarding on and a default-deny FORWARD policy.
- Explicit ACCEPT rules are added only for the authorized paths. Each rule carries a rule ID in its LOG prefix.
- Fixed subnets and fixed container IPs, so every run is identical.
- Each probe runner sits on exactly one zone network. It can reach other zones only through `seg-fw`.

## Probe interface

Provider-independent, so the same scenario executor can later run against Docker labs, Linux VMs or customer agents.

```go
type Provider interface {
    Healthy(ctx context.Context, zone string) error
    Probe(ctx context.Context, req ProbeRequest) (ProbeResult, error)
    FirewallEvents(ctx context.Context, window TimeWindow) ([]FirewallEvent, error)
}
```

- `ProbeRequest`: source zone, destination zone, destination host, port, protocol, timeout, expected outcome (`allow` or `deny`).
- `ProbeResult`: outcome (`connected`, `refused`, `timeout`, `probe_unavailable`), start and end timestamps, and source and destination endpoints.
- `FirewallEvent`: timestamp, rule ID, action (`ACCEPT`, `DROP`, `REJECT`), source and destination IP and port, protocol.

The Docker provider implements this first. It runs probes with `docker exec` into the zone's probe runner and reads firewall events from the log file inside `seg-fw`.

## Evidence and attribution

A probe result is matched to firewall evidence by source IP, destination IP and port, protocol, and a timestamp window around the attempt. The firewall log is what proves enforcement. A probe result alone never does.

## Verdict rules

| Condition | Verdict | Gate |
|---|---|---|
| Expected deny, connection succeeded | FAIL | G1 |
| Expected deny, firewall log shows a DROP or REJECT for this probe | PASS | G2 |
| Expected deny, timeout or refusal with no matching firewall evidence | UNKNOWN | G3 |
| Probe or destination unavailable (failed health check or probe cannot run) | ERROR | G4 |
| Expected allow, connection succeeded and firewall shows ACCEPT | PASS | G5 |
| Firewall log unavailable or unreadable | UNKNOWN, never PASS | G6 |
| Expected allow, connection did not succeed | ERROR (positive control broken) | my call |

Verdict rules are a pure function of the probe result and the firewall events. They are unit-tested without Docker.

## Scenario packs

Each pack is a fixed matrix of probes. Every pack includes positive controls.

- **SWIFT isolation:** corp to swift (deny), swift to corp endpoint (deny), corp to swift on the allowed path if one is defined (allow).
- **CDE and ATM isolation:** corp to cde (deny), corp to atm-mgmt (deny), app to cde (deny).
- **Core banking tiering:** corp to core-db (deny), app to core-db port 5432 (allow), app to core-db on a non-authorized port (deny), user network to core-db (deny).

Each pack is run multiple times, and a result counts only if every run agrees.

## Repeatability

- Image digests pinned, as in the WAF lab.
- Firewall rules reset to the scenario's rule set at the start of every run.
- Fixed IPs, ports and timeouts.
- Each run records its own time window so firewall events from other runs are never matched.

## Location and deployment

- Lab files under `lab/segmentation/`, mirroring `lab/wafmodsec/`.
- Go code under `internal/segprobe/`, with the provider interface, probe executor, evidence matcher and verdict engine.
- Live runs on staging (`audspect-staging`) as a compose project separate from the existing services. The lab publishes no host ports except what the runner needs.
- Live tests are gated by an environment variable, so `go test ./...` on the build host stays fast and does not need the lab.

## Acceptance gates

Phase 1 is done when, on staging:

- G1: a deliberately opened prohibited path produces FAIL.
- G2: a denied probe with a firewall DROP or REJECT produces PASS.
- G3: a denied probe with no firewall evidence produces UNKNOWN.
- G4: a stopped destination produces ERROR.
- G5: an authorized probe produces PASS.
- G6: a lab with firewall logging disabled produces UNKNOWN for every probe, never PASS.
- Every scenario pack runs three times with identical verdicts.
- Unit tests for the verdict engine and evidence matcher pass on the build host.

## My calls (override if you disagree)

- Central router firewall (one container) rather than one firewall per zone. It keeps the lab small and still shows every decision.
- DROP for denied traffic in the lab, with REJECT used in one scenario so both code paths are covered.
- Positive-control failure is ERROR, not FAIL. A broken allowed path means the test cannot validate segmentation.
- Probes are Go binaries running in each zone's runner container, so the same probe code can later run on agents.

## Open questions for approval

- Are the six zones and the example services acceptable as the lab's shape?
- Should the lab use a dedicated subnet range on staging, or does a range need to be checked against the existing staging networks first?
