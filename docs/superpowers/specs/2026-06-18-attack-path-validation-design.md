# Attack Path Validation — Design / Plan

**Decision:** Build a **native, graph-based Attack Path Validation engine** rather than integrating Infection Monkey. Reference brief: `monkey.txt`. Confirmed direction: native engine.

## Why native over Infection Monkey

Infection Monkey = a Monkey Island server (Python/React) + **self-propagating agents** that scan, attempt credential reuse/exploits, and spread host-to-host. Frictions with our platform:

1. **Self-propagation clashes** with our enrolled, controlled, single-host "dumb executor" agent model — and autonomous spread to non-enrolled hosts is a serious authorization/blast-radius risk in client production (e.g. HDFC) + air-gap. Gating it to a lab AD range removes most of its value.
2. **Duplicate heavy infra** — its own server/agents/state alongside orchestrator + agents + Caldera + Postgres + Chrome.
3. **Weak reporting** (acknowledged by the project) — we'd rebuild it anyway.
4. **Wrong layer** — `monkey.txt` itself ends at "build your own attack-path engine; Monkey becomes just another data source." We can skip straight there.

**We already own ~70% of the inputs:** the agent already does `checkSMB`/`checkWinRM`/`checkRDP`/`adCredential*`/`hostIsDomain`; **SharpHound is already bundled** (art-payloads); the `framework` handler pattern, `ComputeScore`, and the report engine are all extensible. So the native engine is **high-reuse, bank-safe (recon/relationship mapping, no exploitation, no propagation)** — the XM Cyber / BloodHound Enterprise approach, more valuable than Monkey's propagation demo.

## Architecture (customer-facing: "Attack Path Validation")

Agents collect relationship/reachability **edges** → server builds a **graph in Postgres** → computes paths/blast-radius/reachability → **AttackPathScore** → report section + graph visualization. All analytics server-side (intelligence on the server).

## Phases (sequenced for value-per-effort)

- **Phase 0 — prerequisites (do first):** finish the detection-validation loop and ATT&CK coverage expansion (already in motion). Do not start Phase 1 until these land.
- **Phase 1 — Collection:** new deferred agent task `attackpath.collect` — run SharpHound where domain-joined + emit local edges (host↔host SMB/WinRM/RDP, user→host sessions, local-admin, group memberships) as a normalized edge payload. Recon-only; gated by the same authorization + execution-window controls as live runs.
- **Phase 2 — Graph + analytics (server):** store nodes/edges in a `graph` schema; compute shortest path to **Domain Admin**, shortest path to tagged **crown jewels**, **blast radius** per entry host, **reachability** counts (endpoints / critical servers / DCs), **segmentation violations**.
- **Phase 3 — Scoring:** add **`AttackPathScore`** to `ComputeScore`, derived from reachable critical assets · lateral hops · credential weaknesses · segmentation violations · domain-compromise possibility. Sits beside Prevention/Detection/Exposure (the 4th score `monkey.txt` wants).
- **Phase 4 — Report + dashboard:** new "Attack Path Validation" report section (reachability, lateral-movement-risk band, blast-radius funnel, crown-jewel checklist) + a node-graph visualization (Workstation → FileServer → DC) — renders in HTML and the Chrome→PDF pipeline automatically. **Rename** the existing per-host "Attack Path Analysis" (kill-chain phase ordering) → "Kill-Chain Path" to remove the naming collision.
- **Phase 5 — optional, later:** Infection Monkey as a **lab-only** data source feeding the same graph, if a client ever wants true propagation validation in an isolated range. Low priority.

## Safety / authorization

Even native collection touches AD/network (SharpHound, SMB/WinRM enumeration) — recon, lower-risk than exploitation, but still scoped: reuse existing posture/telemetry/lab-mode gating + execution windows + explicit authorization. Never propagates, never exploits.

## Reuse summary

| Need | Already have |
|---|---|
| Edge collection | agent `checkSMB/WinRM/RDP`, `adCredential*`, bundled SharpHound |
| Engine slot | `framework` handler pattern |
| Scoring | `ComputeScore` (+ new `AttackPathScore`) |
| Dispatch/results | deferred-exec task + result pipeline |
| Report/PDF/CSV | report engine + Chrome→PDF + forensic CSV |

Mostly-new work: the edge normalizer, the Postgres graph + path analytics, the score formula, and the graph visualization.
