# Fast, Accurate Simulation Engine — Full-Arc Design

**Status:** Design (approved direction; pending spec review)
**Date:** 2026-06-09
**Author:** Audspect Engineering

**Goal:** Make BAS simulation execution an order of magnitude faster at enterprise scale (target: a full ATT&CK sweep in minutes, fleet content in the tens of thousands) **without sacrificing per-step accuracy** — every step's verdict must be identical to what it would be if the scenario ran strictly sequentially.

**Architecture:** Decouple the *execution model* from *technique content*. Introduce a resource-constraint execution-graph scheduler on the agent (concurrency gated by deterministic isolation locks, not by trust in a label), persistent isolated execution hosts (no per-step process cold-start), a layered timeout/cleanup model, an event-sourced result protocol, and a content scale-out track. Accuracy is enforced by execution constraints and proven by a serial-vs-parallel equivalence harness.

**Tech stack:** Go (orchestrator + agent), PowerShell/cmd execution hosts (Windows-first; `pwsh`/bash slot in later), Postgres (content + run state), gorilla/websocket (dispatch channel).

---

## 1. Decisions locked in brainstorming

| Decision | Choice | Rationale |
|---|---|---|
| Platform scope (v1) | Windows-first, cross-platform-ready | The full ART sweep is Windows; biggest pain. Interfaces designed so `pwsh`/bash hosts add later. |
| Concurrency safety source | Deterministic isolation locks; curated resource metadata is a *hint*, default-to-serial when unlabeled | A wrong/missing label can never corrupt another step; the lock (and serial default) guarantees it. |
| Protocol compatibility | Versioned, capability-negotiated; old agents fall back to today's single-dispatch + final POST | No forced fleet upgrade; mixed fleets work. |
| Accuracy validation | Built-in serial-vs-parallel equivalence harness, wired into CI | "100% accuracy" becomes a checkable invariant, not a claim. |
| Engine architecture | Persistent host pool + classification-gated scheduler + kill/recycle on timeout (Approach 1) | Only option that delivers full speedup *and* preserves per-step isolation + hard timeouts. |

---

## 2. The accuracy model (the spine — read this first)

Correctness is **not** derived from classifying a step correctly. It is enforced by three execution constraints; classification only chooses how wide a lock to take.

1. **Resource isolation (primary).** Every step declares the resource *domains* it touches. Two steps may run concurrently only if their domains do not conflict (see §4 rule). Enforced by per-domain read/write locks held for the step's duration.
2. **Execution isolation.** Each step runs inside an **execution envelope** (pre-clean → execute → capture → post-clean) in a fresh scope, so no variable, module-cache, or ambient-session state leaks between atomics on a shared host.
3. **Deterministic ordering (locks).** Lock acquisition is ordered (canonical sort of lock keys) so the scheduler is deadlock-free and the *observable* outcome of any two conflicting steps is the same as some valid serial order.

**Safety guarantee:** an unlabeled (or mislabeled-narrower) step defaults to a **global write lock** → fully serial → always correct. Classification can only *relax* toward more parallelism for steps proven independent. Therefore accuracy is independent of label quality; labels are a performance optimization.

> Framing: *Safety is enforced by execution constraints; classification only optimizes concurrency.*

---

## 3. Architecture overview (three planes)

```
CONTROL PLANE (orchestrator)
  technique graph (ATT&CK-mapped, existing)
  step resolver  → tags each step with {resourceProfile, timeoutProfile}
  dispatcher     → versioned: streamed batches (new) or single message (legacy)

EXECUTION PLANE (agent)
  scheduler           → queue + resource-lock resolver (the concurrency brain)
  host pool           → N persistent isolated execution kernels (warm PS hosts)
  execution envelope  → per-command sandbox (pre/exec/capture/post-clean)
  timeout supervisor  → 3-layer timeouts + kill/recycle + lock release

TELEMETRY PLANE
  event stream        → StepQueued/Started/OutputChunk/Completed/Timeout/Killed
  scoring + reporting → unchanged (consumes the same per-step results)
```

The control plane already exists in part (`scenario.BuildSteps`, the WS hub). This design adds the resource/timeout tagging, the agent scheduler + host pool, and the event protocol.

---

## 4. Phase A — Execution engine *(implementation-ready)*

The 80% speed win, self-contained on the agent. Windows-first.

### 4.1 Resource profile (the 3-axis model)

Each step carries a `resourceProfile` resolved server-side from curated per-technique metadata:

```go
// internal/scenario (server) and agent wire type
type ResourceProfile struct {
    Domains []ResourceLock `json:"domains"` // resources this step touches
    Scope   string         `json:"scope"`   // "local" | "global"
    Risk    string         `json:"risk"`    // "observation" | "modification" | "persistence"
}

type ResourceLock struct {
    Domain string `json:"domain"` // "registry" | "filesystem" | "process" | "network" | "wmi-secpolicy"
    Key    string `json:"key"`    // optional sub-scope, e.g. a registry hive path; "" = whole domain
}
```

- **Axis A — domain:** `registry`, `filesystem`, `process`, `network`, `wmi-secpolicy`.
- **Axis B — scope:** `local` (a specific path/key) vs `global` (system-wide state, e.g. a policy change).
- **Axis C — risk:** `observation` (read-only), `modification`, `persistence`. Risk maps to lock **mode**: `observation` → read lock; `modification`/`persistence` → write lock.

**Default (unlabeled):** `Domains = [{global,*}]`, `Scope = global`, `Risk = modification` → global write lock → serial. Safe by construction.

### 4.2 The parallelism rule

> Two steps may run in parallel **iff** they share no conflicting lock: for every domain both touch, **both must be `observation`** (read locks). Any `modification`/`persistence` on a shared domain serializes them. A `global`-scope step takes a write lock on a synthetic `*global*` domain, excluding everything.

Implemented as per-`(domain,key)` `sync.RWMutex`: observation → `RLock`, modification/persistence → `Lock`. A step acquires **all** its locks (sorted by key for deadlock-freedom) before executing, releases on completion. This *is* the resource-constraint execution graph — no explicit graph structure needed; the lock set encodes the edges.

Expected parallel gain: **10–25×** (vs 5–10× for a flat 3-class model), because two read-heavy posture checks on the same domain still run concurrently.

### 4.3 Scheduler

New package `agent/sched`:
- A bounded worker pool, `N = runtime.NumCPU()` (configurable, capped).
- A ready-queue; a worker pulls the next step whose lock set is currently acquirable (non-blocking try; otherwise leave queued and take another ready step). This keeps workers busy instead of head-of-line blocking on a contended step.
- Lock manager: a map `(domain,key) → *sync.RWMutex`, created lazily, with ordered acquisition.
- Per-step result recorded the instant it completes (feeds the event stream in Phase B; in Phase A it accumulates as today).

### 4.4 Host pool (persistent isolated execution kernels)

New package `agent/hostpool` (Windows: PowerShell; `cmd` steps use a lightweight per-step process — `cmd` has negligible cold-start, so no pool needed there):
- N long-lived `powershell.exe -NoProfile -NonInteractive -Command -` processes, one bound per worker, kept warm.
- A **command protocol** over the host's stdio: write `<envelope> <command> <sentinel-marker>`; read stdout/stderr until the unique end sentinel; parse the trailing `EXIT:<code>` line. Markers are per-command GUIDs so output framing is unambiguous.
- **Execution envelope** wraps every command:
  ```
  & {
      # pre-clean: fresh scope; clear user vars; reset error state
      $ErrorActionPreference='Continue'; $error.Clear()
      try { <atomic command> }
      finally { # post-clean: remove temp vars/drives this scope created }
  }
  Write-Output "EXIT:$LASTEXITCODE <sentinel>"
  ```
  Prevents variable leakage, module-cache side effects, and hidden state drift across atomics sharing a host.
- **Recycle:** on execution-timeout, host-unresponsive, or protocol desync, kill the host process tree (reuse the existing Job Object tree-kill) and spawn a fresh one. One hang costs one host restart, never a queue stall.

### 4.5 Timeout supervisor (3 layers)

Per-step `timeoutProfile` (resolved server-side, sane per-technique defaults — not a blanket 120s):
```go
type TimeoutProfile struct {
    ScheduleSec int `json:"scheduleSec"` // max wait in queue before forced-serial escalation/abort
    ExecuteSec  int `json:"executeSec"`  // max command runtime (default ~10–15s)
    GraceSec    int `json:"graceSec"`    // cleanup window after kill before host recycle
}
```
- **Schedule timeout:** bounds how long a step waits for its locks; on expiry, escalate (run serially) or record `StepTimeout` — never silently stuck.
- **Execute timeout:** kills the command; the result is an explicit `timeout` verdict (accurate: "ran, did not return"), never a skip or a guess.
- **Grace window:** after kill, allow cleanup; **always release the step's locks** (deferred) and clean zombie handles/temp artifacts so the next step on that domain is uncontaminated. This closes the silent-accuracy hole where lingering registry/file locks corrupt the next test.

### 4.6 Phase A deliverables / file map
- `agent/sched/scheduler.go`, `agent/sched/locks.go` — worker pool + lock resolver.
- `agent/hostpool/pool.go`, `agent/hostpool/envelope.go`, `agent/hostpool/protocol.go` — warm PS hosts + envelope + stdio framing.
- `agent/agent.go` — replace the sequential `for` loop with the scheduler; preserve snapshot/revert and quarantine/state gates.
- `orchestrator/internal/scenario` — resolve and attach `ResourceProfile` + `TimeoutProfile` to each step; new curated metadata source (table or per-technique field) with default-to-serial.
- `orchestrator/internal/db` — content schema for resource/timeout metadata.

---

## 5. Phase B — Streaming protocol + event-sourced log *(design depth)*

### 5.1 Versioned, negotiated protocol
On WS connect (or enroll), the agent advertises `protocolVersion`/capabilities. The server:
- **Capable agent:** streams steps in **batches** (and ships payloads **on demand** by hash rather than inline base64 in one giant message), and the agent posts **incremental** results.
- **Legacy agent:** falls back to today's single `command_scenario` message + single final `/api/scenarios/result` POST. No forced upgrade.

### 5.2 Event-sourced execution log
Replace "batch of results" with an append-only event stream per run:
```
StepQueued → StepStarted → StepOutputChunk* → (StepCompleted | StepTimeout | StepKilled)
```
- Persisted (run-scoped) so a run is **replayable**, supports **partial-failure recovery** (the concurrency guard + this stream mean a crash/cancel keeps everything completed), and drives a **live UI timeline** like the enterprise consoles.
- The existing scoring/reporting consumes the terminal events; no scoring changes required.

### 5.3 Builds on shipped work
The concurrency guard (one run per agent) and the run-status lifecycle already exist; this layers live progress and resilience on top.

---

## 6. Phase C — Scale-out to enterprise volume *(design depth)*

Industry reality (calibrates the strategy): an enterprise "50,000+" library is roughly **70–85% read-only posture + detection validation**, **10–20% lightweight scripted simulation**, **1–5% real exploit-like execution**. The lever is to scale *cheap truth checks*, not expensive detonations.

1. **Read-only assertion library expansion.** Build a large catalog of read-only posture/config/hardening/identity checks on the **existing** `runLocalScan`/`simulate_windows.go` framework. These are `observation`-risk by definition → maximal parallelism under §4 → near-free at scale.
2. **Endpoint sharding.** Fan one logical sweep across many agents; aggregate centrally. Total wall-clock stays flat as fleet/content grows.
3. **Probe dedup / cache.** Identical environment probes (e.g. "is Defender running") asked by many atomics are answered **once per run** and cached; downstream atomics read the cached fact.
4. **Canonical Intent Model (CIM) — the long-term multiplier (forward-looking, not v1).** Store techniques as *intent* ("create persistence → modify registry run key → validate Defender alert") and compile to OS-specific execution at runtime. Enables cross-platform reuse, intent-level **deduplication**, cached execution plans, and reduced execution variance. Flagged as a future track — it is the architectural step that most separates 10× from 50–100× systems, but it is a large effort and **out of scope for the first implementations**.

---

## 7. Accuracy validation harness (spans all phases)

A built-in mode/test that runs a scenario **twice** — once strictly serial (workers=1, locks effectively global), once fully concurrent — and asserts **identical per-step verdicts** (pass/fail/skip/timeout), ignoring wall-clock and ordering.
- Shipped as a Go test fixture (synthetic atomics with known side effects) **and** an operator-runnable diagnostic against a real endpoint.
- Wired into CI as the headline regression: a concurrency change that alters any verdict fails the build. This is what makes "100% accuracy" an enforced invariant rather than a claim.

---

## 8. Data flow (end to end)

1. Operator runs a scenario → orchestrator resolves steps (existing) and **tags each with `ResourceProfile` + `TimeoutProfile`** from curated metadata (default-to-serial when absent).
2. Dispatch: streamed batches (capable agent) or single message (legacy).
3. Agent scheduler enqueues steps; workers execute via the host pool, acquiring resource locks per §4 and running inside the execution envelope under the 3-layer timeout.
4. Each step emits events (Phase B) / accumulates results (Phase A); locks release on completion/kill.
5. Results flow to the existing scoring/reporting unchanged.

---

## 9. Error handling

- **Hung command:** execute-timeout kill → grace cleanup → host recycle → `timeout` verdict → locks released.
- **Host desync/crash:** detected via protocol marker mismatch → recycle host, re-run the in-flight step once, then mark failed if it recurs.
- **Lock starvation:** schedule-timeout escalates a step to forced-serial or records `StepTimeout`.
- **Cancellation/agent crash mid-run:** event stream + concurrency guard preserve completed results (no more "partial/10" total loss).
- **Snapshot/revert:** unchanged; still taken per run and applied at end.

---

## 10. Testing strategy

- **Unit:** lock resolver (read-fan-out, write-exclusion, global-exclusion, default-serial); deadlock-freedom under randomized lock sets; envelope state-reset (no variable bleed); protocol framing + recycle-on-timeout.
- **Integration:** scheduler against a mock host pool with injected slow/hung/crashing steps.
- **Accuracy:** the §7 equivalence harness (the headline test).
- **Performance (informational, not gating):** wall-clock of a representative sweep, serial vs concurrent, to track the speedup.

---

## 11. Sequencing & decomposition

This arc is **three sub-projects**; each gets its own implementation plan when built:
- **Phase A (build first):** agent execution engine — self-contained, no protocol change, biggest win. Includes the equivalence harness.
- **Phase B (next):** streaming protocol + event-sourced log — server + agent, versioned/negotiated.
- **Phase C (ongoing):** content library expansion + sharding + dedup; CIM is a separate future track.

The first implementation plan will cover **Phase A only**.

---

## 12. Out of scope (YAGNI for now)

- Canonical Intent Model implementation (designed-for, not built).
- Linux/macOS host pools (interfaces designed cross-platform; not implemented v1).
- Kubernetes-based execution workers (single-agent host pool first; sharding is agent-level fan-out, not a new control plane).
- Detection-correlation/telemetry-plane analytics beyond what scoring already does.

---

## 13. Risks & open questions

- **PowerShell host protocol robustness** — stdio framing under atomics that themselves write odd output or spawn detached processes. Mitigation: GUID sentinels + recycle-on-desync; the per-step process fallback (Approach 2) remains available if a step is marked "isolate".
- **Resource-domain granularity** — too coarse (everything `registry`) under-parallelizes; too fine risks missing a real conflict. Mitigation: start coarse + correct (whole-domain locks), refine keys per technique as data shows contention; default-to-serial keeps it always safe.
- **Curation cost** — labeling techniques with resource profiles. Mitigation: default-to-serial means unlabeled is correct-but-slow; curate highest-volume techniques first (read-only posture checks give the most parallel benefit).
- **Snapshot/revert vs concurrency** — concurrent mutating steps are serialized by locks, so revert semantics are unchanged; confirm during Phase A implementation.
