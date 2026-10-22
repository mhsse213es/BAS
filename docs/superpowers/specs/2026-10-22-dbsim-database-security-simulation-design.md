# Database Security Simulation (`dbsim`) — Design

Date: 2026-10-22 · Source brief: `DAM_BAS.txt` (repo root) plus the technical design reviewed in session.
Status: DRAFT — pending builder check and user approval.

## 1. Intent and why

Audspect is a BAS tool: it proves whether security controls work. Databases are where regulated data lives (BFSI, NBFC, healthcare, manufacturing targets) and today Audspect has no way to test the database layer's own controls. A DAM tool *monitors* database activity; this capability *tests* whether database defenses prevent, record and surface risky actions, and whether the customer's DAM/SIEM actually raises an alert. It complements DAM; it never replaces it, and it is not a vulnerability scanner or pen-test platform.

## 2. Goals, non-goals, anti-goals

Goals
- A scenario engine (`internal/dbsim`) with PostgreSQL and MySQL adapters.
- Probes executed **by the agent** (decided by user) against databases it can reach.
- Evidence-based results: a detection is credited only when a real DAM/SIEM alert is retrieved and correlated to the probe.
- Results rendered as `dlpreport.Record` with prevention / detection / response kept separate.
- Lab-first; then a narrow read-only client pilot.

Non-goals (first release)
- SQL Server, Oracle, cloud-managed DBs (RDS/Azure SQL/Cloud SQL).
- Production mutation, destructive attack simulation, password spraying/guessing, auto-remediation or auto-revoking grants.
- Running SQL-injection payloads from the DB module (belongs to the WAF/API test path; DB module may only correlate DB-side evidence of an approved app test).
- Automatic containment without an existing integration.

Anti-goals (failure even if it "works")
- Any green result that is inferred rather than evidenced (a successful query run is not a detection).
- Any mutating action reaching a client database.
- A second, parallel verdict taxonomy.
- Real PANs or customer records in fixtures, logs or reports.

## 3. Verified facts about the existing code (2026-10-22)

| Area | Fact | Consequence |
|---|---|---|
| `internal/dlpreport` | `Record` has four enums: `EnforcementOutcome`, `ClassificationOutcome`, `TelemetryOutcome`, `ResponseOutcome`, plus `EvidenceProvenance`, `Limitations`; `Validate()` requires Limitations when a dimension is uncertain. Enforcement/Telemetry/Response are caller-supplied by design. | dbsim is the caller. Mapping in §7. Reuse, do not extend, the enums unless a value is genuinely missing. |
| PASS/FAIL/ERROR/SKIPPED | Lives in scoring layers (`killchain/verdict.go`, `models.Result*`), not in `dlpreport`. | dbsim emits both: a `Record`, and a scoring-layer result for run pipeline integration (§7). |
| `internal/dlpcorrelate` | Sequences already-computed verdicts (`StageResult`); **no connector queries, no marker/time-window matching**. | Not the correlator. Marker correlation is new (`dbsim/correlation.go`). dlpcorrelate may be used afterwards to chain stages (e.g. prevention → detection) if useful. |
| `internal/siem/correlator.go` | QRadar only; source-IP + time window; technique verdict. | Not reused for DB. |
| `internal/detectverify` | 7 connectors (Sentinel, Defender XDR, Splunk, QRadar, CrowdStrike, Trellix, Elastic) behind `Connector.Verify(VerifyRequest)`; request = host/IP/technique/time window; result keeps `MatchedAlert.RawJSON` and `DetectionLatency`. No marker field. | Reuse unchanged. dbsim post-filters returned alerts for the probe marker (§6). |
| `internal/dlpfixture` | Holds DLP content strings (e.g. a PostgreSQL connection string); no seeded-table fixtures. | DB fixtures with create/cleanup are new (`dbsim/fixtures`). May draw synthetic value patterns from dlpfixture. |
| Agent | `agent/go.mod` has no DB drivers; executors only dispatch shell types (`sh`, `cmd`, `wmi`, `schtasks`, …). Orchestrator already has `jackc/pgx/v5`; no MySQL driver anywhere. | New native step type in the agent; add `pgx/v5` and `go-sql-driver/mysql` (pure Go, no cgo) to the agent. |
| Scenario signing | `.sig` per scenario; `scenario/execclass*.go` classifies exec classes. | Reuse for dbsim scenarios; **re-sign after any edit** (known trap). |
| "DLP-DB channel" | Not found by grep as a named thing. | Treat as non-dependency. Builder to confirm and reuse if it exists under another name. |

## 4. Architecture

```
Orchestrator: scope approval, scenario selection, dispatch, deadlines, scoring, reports
   │  signed dbsim scenario + probe spec (credential REFERENCE, never secret)
   ▼
Agent (dumb executor): verify .sig → local gate checks → native "dbprobe" step
   │  uses embedded drivers via internal dbsim-agent package; returns raw ProbeResult + audit slice
   ▼
Target DB (PostgreSQL / MySQL)         DAM / SIEM (customer)
   ▲                                       │ queried by orchestrator via detectverify connectors
   └───────────── orchestrator correlator ─┘  (marker post-filter) → dlpreport.Record
```

Trust boundary: the server decides authorization, scenario selection and scoring. The agent enforces execution limits locally as a second layer and never scores. Agent-reported audit evidence is evidence, not truth: where possible the orchestrator also pulls audit/alert data from the monitoring side independently.

### 4.1 Package layout

Shared (orchestrator and agent both import; contains no scoring):
- `internal/dbsim/` — `types.go` (Role, Grant, Probe, ProbeResult, AuditEvent, Fixture), `adapter.go` (interface + registration), `scope.go`, `budget.go`, `cleanup.go`.
- `internal/dbsim/postgres/`, `internal/dbsim/mysql/` — adapters; each declares its supported operations and audit sources. Unsupported → SKIPPED, never a pass.
- `internal/dbsim/fixtures/` — deterministic synthetic datasets + cleanup manifests.

Orchestrator-only:
- `internal/dbsim/policy.go` — least-privilege policy diffing (customer-supplied policy).
- `internal/dbsim/correlation.go` — marker correlator over `detectverify` results.
- `internal/dbsim/report.go` — rendering to `dlpreport.Record` and scoring-layer result.

Because the agent module is separate (`module audspect/agent`) from the orchestrator (`github.com/audspect/bas`), the builder must decide how shared code is placed (see §10, builder decision B1). The agent must not import orchestrator internals.

### 4.2 Adapter interface (illustrative)

```go
type Adapter interface {
    Connect(ctx context.Context, cfg ConnectionConfig) error
    EnumerateRoles(ctx context.Context) ([]Role, error)
    ReadGrants(ctx context.Context) ([]Grant, error)
    RunProbe(ctx context.Context, p Probe) (ProbeResult, error)
    CollectAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, error)
    Cleanup(ctx context.Context, f Fixture) (CleanupResult, error)
    Capabilities() Capabilities // supported probes + audit sources; drives SKIPPED
    Close() error
}
```

Do not paper over PostgreSQL/MySQL differences; expose them via `Capabilities()`.

### 4.3 Agent step type

A new native step kind (`dbprobe`) beside the existing shell kinds. Payload: engine, target identity, credential reference, probe id, limits, marker, fixture id. The agent: verifies the scenario signature, checks local execution policy (mode, class, budgets), resolves the credential via the existing secret mechanism, runs the probe, returns structured results. It must not accept arbitrary SQL from the server beyond the signed scenario's declared probes.

### 4.4 Credentials

Server stores references only. Agent resolves at execution; TLS with certificate verification; dedicated least-privilege test identity (client mode: read-only DB role that cannot write, alter schema, administer accounts or touch audit settings); secrets redacted from logs/reports. The exact secret-resolution mechanism is a builder discovery item (B2).

## 5. Scenario catalog (first release)

Each scenario declares: id, version, engine, `class` (`read_only` | `bounded_synthetic` | `mutation`), prerequisites, allowed operations, expected prevention/detection behavior, required evidence, limits, cleanup obligations. Format must match the existing signed-scenario format; the YAML below is conceptual.

| ID | Test | Modes | Phase |
|---|---|---|---|
| DB-01 | Authentication policy (policy inspection + controlled auth checks; no guessing/spraying) | lab, client | 2 |
| DB-02 | Excessive grants vs customer-declared least-privilege policy (effective privileges, role inheritance, ownership; report diff + policy source; never revoke) | lab, client | 2 |
| DB-03 | Unauthorized table/column access | lab; client read-only where appropriate | 2 |
| DB-04 | Audit coverage (config, test event, log availability) | lab, client | 3 |
| DB-05 | Suspicious-read detection (event + correlated alert) | lab | 4 |
| DB-06 | Account revocation (revoked identity denied on a new connection) | lab | 5 |
| DB-07 | Synthetic sensitive-data classification | lab | 5 |
| DB-08 | Audit-config tampering resistance (restricted account is denied; actual disablement lab-only with recovery plan) | lab | 5 |
| DB-09 | Bounded bulk-read detection (row-capped synthetic read) | lab | 4 |
| DB-10 | Unauthorized write/delete prevention (verified fixture-state + cleanup) | lab only | 5 |
| DB-11 | Backup/export permissions (privilege/config checks; controlled op only if authorized) | lab | 5 |
| DB-12 | Cross-system trust (links/federation) | lab; later release | post-1.0 |

Credential hygiene: empty/weak credential *policy* via inspection; password reuse is not provable from DB metadata → SKIPPED unless an identity-management evidence source exists.

## 6. Correlation and timing

- Every probe carries `run_id` + a unique action marker, propagated where the engine supports it (query comment, `application_name` for PostgreSQL, equivalent session attribute for MySQL). Do not assume an audit plugin preserves comments or session metadata; the adapter's `Capabilities()` states what is preserved.
- Orchestrator flow after the agent reports: (1) obtain host-and-window alerts from the configured `detectverify` connector (`VerifyRequest` with agent host/IP, window around probe execution); (2) `dbsim/correlation.go` filters `MatchedAlert.RawJSON` for marker, DB principal, target and run id; (3) grade `exact_marker | strong_contextual | ambiguous | none`.
- Detection is credited only for exact or strong matches within the scenario's detection window, **and** only if the probe ran and the monitoring source was reachable/healthy. Otherwise: connector down → Telemetry `Unverifiable`; no match with healthy source → `Absent`; match after deadline → `Delayed`.
- Concurrent runs must not cross-correlate (unique marker + principal + window; ambiguous matches never credit).
- Metrics: time-to-detect (alert time − probe execution time; reuse `DetectionLatency`), time-to-contain only when a real containment integration is enabled.
- Known limitation: if the customer's DAM/SIEM does not surface query text or session attributes in alert raw data, marker matching cannot succeed and the result is `Unverifiable` with an explicit Limitations note. This is reported, not hidden.

## 7. Result model

Render each scenario execution as one `dlpreport.Record`:

| Dimension | Record field | Source |
|---|---|---|
| Prevention | `Enforcement` (`Blocked` / `Allowed` / `Unknown`) | probe result (denied vs succeeded) |
| Audit & detection evidence | `Telemetry` (`Present` / `Absent` / `Delayed` / `Incomplete` / `Unverifiable`) | DB audit slice + correlated alert |
| Response | `Response` (`Alerted` / `CaseCreated` / `Escalated` / `Remediated` / `NotTested`) | connector evidence; `NotTested` if none |
| Classification | `Classification` | DB-07 only; else `NotEvaluated` with Limitations |
| Provenance | `EvidenceProvenance` | timestamps, source system, correlation id (marker), integrity hash, collection method |

Scoring-layer result (PASS/FAIL/ERROR/SKIPPED): ERROR = execution or evidence processing failed; SKIPPED = could not legitimately run (e.g. audit plugin absent); neither counts as control validation. A forbidden read that succeeds but is alerted: prevention fails, detection passes; overall follows the existing scoring policy, dimensions retained in the report. The builder must locate the correct scoring integration point for run results (B3) and must call `Record.Validate()` on every record.

## 8. Safety gates (engine-enforced)

1. **Authorization & identity**: explicit scope approval, target identity verification (DB system identifier / instance id, not hostname alone), scenario allowlist, run expiry.
2. **Execution class**: client mode rejects `mutation` at orchestrator authorization *and* agent execution policy *and* DB permissions (read-only role). Mislabelled/misdispatched scenarios must still be rejected by what they actually do (agent checks operation allowlist, not just the label).
3. **Resource limits**: connection, row, time, concurrency, run-duration caps; server-side statement timeouts where supported; cancel and verify the query stopped.
4. **Fixture isolation & cleanup**: dedicated schema, unique fixture ids, recorded pre-test state, verified restoration. Cleanup failure is a safety incident that blocks normal completion.
5. **Signing & integrity**: verify `.sig` before execution (agent and server); reject tampered/expired; record scenario version + agent identity; secrets and real data never in evidence.

## 9. Phased delivery and acceptance

| Phase | Deliverable | Exit |
|---|---|---|
| 1 | Contract verification (done for facts in §3) + threat model + builder discovery items B1–B5 settled | integration tests pinning existing contracts |
| 2 | Core engine, PG+MySQL adapters (connect/roles/grants), read-only probes (DB-01/02/03), agent `dbprobe` step, scope + budgets | reproducible safe probes on both engines |
| 3 | Audit collectors (DB-04), `dlpreport` rendering, signed-scenario verification tests | real audit evidence in reports, none invented |
| 4 | Marker correlator over `detectverify`, detection windows, latency; DB-05, DB-09 | confirmed alert correlates to the right run; **first end-to-end proof on both engines**: signed scenario → agent → audit event → real alert → `Record` |
| 5 | Lab release: fixtures + verified cleanup, DB-06/07/08/10/11, failure recovery | lab acceptance criteria |
| 6 | Client read-only pilot (explicit authorization, read-only identity, narrow scope) | client-mode safeguards validated |

Estimates are planning guesses, not commitments. **Phase 4's end-to-end proof is the key milestone; do not expand the catalog or start a pilot before it.**

Minimum failure tests (none may yield a misleading pass): (1) valid signed scenario, out-of-scope DB; (2) tampered scenario at the agent; (3) mutation scenario in a read-only client run; (4) DB denies, DAM silent; (5) action succeeds, alert after deadline; (6) audit plugin unavailable; (7) SIEM connector down; (8) fixture cleanup fails; (9) two simultaneous runs must not correlate with each other; (10) agent disconnects mid-probe.

Also required: PG/MySQL adapters pass supported-operation suites; grant diff finds seeded deviations and changes nothing; reports contain scenario/version, target, principal, timestamps, verdict, dimensions, evidence refs, limitations; secrets redacted; evidence access authorized and audited.

## 10. Left to the builder

- **B1** How shared dbsim types live across the two Go modules (agent vs orchestrator) without the agent importing orchestrator internals (shared module, vendored subset, or protocol-only contract). Constraint: agent must stay free of orchestrator internals.
- **B2** The existing secret-resolution mechanism the agent should use for DB credential references; if none suits, propose one (still reference-only).
- **B3** The exact scoring-layer integration point and result type for run-pipeline results, and how existing modules (e.g. `phishval`, `killchain`) persist results.
- **B4** Whether the "DLP-DB channel" exists under another name; reuse if so.
- **B5** Garble/`-literals` build impact of adding the two drivers to the agent (see garble notes); binary size delta; confirm Windows/Linux/macOS agent builds still pass.
- Audit sources per engine (pgaudit / `log_statement` for PostgreSQL; MariaDB/Percona audit plugin or MySQL Enterprise audit / general log for MySQL) — choose the explicitly supported configurations; everything else is SKIPPED.
- Scenario file format, signing flow, and the console/UI surface are to follow existing conventions.

## 10a. Resolved after builder check (author's calls, flagged for review)

- **R1 Which entity alerts are keyed on.** Query connectors for **both** the DB server (host/IP) and the agent's source IP, as two `VerifyRequest`s, and union the results before marker filtering. The target registry records the DB server host/IP; the agent IP comes from the run. Correlation quality is graded on the marker, not on which entity matched. The lab setup must place the agent and DB on different hosts for the Phase 4 proof (a same-host run proves less and is labelled so in Limitations).
- **R3 Probe SQL is not free-form.** Probes are *named operations implemented in agent code* (e.g. `read_restricted_table`, `bounded_synthetic_read`, `read_grants`). The signed scenario carries probe id + declared parameter schema + limits; the marker, target and fixture id are bound as typed parameters at runtime (the marker is placed in the query comment/`application_name` by the adapter, never by string-splicing server text). The signature covers probe id, parameter schema and limits, not the final SQL. This is also the primary defence against mislabelled scenarios (§8 gate 2): the agent allowlists by probe id, not by label.
- **R4 Proving non-mutation in client mode.** Layered, with no SQL parsing: (a) read-only DB role, (b) every client-mode probe runs inside a `READ ONLY` transaction (PostgreSQL `BEGIN READ ONLY`; MySQL `START TRANSACTION READ ONLY`), (c) named-operation allowlist, (d) statement/row/time limits. Probes that invoke user-defined routines are not allowed in client mode.
- **R5 Least-privilege policy format (DB-02).** Minimal format, stored per target: roles → allowed objects → allowed privileges (JSON/YAML), plus an optional deny list and a `source` string. No import of external formats in v1.
- **R6 Target identity.** Scope approval records the expected PostgreSQL `system_identifier` / MySQL `server_uuid`, supplied at target registration. Mismatch refuses the run. Lab mode may discover-then-confirm (operator confirms the discovered id once); client mode requires pre-registration, never trust-on-first-use.
- **R7 Clocks.** Prefer the DB-reported statement/audit time over the agent's clock; always record the agent/orchestrator clock and measured skew; detection windows are padded by a configurable skew allowance, and skew above a threshold downgrades timing confidence (Limitations), not silently shifts the verdict.
- **R8 Client-mode release gate.** The engine hard-refuses client mode unless an Admin enables it in settings (default off) *and* the target is registered with the read-only identity check passing. Enabling is an Admin-only, audited action. Phase 6 does not start until Phase 4's end-to-end proof and the 10 failure tests pass; the engine does not enforce that process gate in code, the plan does.
- Lower priority: prevention-fails/detection-passes follows existing scoring policy (builder confirms in B3); `Incomplete` is used when a DAM event exists but the audit slice lacks the principal or marker; hung-agent cancel follows existing run-cancel/grace-period behaviour.

- **R2 (decided by user, 2026-10-22): lab detection path is Elastic.** No lab DAM/SIEM exists, so the plan includes building one: a self-hosted Elastic stack fed by PostgreSQL audit logging (pgaudit/`log_statement`) and a MySQL-family audit source, with a detection rule that alerts on the probe marker. The Phase 4 proof targets the existing `detectverify` Elastic connector. The lab stack is test infrastructure (compose-based, kept outside shipped product code) and is a plan phase of its own.

## 10b. Amendments after Task 1 discovery (2026-10-22; binding, override earlier text)

Source: `docs/dbsim-discovery.md` (commit `49e3811e`), claims C1 and C4 re-verified by the controller against `elastic.go:176,303-308` and `orchestrator/go.mod`.

- **A1 (supersedes §6 / §11 "reuse `detectverify` unchanged").** For Elastic, `MatchedAlert.RawJSON` is a synthesized summary and the query `_source` whitelist omits `message`, `kibana.alert.reason`, `event.*` and similar, so a marker in audited SQL is invisible to a post-filter. Resolution: a minimal **additive** change to the Elastic connector — widen the `_source` whitelist and add one new key to `RawJSON` (e.g. `source`) carrying only those extra fields; all existing `RawJSON` keys, `VerifyRequest`, `Verify` semantics and other connectors are unchanged; existing connector tests must still pass. dbsim still adds no marker field to `VerifyRequest`. Owned by Task 12 (new first step). Other connectors (Splunk, Sentinel, …) are out of the first release's proof; they are SKIPPED/Unverifiable for marker matching until separately verified.
- **A2.** `matchAlerts` returns `Detected` for any host/window alert. dbsim **never uses `VerifyResult.Verdict`**; it derives its verdict only from marker-matched alerts.
- **A3 (supersedes §4.1 "shared package" and plan B1 default).** No shared Go package and no orchestrator import of agent code (the production orchestrator image cannot build with it). Each module owns its wire types, equal by a golden JSON vector test on both sides (repo precedent: `agent/protocol/golden_vector_test.go`). Adapters, probes, limits, fixtures live **agent-side** in package `agent/dbprobe/` (`postgres/`, `mysql/` subpackages; build-tag free, pure Go); the wire type `DBProbeSpec` (+ result) lives in `agent/protocol`. The orchestrator side (`orchestrator/internal/dbsim/`) holds mirror structs, a probe registry **as data** (id, class, engines, param schema, capabilities-needed), policy diff, correlation, report. All plan references to `agent/dbsim/` mean `agent/dbprobe/`.
- **A4 (refines §4 / §8 signing wording).** The agent never sees the scenario `.sig`; the orchestrator verifies it at load. The agent verifies the signed `CommandEnvelope` (`agent/commandsig.go`), whose payload carries the `dbprobe` step, so the probe id, params and limits are covered by a signature the agent checks. Failure test 2 means a tampered/unsigned/replayed envelope reaching the agent, and a tampered `.sig` at the orchestrator.
- **A5 (supersedes §7 persistence).** Use the dedicated-store pattern: new `dbsim_runs` table (+ `EnsureDBSimRunSchema`, store file under `orchestrator/internal/db/`) holding the full report JSON (the `dlpreport.Record` per scenario + evidence refs) with the graded `PASS|FAIL|ERROR|SKIPPED` copied out; `dlpreport.Record` has no persistence or consumer today so dbsim is its first caller. No `scenario_runs` row by default. Agent result: a typed optional field on `protocol.ExecResult`, never parsed from stdout.
- **A6 (refines §8 gate 2).** Execution-class mapping: `read_only → non_destructive`, `bounded_synthetic → potentially_destructive`, `mutation → destructive`; unregistered `(technique_id, action_key)` fails closed (destructive). dbsim adds a separate agent-side gate before B5 (`evaluateB5Gate`) and does not weaken B5. `Command` on a `dbprobe` step is non-executable text (the probe id).
- **A7 (resolves B2).** The agent has no credential-reference resolver. New minimal resolver following the proxy-credential precedent: `credentialRef` → env `BAS_DBCRED_<NAME>` (JSON `{user,password}`), else an agent-local protected store (DPAPI registry value on Windows, root-only 0600 file on POSIX). Unresolvable ref ⇒ SKIPPED with reason, never a default account; secrets never logged (extend logger redaction); operator provisioning documented in the operator guide.
- **A8 (resolves B5).** Both drivers build with `CGO_ENABLED=0` on all 5 targets, ≈ +4.2 MB per agent binary; `golang.org/x/text` is a new agent dependency. `GOGARBLE=audspect/*` leaves third-party drivers unobfuscated. The real garble build runs on staging. The legacy agent (go 1.20) cannot run dbsim steps and must report them SKIPPED/unsupported.
- **A9 (resolves B4).** `scenarios/dlp-exfiltration-db-export.yaml` is a DLP text-exfiltration scenario with no DB client; not a dependency. Keep ids/labels distinct from dbsim `DB-xx`.
- **A10 (scenario plumbing, from discovery (a)).** A new `dbsim` `license.ProductLine` const plus `tierProductLines` entry and `api/product_gate.go` route prefixes are required; the `scenario.Step` shape gains the dbsim fields and the validator accepts executor `dbprobe`; scenario YAML + `.sig` follow the existing signer.

## 11. Calls I (the author) made — flagged for review

- Probes via embedded pure-Go drivers, not shelling out to `psql`/`mysql` (user decided agent-side; embedding is my choice).
- Reuse `detectverify` unchanged with an orchestrator-side marker post-filter, rather than adding a `Marker` field to `VerifyRequest` and touching 7 connectors.
- Emit both a `dlpreport.Record` and a scoring-layer result.
- DB-12 deferred past 1.0; DB-04 placed in Phase 3 (needs audit collectors).
- Rename of the brief's DB-xx numbering to the implementation catalog in §5 (brief had 14; this has 12 — SQL injection and incident-response/containment from the brief are intentionally out of the DB module).
