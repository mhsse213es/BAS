# Database Security Simulation (`dbsim`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agent-executed PostgreSQL/MySQL security simulation that credits a detection only when a real Elastic alert is retrieved and correlated to the probe, reported as `dlpreport.Record`.

**Architecture:** The orchestrator dispatches a signed scenario containing a native `dbprobe` step; the agent runs a named probe through embedded drivers under local safety gates and returns structured evidence. The orchestrator pulls alerts through the existing `detectverify` Elastic connector, post-filters them for the probe marker (`dbsim/correlation`), and renders a `dlpreport.Record` plus a scoring-layer result.

**Tech Stack:** Go (agent module `audspect/agent`, orchestrator module `github.com/audspect/bas`), `jackc/pgx/v5` (already in orchestrator), `go-sql-driver/mysql` (new), Docker Compose lab (PostgreSQL+pgaudit, MySQL-family with audit plugin, Elasticsearch/Kibana, Filebeat).

**Spec:** `docs/superpowers/specs/2026-10-22-dbsim-database-security-simulation-design.md` (read §3 facts, §8 gates, §10a resolved calls R1–R8 before any task).

## Global Constraints

- Probes run **in the agent**; the agent never scores. (spec §2, §4)
- Reuse `dlpreport.Record` (`Enforcement/Classification/Telemetry/Response`) — **no new verdict taxonomy**; call `Record.Validate()` on every record. (§7)
- Reuse `detectverify` connectors with **no `Marker` field added to `VerifyRequest`** and no change to `Verify` semantics or other connectors; the only connector change is the additive Elastic one in spec A1 (Task 12). Marker filtering lives in `orchestrator/internal/dbsim/correlation`. dbsim never uses `VerifyResult.Verdict`. (§6, A1, A2)
- Probes are **named operations in agent code**; signature covers probe id + parameter schema + limits; no free-form SQL from the server. (R3)
- Client mode: read-only DB role **and** `READ ONLY` transaction **and** probe-id allowlist; hard-refused unless Admin-enabled (default off). (R4, R8)
- Target identity = PG `system_identifier` / MySQL `server_uuid`, pre-registered; client mode never trust-on-first-use. (R6)
- Alerts queried for **both** DB-server host/IP and agent IP, then unioned. (R1)
- Unsupported capability ⇒ `SKIPPED`; evidence/connector failure ⇒ `ERROR`/`Telemetry=Unverifiable`; never a pass. (§7, §9)
- Secrets: credential **references** only in scenarios; redact from logs, errors and reports. No real PANs/customer data in fixtures. (§4.4, §2)
- Pure-Go drivers only (no cgo); agent builds for Windows/Linux/macOS must still pass; garble `-literals` impact checked. (§10 B5)
- Re-sign every edited scenario `.sig`. Commit and push after each task (repo convention).
- Cleanup failure is a safety incident that blocks normal completion. (§8 gate 4)

## Amendments after Task 1 (binding; spec §10b A1–A10 and `docs/dbsim-discovery.md`)

These override any task text that differs:
- **Packages (A3):** agent-side code is `agent/dbprobe/` (+ `postgres/`, `mysql/`, `fixtures/`); wire types `DBProbeSpec`/result live in `agent/protocol`. The orchestrator never imports agent code; `orchestrator/internal/dbsim/` holds mirror wire structs, a probe registry as data, policy, correlation, report. Task 2 and Task 3 therefore produce **two** sets: agent types/gates and orchestrator mirrors, tied by a golden JSON vector test (precedent `agent/protocol/golden_vector_test.go`). Task 3's orchestrator `Authorize` takes the mirror registry's probe entry, not an agent `ProbeDef`.
- **Task 6 (A4, A6, A7):** dispatch via a `dbprobe` branch in `agent/executor.go` `execStep` before `buildCmd`; copy the new field in `decodeStep` (`agent/agent.go`); add the dbsim gate before `evaluateB5Gate` without weakening B5; credential resolver per A7 (env `BAS_DBCRED_<NAME>`, else local protected store; unresolvable ⇒ SKIPPED); result as a typed optional field on `protocol.ExecResult`. "Tampered scenario" test = tampered/unsigned/replayed `CommandEnvelope`.
- **Task 7 (A6, A10):** also add the `dbsim` `license.ProductLine` const + `tierProductLines` + `api/product_gate.go` prefixes, extend `scenario.Step` and the validator for executor `dbprobe`, register execclass entries (`read_only→non_destructive`, `bounded_synthetic→potentially_destructive`, `mutation→destructive`), sign YAMLs with `orchestrator/scripts/signer.go`.
- **Task 8 (A5):** persistence is a new `dbsim_runs` table + `EnsureDBSimRunSchema` + store under `orchestrator/internal/db/`; graded `PASS|FAIL|ERROR|SKIPPED` copied out; `dlpreport.Record` JSON stored in full.
- **Task 12 (A1) gets a new first step:** write the failing test, then make the additive Elastic change (widen `_source`, add one `source` key to `RawJSON` with the extra fields, e.g. `message`, `kibana.alert.reason`, `event.original`, `user.name`); update `TestContractElasticRawJSONIsNormalizedSubset` to the new pinned shape; all existing `detectverify` tests must still pass. Other connectors stay untouched and are Unverifiable for marker matching.
- **Task 11/13 build note (A8):** the real garble build and the lab run on staging.

## Review Focus

1. Alert exists but its raw data lacks marker/query text (DAM doesn't surface it) → `Telemetry=Unverifiable` with Limitations, never `Absent` and never credited.
2. Agent and DB on the same host → run labelled lower-confidence in Limitations; no double-counting of the unioned alerts.
3. Driver errors that embed the DSN/password (pgx/mysql connect failures) → redacted in logs, step output and reports.
4. Fixture table empty, or rows with NULL/huge/non-UTF8 values; probe must respect `max_rows` and not crash the evidence encoder.
5. Large clock skew between agent, DB and Elastic, and audit log rotated mid-run → timing confidence downgraded / `Incomplete`, not a silent wrong `Delayed`/`Absent`.

---

## File Structure

Agent module (`agent/`):
- `agent/dbprobe/types.go` — Probe, ProbeResult, Role, Grant, AuditEvent, Capabilities, Fixture, CleanupResult.
- `agent/dbprobe/adapter.go` — `Adapter` interface + `Register/Lookup`.
- `agent/dbprobe/gate.go` — scope/identity, exec-class, budget checks.
- `agent/dbprobe/probes.go` — named-operation catalog (id → handler, class, param schema).
- `agent/dbprobe/postgres/`, `agent/dbprobe/mysql/` — adapters (`adapter.go`, `grants.go`, `audit.go`).
- `agent/dbprobe/fixtures/` — synthetic datasets + cleanup manifests.
- `agent/exec_dbprobe.go` — `dbprobe` executor glue (signature check, credential resolve, cancel).
- `agent/protocol/messages.go` — add `DBProbeSpec` to `ScenarioStep`.

Orchestrator (`orchestrator/internal/dbsim/`):
- `policy.go` (least-privilege diff), `correlation.go` (marker post-filter + grading), `report.go` (Record + scoring result), `targets.go` (registry, identity, mode), `scenarios/` (signed DB-xx definitions).

Lab (test infra, not shipped): `lab/dbsim/docker-compose.yml`, `lab/dbsim/elastic/` (detection rule, filebeat), `lab/dbsim/README.md`.

Docs: `docs/dbsim-discovery.md` (Task 1), `docs/dbsim-mastery-qa-log.md` (Task 16).

---

### Task 1: Discovery and contract pinning (spec B1–B5)

**Files:**
- Create: `docs/dbsim-discovery.md`, `orchestrator/internal/dbsim/contracts_test.go`

**Interfaces:**
- Produces: written decisions B1 (where shared wire types live; default: `agent/protocol` carries `DBProbeSpec`, orchestrator imports it the same way it already imports other protocol types — confirm), B2 (agent's existing credential/secret resolution mechanism), B3 (scoring-layer result type + persistence point for run results), B4 (whether a DLP-DB channel exists under another name), B5 (build/size impact).

- [ ] **Step 1: Write contract-pinning tests** in `contracts_test.go`: `TestRecordValidateRequiresLimitationsWhenUncertain` (Record with `Telemetry=Unverifiable`, empty Limitations ⇒ error), `TestElasticBuildQueryScopesByHostNameAndIP` (query built for a `VerifyRequest` contains `host.name`/`host.ip` terms and the window range), `TestMatchedAlertKeepsRawJSON`.
- [ ] **Step 2: Run** `cd orchestrator && go test ./internal/dbsim/ -run Contract -v` — expect PASS (pins current behavior; if any FAIL the spec's §3 is wrong → stop and update the spec).
- [ ] **Step 3: Answer B1–B5 in `docs/dbsim-discovery.md`** by reading code: agent `agent.go` `ScenarioStep`/`executor.go` dispatch, `agent/protocol/messages.go`, existing signature verification (`agent/*sig*`, `scenario` package), run-result persistence, and grep for an existing DB exfil channel. Add both drivers to a scratch branch of `agent/go.mod`, run `go build` for windows/linux/darwin and the project's garble build; record binary-size delta and any `-literals` problem.
- [ ] **Step 4: Commit and push** (`docs: dbsim discovery and contract pins`).

### Task 2: Wire contract and probe catalog types

**Files:**
- Create: `agent/dbprobe/types.go`, `agent/dbprobe/probes.go`
- Modify: `agent/protocol/messages.go` (`ScenarioStep` gains `DBProbe *DBProbeSpec`)
- Test: `agent/dbprobe/probes_test.go`, `agent/protocol/messages_test.go`

**Interfaces:**
- Produces: `type DBProbeSpec struct { Engine, ProbeID, TargetID, CredentialRef, RunID, Marker, FixtureID string; Mode ExecMode; Limits Limits; Params map[string]string }`; `type ExecMode string` (`ModeLab`, `ModeClient`); `type ProbeClass string` (`ClassReadOnly`, `ClassBoundedSynthetic`, `ClassMutation`); `type Limits struct { MaxRows, TimeoutSec, MaxConns int }`; `type ProbeDef struct { ID string; Class ProbeClass; ParamSchema map[string]ParamKind; Engines []string }`; `func LookupProbe(id string) (ProbeDef, bool)`; `type ProbeResult struct { Denied bool; RowsRead int; ErrorClass string; DBTime time.Time; AgentTime time.Time; Notes []string }`.

- [ ] **Step 1: Write failing tests:** `TestDBProbeSpecRoundTripsJSON`; `TestLookupProbeUnknownIDNotFound`; `TestEveryProbeDeclaresClassAndEngines`; `TestParamSchemaRejectsUndeclaredParam` (a `Params` key not in schema ⇒ validation error).
- [ ] **Step 2: Run** `cd agent && go test ./dbprobe/ ./protocol/ -v` — expect FAIL (undefined).
- [ ] **Step 3: Implement** types + `ValidateSpec(DBProbeSpec) error` (checks probe exists, params ⊆ schema, limits > 0). Initial probe ids: `read_roles`, `read_grants`, `auth_check`, `read_restricted_table`.
- [ ] **Step 4: Run tests** — expect PASS. **Step 5: Commit and push.**

### Task 3: Safety gates (scope, execution class, budgets)

**Files:**
- Create: `agent/dbprobe/gate.go`; orchestrator side `orchestrator/internal/dbsim/targets.go`
- Test: `agent/dbprobe/gate_test.go`, `orchestrator/internal/dbsim/targets_test.go`

**Interfaces:**
- Consumes: Task 2 types.
- Produces: `func CheckSpec(spec DBProbeSpec, def ProbeDef, observedIdentity string, expectedIdentity string, clientEnabled bool) error` (agent); `type Budget struct{...}` with `func (b *Budget) Charge(rows int) error` and context deadline helper `func WithDeadline(ctx context.Context, l Limits) (context.Context, context.CancelFunc)`; orchestrator `type Target struct { ID, Engine, Host string; Port int; Mode ExecMode; ExpectedIdentity string; ReadOnlyIdentityVerified bool }` and `func Authorize(t Target, def ProbeDef, clientEnabled bool, runExpiry time.Time) error`.

- [ ] **Step 1: Write failing tests** (these are release failure tests 1 and 3): `TestCheckSpecRejectsIdentityMismatch`, `TestCheckSpecClientModeRejectsMutationProbe`, `TestCheckSpecClientModeRejectsMislabelledScenarioByProbeID` (spec says client/read-only but `def.Class==ClassMutation`), `TestAuthorizeRefusesClientModeWhenDisabled`, `TestAuthorizeRefusesExpiredRun`, `TestBudgetChargeExceedsMaxRows`.
- [ ] **Step 2: Run** both packages — expect FAIL. **Step 3: Implement** the functions above; client mode requires `ReadOnlyIdentityVerified` and `clientEnabled`; identity compare is exact. **Step 4: Run — PASS. Step 5: Commit and push.**

### Task 4: PostgreSQL adapter (read-only core)

**Files:**
- Create: `agent/dbprobe/adapter.go`, `agent/dbprobe/postgres/adapter.go`, `grants.go`
- Modify: `agent/go.mod` (add `github.com/jackc/pgx/v5`)
- Test: `agent/dbprobe/postgres/adapter_test.go` (integration, build tag `dbsim_integration`, uses lab compose PG)

**Interfaces:**
- Produces: `type Adapter interface { Connect(ctx, ConnectionConfig) error; Identity(ctx) (string, error); EnumerateRoles(ctx) ([]Role, error); ReadGrants(ctx) ([]Grant, error); RunProbe(ctx, ProbeDef, DBProbeSpec) (ProbeResult, error); CollectAudit(ctx, AuditQuery) ([]AuditEvent, error); Cleanup(ctx, Fixture) (CleanupResult, error); Capabilities() Capabilities; Close() error }`; `func Register(engine string, f func() Adapter)`; `func New(engine string) (Adapter, bool)`.

- [ ] **Step 1: Write failing integration tests:** `TestPGIdentityIsSystemIdentifier`, `TestPGReadGrantsReturnsSeededGrant`, `TestPGClientModeProbeRunsInReadOnlyTransaction` (a write attempted through the same connection fails with SQLSTATE 25006), `TestPGMarkerLandsInApplicationName`, `TestPGConnectErrorRedactsPassword` (Review Focus 3), `TestPGCapabilitiesDeclareAuditSource`.
- [ ] **Step 2: Run** with `-tags dbsim_integration` against the lab PG — expect FAIL. **Step 3: Implement** the adapter: TLS verification on by default, `BEGIN READ ONLY` for client mode, marker via `application_name` and a leading SQL comment, statement timeout from `Limits`. **Step 4: Run — PASS. Step 5: Commit and push.**

### Task 5: MySQL adapter (read-only core)

**Files:** Create `agent/dbprobe/mysql/adapter.go`, `grants.go`; Modify `agent/go.mod` (add `github.com/go-sql-driver/mysql`); Test `agent/dbprobe/mysql/adapter_test.go`.

**Interfaces:** Consumes Task 4 `Adapter`. Same method set; `Identity` returns `@@server_uuid`.

- [ ] **Step 1: Write failing integration tests** mirroring Task 4: `TestMySQLIdentityIsServerUUID`, `TestMySQLReadGrantsReturnsSeededGrant`, `TestMySQLClientModeUsesReadOnlyTransaction` (`START TRANSACTION READ ONLY`, write ⇒ error 1792), `TestMySQLMarkerInQueryComment` (MySQL has no `application_name`; assert comment only and that `Capabilities()` says session attribute not supported), `TestMySQLConnectErrorRedactsPassword`.
- [ ] **Steps 2–5:** run FAIL → implement → PASS → commit and push. Note any behavioural differences in `Capabilities()` rather than hiding them.

### Task 6: Agent `dbprobe` executor

**Files:** Create `agent/exec_dbprobe.go`; Modify `agent/agent.go` (dispatch on a `dbprobe` executor value; mirror `ScenarioStep` field), test `agent/exec_dbprobe_test.go`.

**Interfaces:** Consumes Tasks 2–5. Produces `func executeDBProbe(ctx context.Context, step ScenarioStep) (DBProbeOutcome, error)` where `DBProbeOutcome` = `ProbeResult` + audit slice + `GateRefusal string`.

- [ ] **Step 1: Write failing tests** (failure tests 2 and 10): `TestDBProbeTamperedScenarioRefusedBeforeConnect` (assert no adapter `Connect` call via a fake adapter), `TestDBProbeUnknownProbeIDRefused`, `TestDBProbeContextCancelStopsQueryAndReportsError` (fake adapter blocks; cancel; outcome is error, not pass), `TestDBProbeResolvesCredentialRefWithoutLoggingSecret`.
- [ ] **Step 2: Run — FAIL. Step 3: Implement** using the signature and credential mechanisms identified in Task 1 (B2); order of operations: verify signature → `ValidateSpec` → resolve credential → `New(engine)` → `Connect` → `Identity` → `CheckSpec` → `RunProbe` → `CollectAudit` → `Cleanup` if fixtures. **Step 4: PASS. Step 5: Commit and push.**

### Task 7: Orchestrator dispatch, DB-01/02/03 scenarios, grant-policy diff

**Files:** Create `orchestrator/internal/dbsim/policy.go`, `scenarios/db01_auth_policy.*`, `db02_excessive_grants.*`, `db03_unauthorized_access.*` (format per Task 1); Modify the scenario registry/execclass files found in Task 1 so DB scenarios classify as non-mutating; re-sign `.sig`. Tests: `policy_test.go`, scenario-load tests following existing `scenario/*_test.go` patterns.

**Interfaces:** Produces `type Policy struct { Source string; Roles map[string]RolePolicy }`, `type RolePolicy struct { Allow map[string][]string; Deny map[string][]string }`, `func Diff(p Policy, actual []Grant) []Deviation`.

- [ ] **Step 1: Write failing tests:** `TestDiffFlagsSeededExcessiveGrant`, `TestDiffIncludesRoleInheritance`, `TestDiffNeverProducesRevokeAction` (Deviation has no executable field), `TestDBScenariosLoadAndVerifySignature`, `TestDBScenariosClassifiedNonMutating`.
- [ ] **Step 2–5:** run FAIL → implement → PASS → commit and push. DB-02 reports policy `Source` in output.

### Task 8: Result rendering (`dlpreport.Record` + scoring result)

**Files:** Create `orchestrator/internal/dbsim/report.go`, `report_test.go`.

**Interfaces:** Consumes agent `ProbeResult`, correlation output (Task 12 — until then a `Correlation` struct stub with `Telemetry`/`Response` set by caller). Produces `func ToRecord(s ScenarioMeta, o Outcome) (dlpreport.Record, error)` and `func ToRunResult(o Outcome) <scoring-layer result per Task 1 B3>`.

- [ ] **Step 1: Write failing tests:** `TestDeniedProbeMapsToEnforcementBlocked`, `TestSucceededProbeMapsToEnforcementAllowed`, `TestSucceededButAlertedKeepsDimensionsSeparate` (Enforcement=Allowed, Telemetry=Present, Response=Alerted), `TestUnsupportedAuditMapsToSkippedNotPass`, `TestUncertainDimensionWithoutLimitationsFailsValidate`, `TestNoSecretInRecordFields`.
- [ ] **Step 2–5:** FAIL → implement (always call `Validate()`) → PASS → commit and push.

### Task 9: Audit collectors and DB-04

**Files:** Create `agent/dbprobe/postgres/audit.go`, `agent/dbprobe/mysql/audit.go`, scenario `db04_audit_coverage.*`; tests alongside (integration tag).

**Interfaces:** Produces `CollectAudit(ctx, AuditQuery{Marker, Principal string; Since, Until time.Time}) ([]AuditEvent, error)`; `AuditEvent{Time time.Time; Principal, Statement, Source string}`. PG source: pgaudit/`log_statement` via the log file or a view the lab exposes; MySQL: the audit plugin chosen in Task 11. Anything else ⇒ `Capabilities().AuditSources` empty ⇒ SKIPPED.

- [ ] **Step 1: Write failing tests:** `TestPGAuditEventContainsMarkerAndPrincipal`, `TestMySQLAuditEventContainsMarkerAndPrincipal`, `TestAuditUnavailableReportsSkippedCapability` (failure test 6), `TestAuditSliceIncompleteWhenLogRotatedMidRun` (Review Focus 5 ⇒ `Incomplete`).
- [ ] **Step 2–5:** FAIL → implement → PASS → commit and push.

### Task 10: Synthetic fixtures with verified cleanup

**Files:** Create `agent/dbprobe/fixtures/catalog.go`, `cleanup.go`; tests alongside.

**Interfaces:** Produces `func Seed(ctx, Adapter, FixtureSpec) (Fixture, error)` (dedicated schema, unique id, records pre-test state), `func VerifyClean(ctx, Adapter, Fixture) (CleanupResult, error)`; values drawn from `dlpfixture` patterns, unmistakably synthetic.

- [ ] **Step 1: Write failing tests:** `TestSeedCreatesIsolatedSchemaOnly`, `TestVerifyCleanDetectsLeftoverObject`, `TestCleanupFailureIsSafetyIncident` (failure test 8; outcome flagged, run cannot complete normally), `TestEmptyAndNullAndHugeValuesRespectMaxRows` (Review Focus 4), `TestNoRealPANPatterns` (synthetic-marker prefix on every value).
- [ ] **Step 2–5:** FAIL → implement → PASS → commit and push.

### Task 11: Elastic lab stack

**Files:** Create `lab/dbsim/docker-compose.yml`, `lab/dbsim/elastic/rule.json` (detection rule: alert when a DB audit event contains the `bas-dbsim:` marker prefix), `lab/dbsim/elastic/filebeat.yml`, `lab/dbsim/README.md`, `lab/dbsim/seed.sql`.

**Interfaces:** Produces a documented stack: PostgreSQL with pgaudit, a MySQL-family server with an audit plugin (choose the one that ships in a pullable image — record the choice and the limits in the README), Elasticsearch + Kibana + Filebeat, alerts index readable by the `detectverify` Elastic connector, alert `host.name`/`host.ip` of the DB server. Agent and DB on **different** containers/hosts.

- [ ] **Step 1: Write the lab smoke script** `lab/dbsim/smoke.sh`: issue a tagged query on each DB, poll Elasticsearch for the alert (≤ 90 s), exit non-zero if absent.
- [ ] **Step 2: Run it before the stack exists** — expect FAIL. **Step 3: Build the stack** until the smoke script passes for both engines. **Step 4: Run — PASS. Step 5: Commit and push.** (Heavy job rule: run on staging if the Windows host is too slow.)

### Task 12: Marker correlator over `detectverify`

**Files:** Create `orchestrator/internal/dbsim/correlation.go`, `correlation_test.go`.

**Interfaces:** Consumes `detectverify.Connector`, `VerifyRequest`, `MatchedAlert`. Produces `type Match string` (`MatchExact`, `MatchStrong`, `MatchAmbiguous`, `MatchNone`); `type CorrelationInput struct { Marker, Principal, RunID string; DBHost, DBIP, AgentIP string; ProbeAt time.Time; Window, SkewAllowance time.Duration }`; `func Correlate(ctx context.Context, c detectverify.Connector, in CorrelationInput) (Result, error)` where `Result{ Match Match; Telemetry dlpreport.TelemetryOutcome; Response dlpreport.ResponseOutcome; Latency time.Duration; Alerts []detectverify.MatchedAlert; Limitations string }`.

- [ ] **Step 1: Write failing tests with a fake `Connector`** (failure tests 4,5,7,9 + Review Focus 1,2,5): `TestExactMarkerInRawCreditsDetection`, `TestAlertWithoutMarkerIsUnverifiableNotAbsent`, `TestNoAlertsHealthySourceIsAbsent`, `TestConnectorErrorIsUnverifiableNeverAbsent`, `TestAlertAfterWindowIsDelayed`, `TestTwoConcurrentRunsDoNotCrossCorrelate` (different markers, overlapping window), `TestUnionOfDBHostAndAgentIPDeduplicatesAlerts`, `TestSameHostRunNotedInLimitations`, `TestSkewAboveThresholdDowngradesTimingConfidence`.
- [ ] **Step 2: Run — FAIL. Step 3: Implement:** two `Verify` calls (DB host/IP, agent IP), union by `AlertID`, filter `RawJSON` for marker/principal/run id, grade, apply window and skew allowance (R1, R7). **Step 4: PASS. Step 5: Commit and push.**

### Task 13: DB-05, DB-09 and the end-to-end proof (**milestone — stop for review after this task**)

**Files:** Create scenarios `db05_suspicious_read.*`, `db09_bounded_bulk_read.*`; probe ids `suspicious_read`, `bounded_synthetic_read` in `agent/dbprobe/probes.go`; end-to-end test `orchestrator/internal/dbsim/e2e_test.go` (build tag `dbsim_e2e`).

**Interfaces:** Consumes everything above; wires orchestrator `Correlate` output into Task 8 `ToRecord`.

- [ ] **Step 1: Write the failing e2e test** `TestE2E_<Engine>_SignedScenarioToCorrelatedRecord` for PostgreSQL and MySQL: signed scenario → real agent binary → lab DB → audit event → Elastic alert → `detectverify` Elastic connector → `Correlate` → `Record` with `Telemetry=Present`, `Response=Alerted`, non-zero latency, `Validate()==nil`.
- [ ] **Step 2: Run against the lab stack — FAIL. Step 3: Fix whatever the real path exposes** (record deviations from the spec in the QA log). **Step 4: Run — PASS on both engines. Step 5: Commit and push; write `docs/dbsim-mastery-qa-log.md` entry for the milestone.**

**Gate:** do not start Task 14+ until the user reviews this milestone.

### Task 14: DB-06 revocation and DB-07 classification (lab)

**Files:** scenarios `db06_account_revocation.*`, `db07_sensitive_classification.*`; probes `auth_after_revoke`, `read_classified_fixture`; tests alongside plus e2e additions.

- [ ] **Step 1: Write failing tests:** `TestRevokedIdentityDeniedOnNewConnection`, `TestRevocationRestoresAccountAfterTest` (cleanup verified), `TestClassificationOutcomeCorrectWhenRuleFires` / `...IncorrectWhenRuleSilent` (maps to `ClassificationOutcome`).
- [ ] **Step 2–5:** FAIL → implement → PASS → commit and push.

### Task 15: DB-08 audit tamper resistance, DB-10 write/delete prevention, DB-11 backup/export permissions (lab only)

**Files:** scenarios `db08_*`, `db10_*`, `db11_*`; probes `try_disable_audit`, `try_write_fixture`, `check_export_privileges`.

- [ ] **Step 1: Write failing tests:** `TestRestrictedAccountCannotDisableAudit`, `TestMutationProbesRefusedInClientMode` (all three), `TestWriteDeniedLeavesFixtureUnchanged`, `TestRecoveryPlanRequiredForActualAuditDisablement` (probe refuses without an explicit lab-only recovery flag), `TestExportCheckReadsPrivilegesOnly`.
- [ ] **Step 2–5:** FAIL → implement → PASS → commit and push.

### Task 16: Client read-only mode, console surface, documentation

**Files:** Modify the settings/API files located in Task 1 to add the Admin-only audited "enable DB client mode" setting (default off) and the target registry endpoints (register target with expected identity, read-only identity check); console surface per existing conventions; Create `docs/dbsim-operator-guide.md` (supported-feature matrix, per-engine audit config, limitations), update `docs/dbsim-mastery-qa-log.md`.

- [ ] **Step 1: Write failing tests:** `TestClientModeRefusedWhenSettingOff`, `TestEnableClientModeRequiresAdminAndWritesAudit`, `TestClientRunWithMutationScenarioRefusedAtEveryLayer` (orchestrator authorize, agent gate, DB role — one test per layer), `TestRegisterTargetStoresExpectedIdentity`, RBAC-matrix test following existing `rbac` matrix tests.
- [ ] **Step 2–5:** FAIL → implement → PASS → run the full `dbsim` suites with `-p 2` → commit and push. Update the memory index and the vault per the end-of-session ritual.

---

## Self-review notes

- **Spec coverage:** §4 architecture → Tasks 2–6; §5 catalog → DB-01/02/03 (7), DB-04 (9), DB-05/09 (13), DB-06/07 (14), DB-08/10/11 (15), DB-12 deferred per spec; §6 correlation → 12; §7 result model → 8; §8 gates → 3, 6, 10, 16; §9 failure tests 1–10 → tests 1 (T3), 2 (T6), 3 (T3, T16), 4,5,7,9 (T12), 6 (T9), 8 (T10), 10 (T6); R1–R8 → T3, 4/5, 12, 16; R2 Elastic lab → 11; B1–B5 → 1.
- **Known unknowns carried into Task 1:** shared-type placement, agent secret mechanism, scoring persistence point, DLP-DB name, garble impact. If Task 1 contradicts a spec §3 fact, stop and amend the spec before continuing.
