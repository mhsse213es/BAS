# dbsim discovery and contract pins (Task 1, decisions B1-B5)

Date: 2026-10-22. Branch `worktree-dbsim`. Authority: `docs/superpowers/specs/2026-10-22-dbsim-database-security-simulation-design.md` (sections 3, 4, 10, 10a, 11). Every statement below was verified by reading the named file or running the named command.

## 0. Findings that contradict or refine the spec (read first)

| # | Spec says | Reality | Severity |
|---|---|---|---|
| C1 | Sec 3/6/11: reuse `detectverify` unchanged; connectors "keep `MatchedAlert.RawJSON`", dbsim post-filters returned alerts for the probe marker. | For **Elastic** (the Phase 4 target, R2) `RawJSON` is a **synthesized summary** (`alertId, ruleName, timestamp, severity, techniques, workflowStatus`), built in `normalizeElasticHit` (`orchestrator/internal/detectverify/elastic.go:303`). It is not the alert document. The query `_source` whitelist (`elastic.go:176`) also excludes `message`, `kibana.alert.reason`, `kibana.alert.original_event` and any `event.*`/`process.*` field. A marker that rides in the audited SQL (query comment / `application_name`) is therefore **invisible** to a post-filter on `RawJSON`. Pinned by `TestContractElasticRawJSONIsNormalizedSubset`. | **High. "Reuse unchanged" does not hold for Elastic.** The controller must amend the spec. |
| C2 | Sec 3: `matchAlerts` implied to be a neutral pass-through. | `matchAlerts` (`match.go:30`) returns `Detected` with Medium confidence for **any** host-scoped alert in the window, even with no technique tag, and returns *all* of them in `MatchedAlerts`. So an unrelated alert on the DB host in the window yields `Detected`. dbsim must never use `VerifyResult.Verdict`; it must derive its own verdict from marker-matched alerts only. | Medium (consistent with sec 6 intent, but must be stated) |
| C3 | Sec 4/4.3: "agent verifies the scenario `.sig`". | The `.sig` is verified **orchestrator-side** at scenario load (`Engine.Load` -> `integrity.ReadBuiltinSignature`, `orchestrator/internal/scenario/engine.go:195` / `orchestrator/internal/integrity/verifier.go:73`; the file-based twin is `integrity.VerifyScenarioFile`, `signing.go:67`). The **agent** never sees a `.sig`; it verifies the RSA-signed `CommandEnvelope` for `command_scenario` (`agent/commandsig.go:47`, `agent/protocol/command_envelope.go`). The envelope payload carries the steps, so a probe spec inside a step IS covered by a signature the agent checks. The R3 statement "the signature covers probe id, parameter schema and limits" holds, but via the envelope, and the scenario `.sig` only covers the YAML at rest. | Medium (wording; design still works) |
| C4 | Sec 4.1: shared `internal/dbsim/` "orchestrator and agent both import". Task brief B1 default: orchestrator imports `agent/protocol`. | **Impossible for shipped code.** (a) `agent` is module `audspect/agent`, orchestrator is `github.com/audspect/bas`; orchestrator's `go.mod` has no `require`/`replace` for `audspect/agent`. The only orchestrator imports of `audspect/agent/...` are `cmd/loadgen` and `internal/scenario/corpusaudit` (dev tools) and they resolve **only through the repo-root `go.work`** (`use ./agent ./orchestrator ...`). (b) The production orchestrator image (`orchestrator/Dockerfile:211-224`) copies only `orchestrator/go.mod`, `go.sum` and `orchestrator/` (no `go.work`, no `agent/`) and builds `./cmd/server`; any `cmd/server` dependency on `audspect/agent/...` would fail to build. (c) `orchestrator/internal/...` cannot be imported from another module anyway (Go `internal` rule). | **High for B1**; see decision below. |
| C5 | Sec 3: scoring layer is "`killchain/verdict.go`, `models.Result*`" with PASS/FAIL/ERROR/SKIPPED. | `killchain.Verdict` is a different vocabulary (ALLOWED, BLOCKED, DETECTED, DETECTED_NOT_CONTAINED, NOT_DETECTED, INCONCLUSIVE, NOT_TESTED, ERROR). `models.CheckResult` is lowercase `pass/fail/skipped/blocked/error/vetoed` (`orchestrator/internal/models/schema.go:11-32`). The literal uppercase PASS/FAIL/ERROR/SKIPPED set is the *apibas grade* (`db.APIBASRun.Result`, `orchestrator/internal/db/apibas_store.go`). See B3. | Medium |
| C6 | Sec 3: `execclass*.go` classifies exec classes, reused for dbsim. | `ExecutionClass` is `non_destructive / potentially_destructive / destructive`, keyed on `(technique_id, action_key)` (`execclass.go:14-20`, `ResolveExecutionClass` at `:1088`), with an **unknown pair failing closed to `destructive`** (`unclassified`, `execclass.go:38`). It is not the same axis as dbsim's `read_only / bounded_synthetic / mutation` (spec sec 5). dbsim needs an explicit mapping (see section b). | Medium |
| C7 | Sec 3: "DLP-DB channel: not found by grep". | It exists under a clear name: scenario `scenarios/dlp-exfiltration-db-export.yaml` (`product_line: dlp`), plus `dlpfixture` entries. It is a *synthetic text payload exfiltrated over existing SFTP/cloud/webhook sinks*; it contains **no database client**. Non-dependency conclusion stands. See B4. | Low |
| C8 | Sec 3: `internal/dlpreport` exists and is "reused". | True, but `dlpreport.Record` has **no consumer anywhere in the repo** (no importer outside the package, grep of `dlpreport"` over `orchestrator/` returns only its own files) and **no persistence**. dbsim would be its first caller and must add storage (see B3). | Low/Medium |
| C9 | Brief expects `buildQuery` pin may need an unexported test. | Not needed: the query is observed on the wire through an `httptest` server using the exported `NewConnector`. No file was added to `internal/detectverify`. | None |

Verified-true spec assumptions: `Record.Validate` rule (pinned), Elastic query scoped by `host.name` / `host.hostname` / `host.ip` plus the `@timestamp` / `kibana.alert.original_time` window (pinned), `VerifyRequest` has no marker field, agent has no DB drivers, orchestrator has `pgx/v5` and no MySQL driver (`orchestrator/go.mod:22`), `dlpcorrelate` is not a correlator (not re-examined here, trusted from the spec).

Status of the three explicit hazards the controller asked about: the **agent-side-probe decision stands**; "**reuse `detectverify` unchanged**" is **contradicted for Elastic (C1)**; the sec 3 facts otherwise hold with the refinements above.

## Decisions

### B1. Where shared wire types live

Decision: **no shared Go package.** Each module owns its own copy of the wire contract and a golden JSON vector test on both sides keeps them equal. This is the repo's existing practice, not a new idea:
- `agent/protocol/command_envelope.go` header: a "deliberately separate Go type (separate module) that must agree on wire shape, pinned by this package's own tests rather than a shared dependency", mirrored by `orchestrator/internal/models/command_envelope.go`.
- `agent/protocol.ScenarioStep` (`agent/protocol/messages.go:76`) mirrors `orchestrator/internal/scenario.ScenarioStep` (`orchestrator/internal/scenario/types.go:376`); the agent additionally has a package-local `ScenarioStep` (`agent/agent.go:633`) built by `decodeStep` (`agent/agent.go:658`).
- There is a golden precedent: `agent/protocol/golden_vector_test.go`.

Concrete layout implied (for the plan, replaces spec sec 4.1 "shared" box):
- Agent module: wire type `DBProbeSpec` (+ `DBProbeResult`) in `agent/protocol`; adapters/probes/limits/fixtures in a new agent package (suggest `agent/dbprobe/`, with `postgres` and `mysql` subpackages). It must not import the orchestrator.
- Orchestrator module: `orchestrator/internal/dbsim/` holds its own mirror structs for the wire shape, the scope/budget/gates, policy diff, correlation, report. Mirror types carry no scoring in the agent copy.
- Contract test: one checked-in JSON golden file per message; the agent test marshals/unmarshals it into `protocol.DBProbeSpec`, the orchestrator test into its mirror, both asserting byte-identical round trip.
- The adapter interface of spec sec 4.2 therefore lives **agent-side**; the orchestrator never runs a probe. Anything the orchestrator needs from an adapter (`Capabilities()` to decide SKIPPED up front) must be carried as data in the scenario/probe registry, not by importing the adapter.
- Rejected alternatives: (1) new third module imported by both: needs `go.work`, Dockerfile COPY changes in two build stages and a new module for little shared code; the legacy agent stage (Go 1.20) is separate and unaffected either way. (2) Orchestrator importing `audspect/agent/protocol`: breaks the production image (C4).

### B2. Agent credential / secret resolution

Finding: **there is no generic credential-reference resolver in the agent.** What exists is fixed-purpose:
- `agent/config.go:25` `loadConfig`: `BAS_AGENT_SECRET` env, then `readEncryptedSecretPlatform()` (`agent/platform_windows.go:138` DPAPI-decrypted registry value via `ReadEncryptedSecret`; `agent/platform_posix.go:33` reads the service config file via `readAgentSecret` in `service_linux.go` / `service_darwin.go`).
- `agent/config.go:77` `resolveProxyCredentials`: `BAS_PROXY_USER` / `BAS_PROXY_PASSWORD` env, then `readProxyCredentialsPlatform()` (DPAPI on Windows, service config file on POSIX).
- Step-level `Env map[string]string` is `json:"-"` on the wire (`agent/protocol/messages.go:92`): it is filled agent-side from policy (`policy_env.go`), so the server cannot push secrets through it. Good: matches "reference, never secret".

Proposal (still reference-only, minimal, follows the proxy-credential precedent): probe spec carries `credentialRef` (an opaque name like `dbcred:lab-pg-readonly`). The agent resolves in this order: (1) env `BAS_DBCRED_<NAME>` holding a JSON `{"user":...,"password":...}`; (2) a per-name entry in a new agent-local store: DPAPI-protected registry value on Windows (reuse the existing DPAPI helper used by `ReadProxyCredentials`), a root-only `0600` file next to the service config on POSIX. Unresolvable ref -> probe result `SKIPPED` with reason, never a fallback to a default account. Resolved secrets live only in a local variable passed to the driver DSN builder (never a string logged; extend the logger redaction list). Server-side the registry stores only the ref name and the expected target identity (R6). This needs an Admin-facing doc on how the operator provisions the ref on the agent host; there is no server-to-agent secret push.

### B3. Scoring-layer result type and persistence

Two live patterns exist; recommendation is the second.

1. Main run pipeline: agent posts raw results to `Handler.SubmitScenarioResult` (`orchestrator/internal/api/handlers.go:2972`), body is `scenario.RawRunResult`; the server interprets exit code/output (`scenario/interpreter.go`, `scenario/outcome.go` `ExecutionOutcome`/`classifyExecution`) into `models.SimulationResult` (`models/schema.go:45`, `Result models.CheckResult` = `pass|fail|skipped|blocked|error|vetoed`) and stores them in `scenario_runs.results jsonb` (`db/postgres.go:129`), `score jsonb`, plus `scenario_variant_results` for variants. This path is built around shell exit codes and ATT&CK technique steps; `execStep` returns `protocol.ExecResult` with only `Stdout/Stderr/ExitCode` (`agent/protocol/messages.go:101`), so a `dbprobe` result must be JSON in `Stdout` or a new optional `ExecResult` field. Integration is real but lossy for the multi-dimension verdict.
2. Dedicated domain store (used by apibas, rwevidence, phishing runs, cloud runs, email gw runs): own table and `db/*_store.go`, own package type, results graded `PASS|FAIL|ERROR|SKIPPED` as strings. Example: `db.APIBASRun{... Result string // PASS, FAIL, ERROR or SKIPPED ... Report []byte}` with `validate()` and `SaveAPIBASRun` (`orchestrator/internal/db/apibas_store.go:15-84`); `phishing_runs` with `EnsurePhishingRunSchema` / `InsertPhishingRun` (`db/phishingrun_store.go`). Notes: `dlpreport.Record` is not persisted anywhere today (C8).

Recommendation: dbsim uses pattern 2: a `dbsim_runs` table (+ `EnsureDBSimRunSchema`) storing the full report JSON (the `dlpreport.Record` per scenario plus probe/audit evidence refs) with the graded result as `PASS|FAIL|ERROR|SKIPPED` copied out for querying, **and** emits the `models.CheckResult` mapping (`pass/fail/error/skipped`; `vetoed` for an agent-side gate refusal) only if/when the run is surfaced through the generic results view. Map `Blocked`-style prevention to `models.ResultBlocked` only for real prevention evidence; `ResultVetoed` must stay distinct from customer prevention (see comment at `models/schema.go:24-32`). Open sub-decision for Task planning: whether a dbsim run also writes a `scenario_runs` row so existing run-list UI works; default is no (own list).

### B4. Existing DLP-DB channel

Exists as scenario `scenarios/dlp-exfiltration-db-export.yaml` (`product_line: dlp`, windows only, "closes the DLP-DB gap named in dlp.txt 1.06 and 3B"). Verified by reading its header: it frames synthetic text as DB extract / BI / ERP / warehouse exports and exfiltrates over existing SFTP/cloud/webhook sinks; its description states "does not implement a real database client". Also `dlpfixture/catalog.go:126` (PostgreSQL connection string fixture) and `dlpprofile/catalog.go:151`. Conclusion: nothing to reuse for probes, adapters, or audit; it is the content-exfiltration view of "DB data leaving", dbsim is the access/grants/audit view. Keep ids and report labels distinct to avoid users conflating "DLP-DB" results with dbsim DB-xx results. Synthetic value patterns may be borrowed from `dlpfixture` as spec sec 3 says.

### B5. Build / size impact (drivers `pgx/v5` + `go-sql-driver/mysql`)

Method: copy of `agent/` (excluding `logs`, binaries) into the scratchpad `...\scratchpad\b5\agent`, `GOWORK=off`, `GOMAXPROCS=2`, `go get github.com/jackc/pgx/v5@v5.9.2 github.com/go-sql-driver/mysql@latest`, added `zz_dbdrivers.go` with blank imports of `pgx/v5/stdlib` and `mysql` plus a `database/sql` reference so they link. Build line mirrors the Dockerfile minus garble: `CGO_ENABLED=0 go build -p 1 -trimpath -ldflags="-s -w"`. Nothing in the real tree was changed.

| Target (amd64 unless noted) | Baseline | With drivers | Delta |
|---|---|---|---|
| windows | 9,517,056 | 13,762,560 | +4,245,504 (+44.6%) |
| linux | 7,733,410 | 11,858,082 | +4,124,672 (+53.3%) |
| darwin | 7,830,816 | 12,060,960 | +4,230,144 (+54.0%) |
| linux/arm64 | n/a | 11,141,282 | built OK |
| darwin/arm64 | n/a | 11,366,370 | built OK |

All five targets built with `CGO_ENABLED=0` (both drivers are pure Go; new modules pulled: `filippo.io/edwards25519 v1.2.0`, `golang.org/x/text v0.29.0`, `pgpassfile`, `pgservicefile`; `go` directive stayed `1.26.6`). Expect the final delta to be a little larger once real adapter code is added. Caveat: `golang.org/x/text` is new to the agent module; `go.work.sum`/`agent/go.sum` will change.

Garble (not run here; the real garble build is deferred to staging): `orchestrator/Dockerfile:37-60` builds the agent with `GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w"` for linux amd64/arm64, windows amd64, darwin amd64/arm64 (garble v0.17.0, go 1.26). Because `GOGARBLE` is scoped to `audspect/*`, `-literals` and renaming apply only to our own packages; third-party drivers are left as-is, the same posture the Dockerfile comment documents for `x/sys`, `windigo`, `sspi`, `gorilla/websocket`. So the usual driver risk (reflection and literal rewriting inside a third-party package) is not expected. Residual risks to check on staging: (1) garble build time/memory with a bigger dependency graph (previous hangs came from huge generated files in our own packages, see memory `garble -literals blowup`; the drivers add none of ours); (2) our own probe code must not depend on reflection over our struct field names (render JSON via json tags or explicit maps, per the existing garble-reflection rule; avoid `sql.Rows.Scan` into struct via reflection libraries); (3) `agent-legacy` (go 1.20, separate module, `Dockerfile:109-134`) does not import `agent/` and is unaffected, but the legacy fleet therefore cannot run dbsim steps and must report them SKIPPED/unsupported, not fail. The `windows` agent also links `windigo`; the plain Windows cross-build above passed, which covers the link, not garble.

## (a) Scenario definitions, `.sig`, adding a new family

- Definitions: `scenarios/*.yaml`, each with an adjacent `<name>.yaml.sig` (base64 RSA-SHA256 over the exact file bytes). 188 entries today. Schema: `scenario.Scenario` and `scenario.Step` (`orchestrator/internal/scenario/types.go:269`, `:127`); per-step fields include `executor`, `command`, `marker` (existing host-event marker; format checked by `ValidateMarkers`, `marker.go`), `action_key`, `technique_id`.
- Load and verify: `Engine.Load` (`orchestrator/internal/scenario/engine.go:110`) -> `integrity.ReadBuiltinSignature(e.verifier, ...)` (`engine.go:195`, `integrity/verifier.go:73`; file-based twin `integrity.VerifyScenarioFile`, `integrity/signing.go:67`; skipped only for dev builds with the placeholder public key; missing `.sig` -> `ErrUnsigned`). Content registry intake (`scenario.ContentRegistry`, `registry.go`) runs for builtin/custom/intel sources.
- Signing: `orchestrator/scripts/signer.go` (`go run signer.go sign <private_key.pem> <file>`, `verify-all <dir>`); test `orchestrator/scripts/signer_test.go`. Re-sign after any edit (known trap). The worktree already has `orchestrator/private_key.pem` (gitignored).
- Adding a family: (1) pick/define `product_line`: `license.ProductLine` consts in `orchestrator/internal/license/tier.go:24-38` are a closed set ("the loader refuses any scenario whose value is not a valid product line"); a new `dbsim` line needs a const plus an entry in `tierProductLines` (`tier.go:43`) and `api/product_gate.go` route prefixes (see g). (2) Extend `scenario.Step` with the dbsim step shape (probe id, params, limits) and add a `dbprobe` executor value in the validator (builder `scenario/builder.go` compile path). (3) Write YAMLs in `scenarios/`, sign them. (4) Catalog tests such as `scenario/catalog_test.go` and the corpus audit (`cmd/auditcorpus`) may need the new ids.

## (b) Where execclass classification happens

- Catalog and resolver: `orchestrator/internal/scenario/execclass.go` (`executionClassifications` map technique_id -> action_key -> class; `ResolveExecutionClass` at `:1088`; unknown -> `unclassified` = `destructive`, fail closed). Generated part: `execclass_generated.go` / `execclass_generated.json`; human decisions in `execclass_reviewed.yaml`; generator `cmd/auditcorpus` + `scenario/corpusaudit`.
- Applied at compile time: `AttachExecutionClassifications(steps)` (`execclass.go:1113`) called from `scenario/builder.go:178` and `api/variant_handlers.go:692`. It writes `ExecutionClass`, `DestructiveAction`, `BlastRadius` onto each `ScenarioStep`; the author-set `action_key` is a lookup key only.
- Agent enforcement: `evaluateB5Gate` (`agent/destructiveguard_gate.go:48`) combines the signed class with the agent's own `destructiveguard.Classify` of Command/Cleanup/payload text, most-restrictive wins; called in the step loop at `agent/agent.go` (just before payload staging). Unknown/empty class ranks as destructive.
- Consequences for dbsim: a `dbprobe` step has no shell text for `destructiveguard.Classify`, and an unregistered `(technique_id, action_key)` would be vetoed. Plan must (1) register explicit catalog entries for the dbsim technique/action keys (suggest mapping `read_only` -> `non_destructive`, `bounded_synthetic` -> `potentially_destructive`, `mutation` -> `destructive` so it is vetoed unless a future grant exists), (2) keep `Command` non-executable text (e.g. the probe id) so the local backstop sees nothing, and (3) add the dbsim class/gates as a SEPARATE agent-side check before B5, not by weakening B5.

## (c) Run result persistence and scoring type

See B3. Key symbols: `Handler.SubmitScenarioResult` (`api/handlers.go:2972`), `scenario.RawRunResult`, `models.SimulationResult` / `models.CheckResult`, `scenario_runs` (`db/postgres.go:129`), `db.APIBASRun` / `SaveAPIBASRun`, `db.EnsurePhishingRunSchema` / `InsertPhishingRun`. Result integrity: agent result MAC verified by `h.verifyResultMAC` before parsing.

## (d) Agent step dispatch path for a new `dbprobe` executor, and module sharing

Wire path today:
1. Orchestrator builds `scenario.ScenarioCommand{Steps []scenario.ScenarioStep}` (`scenario/types.go:376-440`), wraps in a signed `CommandEnvelope` (`orchestrator/internal/models/command_envelope.go`), sends over WebSocket.
2. Agent: `connectWS` checks `protocol.IsSignedCommandType` then `verifyCommandEnvelope` (`agent/commandsig.go:47`: version, type, agentId, expiry, RSA signature against enrolled command-signing cert, replay cache), decodes `protocol.ScenarioCommand` (`agent/protocol/messages.go:50`).
3. `decodeStep` (`agent/agent.go:658`) converts `protocol.ScenarioStep` to the local `ScenarioStep` (`agent.go:633`).
4. Step loop (`agent/agent.go` ~925-1075): circuit breaker, **B5 gate** (`evaluateB5Gate`), payload staging, then `execStep(ctx, step, pool)` (`agent/executor.go:173`), which for non-pooled steps calls platform `buildCmd(ctx, step)`: `agent/executor_posix.go:15` (`sh`, default `bash`), `agent/executor_windows.go:38` (`cmd`, `wmi`, `mshta`, ...), and `agent/pool_windows.go:343` (warm PowerShell pool). `Executor` is a free string switched in those three places.

To add `dbprobe` (all file-level touch points):
- `agent/protocol/messages.go`: add `DBProbe json.RawMessage` (or typed `*DBProbeSpec`) to `ScenarioStep`; add result type (carry in `ExecResult` as a new optional field, or JSON in `Stdout`; prefer a typed optional field so nothing parses stdout).
- `agent/agent.go`: mirror the field in the local `ScenarioStep` and copy it in `decodeStep` (it silently drops unknown fields, so omission = probe never runs).
- `agent/executor.go` `execStep`: branch `if strings.EqualFold(step.Executor, "dbprobe")` BEFORE `buildCmd`/pool (neither platform `buildCmd` can express it), calling a new `agent/dbprobe` entry that enforces deadline, row/statement budgets, READ ONLY transaction (R4), fixture cleanup, and returns `protocol.ExecResult`. Also bypass `captureSnapshotLite`/cleanup-script logic (cleanup is the fixture manifest, not a shell string).
- Gate before B5/execution: dbsim local gates (mode, class, scope, probe-id allowlist) in a new agent file; B5 stays as is.
- Orchestrator: `scenario.Step`/`ScenarioStep` fields (`types.go`), dispatch code that builds steps (`api/handlers.go` dispatchRun area, `scenario/builder.go`), result interpretation (new path; `interpreter.go` is shell-output oriented).
- Both modules: the golden-vector test from B1.
- Agent build-tag note: `execStep` is shared across platforms, so the dbprobe package must be build-tag free (pure Go) to satisfy windows/linux/darwin.

Module relationship: see B1/C4. `go.work` joins `agent, agent-legacy, installer, orchestrator, tray` for local dev only; shipped builds are per-module.

## (e) Agent credential handling

See B2.

## (f) DLP-DB under another name

See B4 (and C7).

## (g) Files Task 16 (console / settings / API / RBAC) will touch

- RBAC permissions: `orchestrator/internal/auth/permissions.go` (consts such as `CanViewAPIBASRuns` at `:79`; role grant maps at `:320`, `:387`, `:451`). Add `CanViewDBSimRuns`, `CanRunDBSim`, `CanManageDBSimTargets`, `CanEnableDBSimClientMode` (Admin only, audited, per R8) and place them in the role tables deliberately.
- RBAC tests: `orchestrator/internal/api/rbac_matrix_test.go` (`routeMatrix` at `:39`, `TestRBACMatrix_NoDrift`) must list every new route or the drift test fails.
- Routes: `orchestrator/internal/api/routes.go` (see apibas at `:241`, `:622`; execution-policy admin settings at `:775-776` as the precedent for an Admin on/off setting).
- Licensing gate: `orchestrator/internal/api/product_gate.go` (prefix -> `license.ProductLine`, `:20-21`) and `orchestrator/internal/license/tier.go`.
- Handlers: new `orchestrator/internal/api/dbsim_*_handlers.go` (pattern: `apibas_handlers.go`, `apibas_scenarios_handlers.go`, `phishingrun_*.go`).
- Persistence: new `orchestrator/internal/db/dbsim_store.go` (+ schema ensure call at startup in `cmd/server/main.go`); target registry (R6 identity), settings flag (R8, default off), audit trail (see `web/src/features/audit-logs.js` and the existing audit writer used by other Admin settings).
- Console: `orchestrator/web/index.html` (Settings tab block at `:712`, nav at `:226`), new `orchestrator/web/src/features/dbsim.js` registered from `orchestrator/web/src/main.js`, helpers in `web/src/core/` (`api.js`, `escape.js` required for any rendered DB-derived string; project CSP/inline-style rules apply: `style-src 'self'`, no inline handlers, use `data-on-click` as in `index.html`). Tests under `orchestrator/web/tests/{unit,smoke,visual}`.

## Contract pins written in this task

`orchestrator/internal/dbsim/contracts_test.go` (package `dbsim`, tests only, exported APIs only):
- `TestRecordValidateRequiresLimitationsWhenUncertain`
- `TestElasticBuildQueryScopesByHostNameAndIP` (observes the query on the wire; also pins the absence of any marker/text clause)
- `TestMatchedAlertKeepsRawJSON`
- `TestContractElasticRawJSONIsNormalizedSubset` (pins finding C1; if the Elastic connector is extended so the marker becomes visible, this test must be changed deliberately)

Command: `cd orchestrator; $env:GOMAXPROCS=2; go test -p 1 ./internal/dbsim/ -run 'TestRecord|TestElastic|TestMatched|TestContract' -v` -> 4 PASS. (`-run Contract` alone from the brief matches only the last test, because the other three names, taken verbatim from the brief, do not contain the word.)

## Implications for the plan (for the controller)

1. Amend spec sec 3/6/11 for C1: the plan must include a change to the Elastic connector (smallest: add an optional marker/extra-field mechanism so the query `_source` includes the audited statement field, and `normalizeElasticHit` exposes it, or give `VerifyRequest` an optional free-text term). That touches `detectverify` (additive, Elastic only); the 6 other connectors are not needed for the Phase 4 proof. Alternatively the Elastic detection rule in the lab stack could write the marker into `kibana.alert.rule.name`-visible fields, which is not realistic for a dynamic marker, so connector extension is the honest route.
2. Amend sec 4.1/10-B1 per C4 (separate wire types + golden vector, adapters agent-side).
3. Amend C3 wording (envelope signature, not scenario `.sig`, is what the agent verifies).
4. Add explicit execclass catalog work and a `dbsim` product line to Task planning (C6, section a).
