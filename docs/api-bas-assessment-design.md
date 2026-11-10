# API BAS first-class assessment: design proposal (no code)

Status: APPROVED 4 November 2026 (all four decisions, with the additional conditions in section 5). Implementation follows the order in section 2.5. Nothing is implemented yet.
Date: 4 November 2026
Source: review of the current state (pasted review, verified in code on this date).

## 1. Verified current state

| Capability | Verified in code | Evidence |
|---|---|---|
| Scenario catalog | Yes, 121 catalog files | `internal/apibas/catalog/*.yaml`, served at `GET /api/scenarios/api-bas` (`apibas_scenarios_handlers.go`) |
| Listed in Scenarios view | Yes, as its own product line | `web/src/features/attack-path.js` (product order and labels), `scn-rich.js` |
| Product-line licensing | Yes | `product_gate.go`: `/api/scenarios/api-bas` and `/api/apibas` gated by `license.ProductAPIBAS` |
| CLI execution | Yes | `cmd/apibas-runner`, `cmd/apibas-lab` |
| Results API | Read-only | `GET /api/apibas/runs`, `GET /api/apibas/runs/{id}` (`apibas_handlers.go`, `db/apibas_store.go`). No write endpoint. |
| Persistent run history | Yes, written by the CLI runner | `apibas-runner` writes via `APIBAS_DB_DSN` into `SaveAPIBASRun` (`db/apibas_store.go:56`) |
| Run creation from the UI or API | No | No route creates a run (`routes.go` lists only the scenario list and the two read routes) |
| Orchestrator scheduling or invocation | No | Nothing in `internal/api` or `internal/apibas` starts the runner |
| UI execution, UI results, comparisons | No | No web feature calls `/api/apibas/runs`; `threat-intel.js` only counts scenarios |

Two corrections to the review's table:
- "Results API: verify implementation" resolves to read-only. It works, but no part of the product creates the data it reads except the CLI.
- The runner holds a database write credential (`APIBAS_DB_DSN`). That is a security problem for a commercial product and is removed by the design below.

## 2. Proposed design

### 2.1 Execution boundary
- API BAS keeps its own execution engine. It does not run through the normal scenario engine, and its scenarios stay out of the normal Run button.
- The orchestrator owns the job. A **Run assessment** action creates a job row, checks authorization, licence and scope, then starts the runner as a child process.
- The runner stops writing to the database. It writes a result document (JSON) to a job-scoped path, and the orchestrator reads it, validates it, and persists it. `APIBAS_DB_DSN` is removed from the runner.
- The CLI keeps working for lab and automation use. It writes a JSON result file and does not touch the product database.

### 2.2 Target and credentials
- Operators register an **API target**: base URL, environment (lab, staging, production), authentication method, and permitted scope (hosts, paths, identities).
- Target credentials are stored through the D4 secret store as references (`cred:apibas_targets:<id>:<column>`), not in environment variables. The runner receives a credential only for the duration of one job, through the orchestrator (stdin or a job-scoped file with mode 0600), never on the command line.
- The lab environment variables stay as they are for the isolated lab only.

### 2.3 Safety controls (enforced by the orchestrator before start)
- Licence: `ProductAPIBAS` required.
- Permission: a new `CanRunAPIBAS` permission, separate from `CanViewAPIBASRuns`.
- Scope: the scenario's requests must stay within the target's permitted hosts and paths. Checked before start, and the runner is given the allow-list only.
- Approval: per-run live approval by an operator with the approval role, as recorded in the earlier decisions (f74c). Production targets require it. No production schedules.
- Concurrency: one active assessment per target. Global cap configurable.
- Timeout: job-level deadline; the runner is killed on expiry and the job is marked failed.
- Audit: start, approval, completion and cancel are written to `audit_logs`.

### 2.4 Results and UI
- Results reuse the existing `apibas_runs` table, written by the orchestrator. Evidence references are stored, not raw response bodies (per the earlier decision: no raw bodies).
- The UI shows: job status, exploitability verdict, detection verdict, evidence references, failures, and history for the same scenario and target.
- Comparisons across runs are a second step, after the single-run view.

### 2.5 Phasing (superseded by section 6)
1. Job model and orchestrator start path, with the runner writing JSON instead of the database. CLI tests updated.
2. Target registration (API and minimal UI) with secret references.
3. Run assessment action, approval, safety checks, audit.
4. Results view, then history and comparison.

Each phase gets its own QA section, commit and fresh-clone check, as before.

## 3. Decisions (approved)

1. **Runner boundary: child process (approved).** Orchestrator owns execution and lifecycle. The runner receives a scoped job request and returns structured JSON. The runner has no PostgreSQL credentials and no direct database access. The orchestrator validates output before persisting it. Process isolation, execution timeout, cancellation and bounded resource use are enforced. A runner crash or malformed output must never produce a successful run.
2. **Production approval: separate approver role (approved).** Lab and staging runs require `CanRunAPIBAS`. Production runs also require explicit approval by a user holding a dedicated approval permission. The requester cannot approve their own production run. Approval is bound to the target, scenario set, scope and run configuration. Any material change invalidates it.
3. **First release: lab and staging only (approved).** The execution service rejects production targets. Hiding or disabling them in the UI is not enough. Production support waits until staging has verified approval enforcement, audit records, cancellation, timeout and failure handling.
4. **Credential source: D4 secret store (approved).** Uses the approved reference-based interface. Credentials are resolved only when the job starts, passed to the child process through a protected mechanism (never command-line arguments or persisted job records), and cleared after execution. Vault remains a future provider, not a dependency.

## 4. What this does not change
- The grading model, the scenario contract and the detection rules.
- The licence gating already in place.
- The normal scenario engine and its Run button.

## 5. Acceptance requirements (added before coding, as approved)

Implementation must satisfy every item below. Each one is tested before its phase closes.

1. **No runner database access.** The orchestrator-launched runner does not read `APIBAS_DB_DSN` and holds no PostgreSQL credential. Direct database writes in the runner are removed. The CLI does not write to the product database either.
2. **Job idempotency.** Each job has a unique key. A retried dispatch for the same key does not start a second execution. A job already running or completed returns its existing state.
3. **Approval binding.** An approval records the target ID, the scenario set (sorted IDs and a hash), the scope and the run configuration. It cannot be reused for a different target or scenario set. Any change to those fields invalidates it.
4. **Result validation.** Before persistence the orchestrator checks: schema version, run ID matches the job, target identity matches the job, every scenario ID is in the approved set, and every evidence reference resolves to the job's own evidence location. Failing any check fails the job. Nothing partial is persisted as success.
5. **Auditability.** Each job records requester, approver (production only), target, scope, start and end timestamps, outcome and failure reason. Recorded in `audit_logs`.
6. **Isolation.** The child process gets an allow-list of environment variables only. It does not inherit host or unrelated credentials. Credentials arrive through a protected channel (a job-scoped file with mode 0600, or stdin), are deleted after the run, and never appear in logs, arguments or job records.
7. **Failure semantics.** A crash, timeout, cancellation or malformed output produces a failed or cancelled job. It never produces a successful run record.
8. **Production rejection.** The execution service rejects a production target with a dedicated error, regardless of what the UI sends.

## 6. Implementation order (approved)

1. Finalise the design and acceptance criteria (this document).
2. Runner process contract: JSON in, JSON out, no database access.
3. Orchestrator job creation, dispatch, lifecycle and persistence.
4. Authorization, target scope, approval and audit enforcement.
5. End-to-end tests on staging.
6. UI in four phases. The UI does not start until the execution and persistence path works end to end.
