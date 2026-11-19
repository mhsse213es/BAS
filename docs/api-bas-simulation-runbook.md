# API BAS: how to simulate the whole product

This runbook shows how to run every API BAS check we have, from a single scenario to a full customer-style assessment, on a developer machine or a lab. It covers what each level proves and what it does not.

**Status (11 November 2026):**

| Level | What it proves | Status |
|---|---|---|
| 1. Lab validation | The scenarios and the grader work against the built-in lab | **Executed.** 148 of 151 validated; evidence in `docs/api-bas-evidence/level1-2026-11-11/`. |
| 2. Product path | The orchestrator's job lifecycle, authorisation, persistence and audit | **Not executed.** Commands below are written, not yet run. |
| 3. Customer API | Compatibility with an external API | **Not executed.** Blocked until the OpenAPI mismatch in section 3 is resolved. |

Passing level 1 does not establish level 2 or level 3 readiness. Read this first: lab results show that a scenario and its grader work against a deliberately flawed lab. They are not evidence about any customer's API. No customer or staging API has been run yet (see section 6).

## 0. What you need

- The repository at `origin/main`, in a clean checkout. Do not run from a working tree with other people's uncommitted changes.
- Go (the version in `orchestrator/go.mod`).
- Docker, if you run the database-backed tests or a local Postgres.
- For level 2 only: a running orchestrator with a database and a licence, set up the way your install does it. See `docs/api-bas-staging-e2e-runbook.md` section 1.

Build the two tools from `orchestrator/`:

    go build -o bin/apibas-lab ./cmd/apibas-lab
    go build -o bin/apibas-runner ./cmd/apibas-runner

## 1. Level 1: every catalogued scenario against the lab

No server, no database. This runs all 151 catalogued scenarios against the lab in both its vulnerable and fixed builds, and feeds the verdicts to the coverage measure:

    cd orchestrator
    go test ./internal/apibas/runner/ -run 'TestPhase28_MeasuredCoverage$' -count=1 -v -timeout 25m

Expected: for each scenario, the vulnerable build grades FAIL with exploitability `exploited`, and the fixed build grades PASS with control `enforced`. The 11 November 2026 run matched this: 148 of 151 validated; `API-BAS-ABUSE-002` is provisional (its timing ceiling is unapproved, though its verdicts match); `API-BAS-REPORT-001` is workflow-verified (simulated receiver); `API-BAS-REPORT-002` is unevaluated (no deadline in the provision). The full evidence, including a verdict per scenario, is in `docs/api-bas-evidence/level1-2026-11-11/`. If your numbers differ, check that file's commit and the catalogue before assuming a regression.

To get a verdict per scenario, the test must write them out; it does not do that by default. The evidence used a temporary change that was not committed.

Run the single end-to-end test that drives the real runner and lab binaries against real Postgres:

    go test ./internal/apibas/jobs/ -run TestEndToEndRealRunnerAgainstRealLab -count=1 -v

## 2. Level 2: the product path (jobs, audit, safety checks)

This exercises what the console and the API do: target registration, job submission, grading, audit rows and refusals.

### 2.1 Start the two labs

The lab refuses to start without its three tokens. Generate them first, and keep them for step 2.3:

    export APIBAS_CUSTOMER_A_TOKEN=$(openssl rand -hex 16)
    export APIBAS_CUSTOMER_B_TOKEN=$(openssl rand -hex 16)
    export APIBAS_LAB_ADMIN_TOKEN=$(openssl rand -hex 16)

    ./bin/apibas-lab -mode vulnerable -fixture orders-two-tenant -addr 127.0.0.1:8099 &
    ./bin/apibas-lab -mode fixed      -fixture orders-two-tenant -addr 127.0.0.1:8100 &

Fixtures are `orders-two-tenant`, `orders-no-protected` and `orders-paged`. Optional flags:

- `-fault authz-store-down` or `-fault fraud-check-down` holds a dependency fault active, to test how a target behaves when a dependency is down.
- `-tls` serves HTTPS with a generated lab CA, for the client-certificate scenarios. Use `-tls-ca` and `-tls-client-cert` to write the CA and a client certificate.

Keep both labs on loopback, or on a host address you have chosen, and stop them when you finish. Do not bind them to `0.0.0.0`.

### 2.2 Register the two targets

Send credential values in the `credentials` field. The server stores them in the secret store, never returns them, and records only the names in the audit log. Replace the placeholders with the tokens from 2.1.

    POST /api/apibas/targets
    {"id":"local-vulnerable","name":"local vulnerable lab","base_url":"http://127.0.0.1:8099",
     "environment":"lab","allowed_hosts":["127.0.0.1:8099"],"allowed_scenarios":["API-BAS-AUTHZ-001"],
     "enabled":true,
     "credentials":{"apibas/lab/customer-a":"<customer-a token>",
                    "apibas/lab/customer-b":"<customer-b token>",
                    "apibas/lab/admin":"<admin token>"}}

Register `local-fixed` the same way, with port 8100. Check that the response contains no credential values and that the audit log has `apibas.target.create` with credential names only.

### 2.3 Submit a job

    POST /api/apibas/jobs
    {"key":"local-run-001","target_id":"local-vulnerable","fixture":"orders-two-tenant",
     "scenario_ids":["API-BAS-AUTHZ-001"]}

| Check | Expected |
|---|---|
| Response | 202 with a job id |
| `GET /api/apibas/jobs/{id}` until done | `completed`, one report, FAIL, exploitability exploited |
| The same request against `local-fixed` | `completed`, PASS |
| Same key sent again | 200, `created:false`, nothing runs twice |
| A second job on the same target while one runs | 409 |
| Audit log | `apibas.job.submit`, then `apibas.job.finish` with status and times |

### 2.4 Safety and failure checks

Run all of these. Each one must behave as stated; if one does not, record it in the QA log.

1. **Production refusal.** Register a target with `"environment":"production"` and submit a job. Expect 403, an `apibas.job.refused` audit row, and nothing executed.
2. **Out of scope.** Submit a scenario that is not in the target's `allowed_scenarios`. Expect 403.
3. **Cancellation.** Start a job and cancel it while it runs (`POST /api/apibas/jobs/{id}/cancel`). Expect 202, status `cancelled`, no reports, and a cancel audit row. Hold the run open first with a larger scenario set or by pausing the lab with `kill -STOP`.
4. **Timeout.** Pause the lab with `kill -STOP <pid>` and wait for the 15-minute limit. Expect `failed` with reason `execution timed out` and no reports. Resume the lab with `kill -CONT`.
5. **Target unreachable.** Stop the lab and submit. Expect `completed` with an ERROR verdict (TARGET_UNREACHABLE), or `failed`. Never PASS.
6. **Restart mid-run.** Restart the orchestrator while a job is running. After start-up the job must be `failed` with reason `orchestrator stopped while the job was running`.
7. **Credential handling.** Check the database, not the logs: `apibas_jobs` holds references only, and `apibas_targets` holds no values.

## 3. Level 3: a customer's own API (bound checks)

Bound checks use the customer's own description and test data: identities, owned objects and protected values, named by credential reference rather than value. The format and the grading rules are in `docs/api-bas-scenario-binding.md`. This level covers:

- OpenAPI 3 and Swagger 2 descriptions, and GraphQL schemas (import, then bind)
- read checks, function-level and property-level checks
- GraphQL queries (graded on the response, since GraphQL errors usually come back as HTTP 200)
- write checks, which change an object and restore it afterwards (only with test objects you accept will change)
- mass-assignment checks, and scheduled runs

To run level 3 you need a target whose API matches the description. The built-in lab does **not** match the sample `orchestrator/internal/apibas/openapi/testdata/shop.yaml`: the sample uses `/v2/...` routes and the lab serves `/api/...` routes. Use your own API, or a lab built to match the description, before expecting bound results.

Write checks need the target to register allowed paths. Scheduled runs are lab and staging only, and need stored test data first.

## 4. Reading the results

- **PASS** with control `enforced`: the attack was refused, or no protected value appeared.
- **FAIL** with exploitability `exploited`: the attack succeeded and the evidence shows it.
- **ERROR**: something went wrong in the test itself. It is never a pass.
- **SKIPPED**: the test could not be judged (for example, the owner's own baseline did not return the expected data, or the read route could not show a change). It is not a pass either.

Some checks cannot see everything. A read check only sees what its read route returns. A GraphQL check only sees the protected values you supplied. A mass-assignment check only sees the fields you listed. The job's limits section says what each scenario cannot see.

## 5. Clean up

Stop both labs. Remove any firewall rule you opened. Clear the three tokens from your shell (`unset APIBAS_CUSTOMER_A_TOKEN APIBAS_CUSTOMER_B_TOKEN APIBAS_LAB_ADMIN_TOKEN`). Delete the test targets if the server is shared. Record the results, including every check that failed, in `docs/api-bas-mastery-qa-log.md`.

## 6. What has not been proven

- No customer API has been tested with any of this.
- No staging run has been done (`docs/api-bas-staging-e2e-runbook.md` is marked NOT RUN).
- Browser checks were done only on a local console, not on a server with real data.
- The reporting scenarios use a simulated receiver, not a real CERT-In endpoint.
- `API-BAS-ABUSE-002` is timing-sensitive, and its classification has been unstable between runs.
- `API-BAS-REPORT-002` cannot pass until a provision-derived deadline is recorded.
