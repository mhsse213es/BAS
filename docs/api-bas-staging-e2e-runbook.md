# API BAS assessment: staging end-to-end runbook

Status: NOT RUN. Claude Code could not reach staging (SSH key authentication was refused from the build host), so none of this has been executed on staging. The same flow is covered locally by `TestEndToEndRealRunnerAgainstRealLab` (real runner and lab binaries, real Postgres). This runbook is for the person with staging access.

Staging: `zain@audspecterver`, 192.168.10.78. Human API and console are on :9543 (JWT). :9443 is mTLS agents only.

## Rules
- Upgrade with `install.sh --upgrade`. Never `--install` over existing data, never raw `docker compose`.
- Do not change any grading threshold while running this.
- The lab is intentionally vulnerable. Bind it to the staging host address only, for the duration of the test, and stop it afterwards. Check the UFW rule you open and remove it.
- Production targets must be refused. A passing run of section 6 is required before production support is considered.

## 1. Prerequisites
1. A release build that includes this work: the orchestrator image contains `/apibas-runner`, and `install.sh` provisions `/etc/audspect/secrets/db-encryption.key`.
2. Linux build of the lab for the staging host: `GOOS=linux GOARCH=amd64 go build -o apibas-lab ./cmd/apibas-lab` from `orchestrator/`.
3. Take the normal pre-upgrade backup. The first upgrade of an install that never had a key generates one and writes `<DATA_DIR>/.db-key-issued`. Export a recovery copy straight after: `sudo bash install.sh --export-db-key <file>`, then store it off the host.

## 2. Enable and verify
1. After the upgrade, add `BAS_APIBAS_RUNNER=/apibas-runner` to `<DATA_DIR>/.env` and restart the orchestrator through `install.sh` tooling.
2. `ls -ld /etc/audspect/secrets; ls -l /etc/audspect/secrets/db-encryption.key` must show root, group 65532, mode 0640.
3. Orchestrator log must contain `[secretstore] encryption key verified` and must NOT contain `job execution disabled`.
4. Without `BAS_APIBAS_RUNNER`, `POST /api/apibas/jobs` must answer 503. Confirm this before enabling.

## 3. Start the lab
Run as an unprivileged user, with random tokens, on the staging host address (not 0.0.0.0):

    export APIBAS_CUSTOMER_A_TOKEN=$(openssl rand -hex 16) APIBAS_CUSTOMER_B_TOKEN=$(openssl rand -hex 16) APIBAS_LAB_ADMIN_TOKEN=$(openssl rand -hex 16)
    ./apibas-lab -mode vulnerable -fixture orders-two-tenant -addr 192.168.10.78:8099 &
    ./apibas-lab -mode fixed      -fixture orders-two-tenant -addr 192.168.10.78:8100 &

Keep the three token values for section 4.

## 4. Register targets (Admin)
`POST https://192.168.10.78:9543/api/apibas/targets` with a JWT. Send credentials as values; they are stored encrypted and never returned.

    {"id":"stg-vulnerable","name":"staging vulnerable lab","base_url":"http://192.168.10.78:8099","environment":"staging",
     "allowed_hosts":["192.168.10.78:8099"],"allowed_scenarios":["API-BAS-AUTHZ-001"],"enabled":true,
     "credentials":{"apibas/lab/customer-a":"<A>","apibas/lab/customer-b":"<B>","apibas/lab/admin":"<ADMIN>"}}

Repeat for `stg-fixed` on :8100. Check: the response has no credential values; `audit_logs` has `apibas.target.create` with `credential_names` only.

## 5. Run
As an Analyst: `POST /api/apibas/jobs` with `{"key":"stg-run-001","target_id":"stg-vulnerable","fixture":"orders-two-tenant","scenario_ids":["API-BAS-AUTHZ-001"]}`.

| Check | Expected |
|---|---|
| Response | 202 with a job id |
| `GET /api/apibas/jobs/{id}` until done | `completed`, one report, result FAIL, exploitability exploited |
| Same for `stg-fixed` | `completed`, result PASS |
| Same key again | 200, `created:false`, no second execution |
| Second key while one is running on the same target | 409 |
| `audit_logs` | `apibas.job.submit` with the requester, then `apibas.job.finish` with status and timestamps |
| Runner temp files | no `apibas-job-*` directory left in the container's temp dir |

## 6. Failure and safety checks (all required)
1. **Production refusal.** Register a target with `"environment":"production"`; submit a job. Expect 403 and an `apibas.job.refused` audit row. Nothing runs.
2. **Out of scope.** Submit a scenario not in the target's `allowed_scenarios`. Expect 403.
3. **Cancellation.** Start a job, then `POST /api/apibas/jobs/{id}/cancel` while it runs. Expect 202, job `cancelled`, no reports, a cancel audit row. (Use a larger scenario set or `kill -STOP` the lab to hold the run open.)
4. **Timeout.** Hold the lab (`kill -STOP <lab pid>`) and wait for the 15 minute limit. Expect `failed`, reason `execution timed out`, no reports. Resume the lab afterwards.
5. **Target unreachable.** Stop the lab and submit. Expect `completed` with verdict ERROR / TARGET_UNREACHABLE, or `failed`; either way never PASS.
6. **Orchestrator restart mid-run.** Restart the orchestrator while a job runs. After start-up the job must be `failed` with reason `orchestrator stopped while the job was running`.
7. **Credential handling.** `docker exec` is not available (distroless); instead check the job row: `SELECT credential_refs FROM apibas_jobs` shows references only, and `SELECT * FROM apibas_targets` shows no values.
8. **Licence.** With a licence lacking API BAS the endpoints must be refused by the product gate.

## 6a. Customer-bound job (optional, after section 6)
Needs an inventory and stored test data on a registered staging target (see `docs/api-bas-scenario-binding.md`). The target must list the identities' credential names in its credential references and carry allowed path prefixes.
1. `PUT /api/apibas/targets/{id}/binding` with the test data; expect 200 with the scenarios that would be generated.
2. `POST /api/apibas/targets/{id}/binding/jobs` with `{"key": "<unique>"}`; expect 202. A repeated key returns the same job with `created: false`.
3. Poll `GET /api/apibas/jobs/{id}`: scenario ids are `API-BAS-AUTHZ-9xx`; a vulnerable route grades FAIL, an enforcing one PASS.
4. Import a changed spec, then repeat step 2 with a new key; expect 409 until step 1 is repeated.
5. Check `SELECT job_id, inventory_version FROM apibas_job_plans` shows the plan and that no credential value appears in it.

## 7. Clean up
Stop both labs, remove the UFW rules you opened, delete the lab tokens from your shell history, and record results in `docs/api-bas-mastery-qa-log.md`, including every check that failed.
