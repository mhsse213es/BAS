# Carbanak BFSI Pack Expansion — Design

Status: APPROVED (direction and implementation plan, 2026-11-21). Built so far: the ledger service
(`cmd/carbanak-ledger-sim`), the attack-gap schema, Stage 3/4/8 corrections, and scenarios 9 and 23-28.
Remaining: scenarios 10-15, 17-22, 29-32 and validation. See `docs/superpowers/plans/2026-11-17-carbanak-bfsi-expansion.md`.

## Intent

Turn the existing 8-stage Carbanak chain (`scenarios/carbanak-kill-chain.yaml`) into a
flagship BFSI adversary pack. Its differentiator is linking endpoint compromise to whether
the bank's financial controls actually stop fraud. The current Stage 8 writes a decoy text
file and deletes it, so it measures nothing about the bank.

## Goals

1. Keep all eight existing stages, with the corrections below.
2. Add 23 new scenarios, bringing the chain to 31 total.
3. Replace the Stage 8 decoy with a 7-step fraud sequence run against a BAS-hosted simulated
   banking ledger.
4. Record two independent verdicts per step:
   - `endpoint_verdict`: did endpoint security detect or prevent the behavior.
   - `fraud_control_verdict`: did the banking application detect or prevent the unauthorized
     transaction.
   Overall = PASS only when both are PASS.

   | Endpoint | Fraud control | Overall |
   |---|---|---|
   | PASS | PASS | PASS |
   | PASS | FAIL | FAIL |
   | FAIL | PASS | FAIL |
   | FAIL | FAIL | FAIL |

   An endpoint block must not conceal a fraud-control failure, and successful fraud prevention
   must not conceal an endpoint failure.
5. Give every simulated transaction a complete, tamper-evident audit trail in the ledger.

## Non-goals

- No connection to real banking, SWIFT, card, or ATM infrastructure.
- No real operator credentials are read, retrieved, or used. All identities are synthetic.
- No model of the Google Apps Script ggldr C2 tunnel (already documented as unmodeled).
- Not a claim that any real bank's controls were validated. Results describe the simulated
  ledger and the lab endpoint.

## Anti-goals

- A ledger that judges itself with a scenario-side script. Decisions come from rules the
  ledger enforces on its own API; the scenario reads them back.
- A PASS in one verdict silently counting toward the other.
- Any step reporting PASS or FAIL when its precondition (ledger not running, target host
  unset) is missing. It reports SKIP or ERROR with a reason.

## Constraints

- Windows-only endpoint stages (`supported_os: [windows]`).
- Signing gate: every edit to a scenario file requires re-signing its `.sig`.
- Step-contract ledger and baseline regenerated (`STEP_CONTRACT_WRITE=1`) with no new gaps.
- `TestBuiltinScenarios_AllHaveValidProductLine` checks a floor of 180, not an exact count;
  no bump is needed for each file added.
- Credential-access tier (from the approved APT29 work): LSASS uses query-only
  `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000), never `PROCESS_VM_READ`. Credential Manager and
  browser stores are enumerated or probed for existence only, never read.
- Lateral-movement stages need a second host. Gate them like APT29 stages 8/24-26:
  `BAS_CARBANAK_TARGET_HOST` unset -> SKIP with a reason.
- Ledger binds to `127.0.0.1` by default. Non-loopback use requires an explicit env override
  and a host label ending in `.test`, `.invalid`, or `.lab`. A production hostname is refused.
- Existing tags, detection profiles, and `[BAS-SIM-CARBANAK-Sn]` markers kept for the original
  eight stages.

## Corrections to the existing chain

- **Stage 3 (netsh firewall rule):** remap to **T1686.003** (Windows Host Firewall). The spec's
  suggested T1686.001 is wrong: MITRE defines T1686.001 as cloud firewalls, T1686.002 as network
  device firewalls, and T1686.003 as the Windows host firewall. Verified on attack.mitre.org.
- **Stage 4 (LSASS):** change `0x1010` to `0x1000` (query-only), per the approved tier.
- **Stage 8 (fraudulent transfer):** replace with the 7-step sequence below. The decoy-file
  behavior is removed.

## Architecture

### Simulated banking ledger (new component)

A small Go service, `carbanak-ledger-sim`, run in the lab by an explicit documented command on
the test endpoint (not by the scenario, not shipped in the agent package). Default
`127.0.0.1:8745`, overridable by env. Exposes a local HTTP API and keeps an append-only,
hash-chained audit log.

**Trust model (builder-check call):** the ledger owns the identity and role schema, loaded from a
config file on the ledger host. A scenario supplies only a synthetic credential. The ledger derives
the caller host from the connection source and never trusts a host field from the request.

**Operating window (approved):** timezone Asia/Kolkata (IST); normal hours Monday–Friday
09:00–18:00 IST; outside = before 09:00, after 18:00, and weekends. Configurable per test
environment; these defaults are for the lab, not a universal banking policy. Results are
deterministic: the clock is a fixed test clock or an explicit timestamp input (env
`BAS_CARBANAK_FIXED_TIME`).

Enforced rules (each produces a recorded decision):

| Rule | Decision on violation |
|---|---|
| Maker-checker: approver == initiator (self-approval, step 8d) | rejected |
| Approval by an identity with no approver role (step 8e) | rejected |
| Beneficiary added or changed without a second approver | rejected |
| Amount above the operator's limit | flagged (routed for review) |
| Limit modification without privileged role | rejected |
| Transaction outside the operating window | flagged |
| Session reuse from a different host or after timeout | flagged |
| Otherwise | approved |

Every decision is an audit row: `run_id`, `step`, `actor`, `action`, `decision`, `rule_fired`,
`prev_hash`, `hash`.

Endpoints (sketch): `POST /session`, `POST /beneficiary`, `POST /transfer`, `POST /approve`,
`PUT /limit`, `GET /audit?run_id=`, `GET /alerts?run_id=`.

### Fraud sequence (replaces Stage 8)

One shared run and ledger state, in order. Evidence carries across steps.

| # | Step | Ledger call | Fraud-control result |
|---|---|---|---|
| 8a | Valid operator authentication | `POST /session` | approved / rejected |
| 8b | Unauthorized beneficiary modification | `POST /beneficiary` (no second approver) | rejected = prevented; approved = failed control |
| 8c | Transaction initiation | `POST /transfer` | approved / flagged |
| 8d | Self-approval by the initiator | `POST /approve` (approver == initiator) | rejected = prevented |
| 8e | Approval by a non-approver identity | `POST /approve` (identity with no approver role) | rejected = prevented |
| 8f | Ledger integrity | `GET /audit`, verify hash chain | intact / tampered |
| 8g | Fraud detection and alert | `GET /alerts?run_id=` | alert present / absent |

Each sub-step writes two records: the endpoint record and the fraud-control record.

### Independence between scenarios (builder-check call)

- 8a–8g live in the Carbanak file and share one run_id and ledger state, in order.
- Items 23–28 are separate scenarios. Each starts with a fresh run_id and creates its own state.
  They never inherit the shared sequence's transactions or approvals.

### New scenarios

Spec item 16 (LSASS query-only) duplicates existing Stage 4 after the 0x1000 change, so it is not
added twice. Total 31. Item 9 stays a separate scenario and Stage 5 is untouched (approved).

| Spec # | Scenario | ATT&CK | Status |
|---|---|---|---|
| 9 | Banking application and process discovery | T1057 | validated (see below) |
| 10 | Payment gateway configuration discovery | T1083 | validated 2026-11-21 (attack.mitre.org T1083 page) |
| 11 | Database server and service discovery | T1046 | validated 2026-11-21 (attack.mitre.org T1046 page); scoped to local listeners |
| 12 | Domain privileged account enumeration | T1069.002 | validated 2026-11-21 (attack.mitre.org T1069/002 page) |
| 13 | Network share discovery for financial data | T1135 | validated 2026-11-21 (attack.mitre.org T1135 page); scoped to local shares |
| 14 | Windows Credential Manager access attempt | T1555.004 | validated 2026-11-21 (attack.mitre.org T1555/004 page); existence check only |
| 15 | Browser credential-store access probe | T1555.003 | validated 2026-11-21 (attack.mitre.org T1555/003 page); existence check only |
| 17 | Kerberos service account enumeration | T1558.003 | validated 2026-11-21 (attack.mitre.org T1558/003 page); LDAP query only, no ticket requested |
| 18 | Synthetic operator credential discovery | T1552 | validated 2026-11-21 at parent level; T1552.001 (Credentials In Files) is the likely refinement, to confirm against its page |
| 19 | SMB administrative share access | T1021.002 | validated 2026-11-21 (attack.mitre.org T1021/002 page); existence check only; needs `BAS_CARBANAK_TARGET_HOST` |
| 20 | WinRM remote execution simulation | T1021.006 | validated 2026-11-21 (attack.mitre.org T1021/006 page); benign echo only; needs target host |
| 21 | Remote service creation | T1569.002 | validated 2026-11-21 with caveat: the service is created and removed but never started, so this exercises creation, not payload execution; needs target host |
| 22 | Remote scheduled task creation | T1053.005 | validated 2026-11-21 (attack.mitre.org T1053/005 page); task dated 2099 and removed; needs target host |
| 23 | Unauthorized payment beneficiary creation | none: `no_clean_attack_technique` | excluded from ATT&CK coverage %; included in execution and fraud-control reporting |
| 24 | Transaction amount manipulation | T1565.002 (proposed) | validated with caveat |
| 25 | Unauthorized transaction approval | T1078 (proposed) | validated with caveat |
| 26 | Operator session misuse | T1078 (proposed) | validated |
| 27 | Payment transaction outside normal hours | T1078 (proposed) | validated with caveat |
| 28 | Transaction limit modification attempt | none: `no_clean_attack_technique` | excluded from ATT&CK coverage %; included in execution and fraud-control reporting |
| 29 | Financial document collection | T1005 | to validate at build |
| 30 | Payment database staging simulation | T1074.001 | to validate at build |
| 31 | Archive financial records | T1560.001 | to validate at build |
| 32 | HTTPS financial data exfiltration simulation | T1041 | to validate at build; `.invalid` domain |

Only items 9 and 23–28 were validated in this pass; the rest are validated during the build.

## ATT&CK mapping validation (items 23–28 and Stage 3)

Source for every row: attack.mitre.org technique pages, checked by search on the official site.
Confidence reflects how well the technique description matches the simulated behavior.

| Item | Scenario | Proposed | Result | Confidence | Status |
|---|---|---|---|---|---|
| Stage 3 | netsh host firewall rule | T1686.001 (spec) | Wrong: T1686.001 is cloud firewalls. Host firewall is **T1686.003** | high | validated, corrected to T1686.003 |
| 9 | Banking application and process discovery | T1057 | Matches process discovery of banking apps | high | validated |
| 23 | Unauthorized beneficiary creation | none | No clean fit. T1098 is account manipulation; a payee record is not an account used to keep adversary access. T1565.001 is not used: it needs stored-data manipulation, which this scenario does not perform. | n/a | **`no_clean_attack_technique`** |
| 24 | Transaction amount manipulation | T1565.002 | Fits "altering data in transit". Caveat: the simulation alters the request on the way to the ledger, not stored data | medium | validated with caveat |
| 25 | Unauthorized transaction approval | T1078 | Fits valid-credential use. Maker-checker bypass is authorization abuse, which the technique describes less directly | medium | validated with caveat |
| 26 | Operator session misuse | T1078 | Fits valid-account use | high | validated |
| 27 | Payment outside normal hours | T1078 | Off-hours is a detection rule, not a technique. The behavior is valid-account use | medium | validated with caveat |
| 28 | Transaction limit modification | none | No clean fit. A transaction limit is a business policy control, not an identity-account modification. | n/a | **`no_clean_attack_technique`** |

Sub-technique for 25–27: T1078 parent. Sub-technique (T1078.002 Domain Accounts) assumed for
Windows-domain operators; confirm against the lab's account model at build.

Rules for proposed mappings (approved):
- Keep the proposed ID in metadata with `mapping: proposed` in the description.
- Exclude `proposed` mappings from coverage reporting.
- Do not publish a mapping as validated until its status is validated.

## Outcome evidence

Each step keeps its existing execution and detection fields. The fraud-control decision is a
separate record in the step output (`fraud_control: {verdict, decision, rule_fired, audit_hash}`),
not folded into `DetectionVerdict`. The builder confirms the exact model fields against
`orchestrator/internal/scenario/outcome.go` before writing code.

## Acceptance criteria

Ledger service:
1. Each rule in the table has a unit test asserting the decision and `rule_fired`.
2. The audit hash chain verifies after a run. A tampered row fails verification (8f).
3. The audit log survives a ledger restart.
4. The ledger binds to loopback by default and refuses a non-loopback host without the override and
   a `.test`/`.invalid`/`.lab` label.
5. With `BAS_CARBANAK_FIXED_TIME` set, results are identical across runs.

Scenarios:
6. Every step emits `endpoint_verdict` and `fraud_control_verdict`. Overall is PASS only when both
   are PASS.
7. An endpoint block with no ledger call is recorded as endpoint PASS and fraud-control NOT-EVALUATED,
   and the overall verdict is not PASS.
8. The ledger down, or `BAS_CARBANAK_TARGET_HOST` unset, produces SKIP or ERROR with the reason, never
   PASS.
9. 8a–8g share one run_id and state. Items 23–28 each start a fresh run_id with no inherited state.
10. LSASS uses 0x1000 only. Credential Manager and browser stores are not read.
11. Proposed mappings do not appear in ATT&CK coverage reporting. Validated mappings do.
11a. Items 23 and 28 have an empty ATT&CK technique ID with reason `no_clean_attack_technique`.
    They are excluded from ATT&CK coverage percentages, and included in scenario execution and
    fraud-control efficacy reporting.

Registration and verification:
12. `TestBuiltinScenarios_AllHaveValidProductLine` count bumped by one per added file.
13. Step-contract ledger/baseline regenerated, with no new gaps on touched files.
14. Each touched `.sig` re-signed; `signer.go verify-all` reports zero failures.
15. `go test ./internal/scenario/...` green.

## Builder-check calls (reversible)

- Ledger start by a documented command, not by the scenario. Default port `8745`. If the port is in
  use, the fraud steps report ERROR.
- Hash-chain format and verification routine: builder decides, within criterion 2.
- Ledger service placement in the repo and its build target: builder decides.
- Stage 5 untouched; item 9 separate (approved).

## Open decisions for you

Decided: items 23 and 28 use `no_clean_attack_technique` (option b). No open decisions remain in
this doc.

Ruling (plan Task 0): scenarios 24-27 are "validated with caveat", so their mappings count as validated
and carry no `mapping: proposed` marker. Cost if wrong: caveated mappings appear in coverage reporting;
reversible in one edit. Next: implementation plan, which is not to be executed until the plan and acceptance
criteria are approved.
