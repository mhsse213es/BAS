# Carbanak BFSI pack: lab runbook

Covers the simulated banking ledger (`carbanak-ledger-sim`) and the scenarios
that run against it. Nothing here connects to a real banking system.

## 1. Start the ledger

Build and start it on a loopback address, or on a lab host whose name ends in
`.test`, `.invalid` or `.lab`.

```
go build -o carbanak-ledger-sim ./cmd/carbanak-ledger-sim
carbanak-ledger-sim --config ledger.json
```

Example `ledger.json` (synthetic identities only; the tokens are not real):

```json
{
  "listen_addr": "127.0.0.1:8745",
  "lab_hostname": "ledger.lab",
  "audit_path": "ledger-audit.jsonl",
  "session_ttl_seconds": 1800,
  "identities": [
    {"id": "op1", "token": "synthetic-op1", "roles": ["operator"], "limit": 100},
    {"id": "op2", "token": "synthetic-op2", "roles": ["operator", "approver"], "limit": 100},
    {"id": "op3", "token": "synthetic-op3", "roles": ["operator"], "limit": 100},
    {"id": "admin", "token": "synthetic-admin", "roles": ["privileged", "approver"], "limit": 100}
  ],
  "window": {"timezone": "Asia/Kolkata", "start_hour": 9, "end_hour": 18, "weekdays": [1, 2, 3, 4, 5]}
}
```

Startup refusals:
- A non-loopback address needs `BAS_CARBANAK_ALLOW_NONLOCAL=1` and a `lab_hostname` ending in `.test`, `.invalid` or `.lab`. Otherwise the ledger exits with code 2.
- A port already in use exits with `ERROR: cannot listen on <addr>: port in use or unavailable`.

## 2. Environment for the scenarios

| Variable | Used by | Purpose |
|---|---|---|
| `BAS_CARBANAK_LEDGER_URL` | fraud steps | Ledger base URL. Default `http://127.0.0.1:8745`. |
| `BAS_CARBANAK_FIXED_TIME` | ledger (start) | RFC3339 instant for the ledger clock. Set it for deterministic off-hours runs, e.g. `2026-11-16T14:30:00Z` for 20:00 IST. |
| `BAS_CARBANAK_OPERATOR_ID` / `_TOKEN` | 8a | Operator identity. Default `op1`. |
| `BAS_CARBANAK_NONAPPROVER_ID` / `_TOKEN` | 8e | Identity with no approver role. Default `op3`. |
| `BAS_CARBANAK_TARGET_HOST` | Stages 19–22 | Lab host for lateral movement. Unset means those stages SKIP. |
| `BAS_CARBANAK_LEDGER_REPLAY_URL` | Item 26 | Ledger reachable from a second host. Unset means item 26 SKIPs. |

## 3. Per-stage evidence checklist

For each stage, confirm in the run output:

- [ ] `EXEC <n>:` line present, with its `[BAS-SIM-CARBANAK-Sn]` marker.
- [ ] Endpoint result recorded (pass, fail, blocked, error, skipped or vetoed).
- [ ] Where the stage calls the ledger: a `BAS-FRAUD-CONTROL` marker with `ledger_called`, `ledger_decision`, `rule_fired` and `audit_hash`.
- [ ] Stages 19–22 and item 26 either ran (target or replay host set) or printed a SKIP line naming the variable.
- [ ] Stage 32 posts only to `192.0.2.1` (RFC 5737, non-routable).
- [ ] Cleanup left no `bas_carbanak_*` files or `BAS-SIM-*` services or tasks on the target.

## 4. Endpoint-vs-fraud reporting check

A fraud step has two verdicts. Confirm the combined result is correct:

| Endpoint | Fraud | Combined (expected) |
|---|---|---|
| PASS | PASS | PASS |
| PASS | FAIL | FAIL |
| PASS | SKIPPED | SKIPPED (not PASS) |
| FAIL | any | FAIL |
The stored result is the combined verdict. A fraud FAIL makes the step FAIL and a
fraud SKIPPED makes it SKIPPED, in every view: scorer, compliance, dashboards, PDF,
CSV and run lists. The endpoint verdict is kept in `endpointResult`, and the details
start with `[fraud control <verdict>: <reason>]`. Results stored before the fix are
folded by `cmd/fraudverdictbackfill` (dry run by default; `-apply` after a backup).

## 5. Determinism

- Set `BAS_CARBANAK_FIXED_TIME` before starting the ledger for any run whose
  outcome depends on the operating window (items 24, 27 and the flags in 8c).
- The audit log is append-only and hash-chained. Use `GET /audit/verify` after the
  run; it must report `intact: true`.
