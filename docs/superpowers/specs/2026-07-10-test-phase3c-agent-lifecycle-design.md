# Phase 3c: Agent Lifecycle — Test Design

## Goal

Build a regression suite for the agent-facing trust boundary and lifecycle handlers in `internal/api` — `EnrollAgent`, `Heartbeat`, `SetAgentState`, `DownloadAgent`, `PingAgent`, `GetAgents`, and the shared `validateAgentAuth` gate. This is the identity layer agents authenticate through before any scenario execution happens; per the user-directed Phase 3 ordering (security perimeter inward), it sits right after 3a (Auth & Access Control) and before 3b (Scenario & Run Lifecycle).

## Scope

**In scope:** `EnrollAgent`, `Heartbeat`, `SetAgentState`, `DownloadAgent`, `PingAgent`, `GetAgents`, `validateAgentAuth`.

**Explicitly out of scope:**
- JWT/RBAC — done in 3a.
- `RedeliverQueuedAPJobs`/`UpdateAPJobProgress` (called inside `Heartbeat`) — attackpath-job domain, belongs to 3e. Verified safe as a no-op against an empty `attackpath_jobs` table, so it doesn't interfere with 3c's tests.
- WebSocket broadcast content (`BroadcastBrowsers`) — fire-and-forget, same call Phase 2/3a made for async side effects; verified safe as a no-op with zero connected browsers.
- `internal/integrity`'s manifest *parser* robustness (malformed/duplicate/missing-file edge cases in `LoadManifest` itself) — a different package with its own future test phase. 3c only exercises the 3 manifest states that matter to handler behavior: not loaded, loaded with a known hash, loaded without a known hash.
- Filesystem permission-denied scenarios for `DownloadAgent` — not reliably testable across this Windows dev host and Linux CI.
- Policy *updates* — `policy_json` is not client-configurable through any in-scope handler; `EnrollAgent` always writes the same hardcoded default (see Test 2 below for the one relevant characterization).
- `GetAgents` filtering/pagination — the handler has no query-param handling; it always returns every agent. Nothing to test.

## Test files

### 1. `internal/api/agent_auth_test.go`
Pure-logic table for `validateAgentAuth`, then integration confirmation that handlers actually enforce it.

- **Precedence matrix**: header-only-correct, query-only-correct, both-correct, header-wrong+query-correct (header wins, request rejected — proves header is checked first and never falls back when merely *wrong*, only when *empty*), header-empty+query-correct (falls through, request allowed), neither-present with a secret configured (rejected), neither-present with no secret configured (allowed — the documented backward-compat bypass).
- **Malformed/edge header values**: `"Bearer <secret>"`-formatted header value does NOT match a bare-secret comparison (raw string equality, no prefix parsing); whitespace-only token value; duplicate `X-Agent-Token` headers via `Header.Add` twice (confirms `Header.Get` semantics — first value wins).
- **Integration confirmation**: one test per `PingAgent`/`EnrollAgent`/`Heartbeat` — wrong token → 401, and (for Enroll/Heartbeat) confirms the DB was never touched (no row created) when auth fails.

### 2. `internal/api/agent_lifecycle_test.go`
- **`EnrollAgent`**: creates a row with the hardcoded default policy; malformed body / missing `agentId` → 400; **re-enroll preserves `enrolled_at`** (stays stable, doesn't reset to a later `NOW()`); **re-enroll preserves `quarantined`/`retired` state** (the `CASE WHEN state IN (...)` upsert clause) but a re-enroll of an `active` agent stays `active`; **re-enroll resets `policy_json` back to the hardcoded default** even if it had been manually diverged via raw SQL beforehand — a real characterization worth locking in, since it means policy customization (if ever added) would need its own preservation logic; **idempotency**: enrolling the same agent 3 times in a row converges to one deterministic row, not three.
- **`Heartbeat`**: creates-or-updates; malformed body / missing `agentId` → 400; returns current `state`+`policy`; **idempotency**: N identical heartbeats converge to the same single row; **`last_update` advances** strictly forward across two heartbeats (server-generated `NOW()` each call, not client-supplied — no "stale timestamp" input vector exists to test against).
- **`SetAgentState`**: valid transitions for all 4 states; invalid state string → 400; unknown `agentId` → 404; **idempotency**: setting the same state twice in a row succeeds both times with the same end state.
- **`GetAgents`**: empty → `[]` not `null`; **ordering** — seed 3 agents with distinct `last_update` values via raw SQL, assert descending order; **nullable field serialization** — a `Heartbeat`-only agent (never `EnrollAgent`-ed) has `enrolled_at == nil` in the decoded response and an empty/default policy; `effectiveAgentStatus` is applied on read (an agent with a stale `last_update` shows `offline` regardless of stored `status`).
- **`PingAgent`**: 200 with a valid/no-secret request; confirms no DB row is created or touched (it's a pure probe).
- **Agent identity edge cases** (via `EnrollAgent` and `Heartbeat`): whitespace-only `agentId` (`" "`) is accepted today (only `== ""` is checked) and stored literally; a very long `agentId` (e.g. 500 chars) is accepted (no length constraint in the schema); a unicode `agentId` round-trips correctly through JSON and Postgres `text`.
- **End-to-end lifecycle chain**: `PingAgent` → `EnrollAgent` → `Heartbeat` → `GetAgents` (confirms enrolled data visible) → `SetAgentState(quarantined)` → `Heartbeat` (confirms state persists through a heartbeat — heartbeat's upsert never touches `state` on conflict) → `GetAgents` (confirms quarantined state still visible). One coherent workflow test complementing the isolated handler tests.

### 3. `internal/api/agent_trust_test.go`
The binary-hash trust/quarantine matrix.

- **Full cross-product** for both `EnrollAgent` and `Heartbeat`: `{no manifest loaded, trusted hash, untrusted hash}` × `{agent currently active, already quarantined, already retired}` — asserting `binary_trusted` and `state` land correctly in the DB every time. Confirms the one-way rule: only `active`→`quarantined` ever happens automatically; an already-`quarantined` or `retired` agent's state is never touched by the trust check regardless of hash.
- **Trust ratchet sequence**: heartbeat with a trusted hash (state stays `active`) → heartbeat with an untrusted hash (state becomes `quarantined`) → heartbeat with a trusted hash again (state **remains** `quarantined` — no auto-restore) → `SetAgentState(active)` (admin action) → heartbeat with a trusted hash (state stays `active`, confirming the admin's restoration holds).
- Manifest fixtures built via `integrity.LoadManifest` against a temp file written with `t.TempDir()` — no changes to the `integrity` package.

### 4. `internal/api/download_agent_test.go`
- Unknown platform key → 404 `"unknown platform: ..."`.
- Known platform, no file present → 404 `"agent binary not found for platform: ..."` (today's actual behavior in every dev/CI environment, since binaries aren't checked into git).
- **Path traversal attempt**: a `platform` value containing `../` sequences or URL-encoded traversal → still resolves to "unknown platform" (proves the allowlist map lookup can't be bypassed; the attacker-controlled string is never concatenated into a filesystem path).
- **Success path**: a real fixture file written to `internal/api/agents/<expected-filename>` for one platform key, removed via `t.Cleanup`, asserting status 200, `Content-Type`, `Content-Disposition` header, and body bytes match exactly.

## Coverage target

Same tier as 3a: every validation branch, every trust/quarantine state transition, and every auth-gate branch in these 6 handlers + `validateAgentAuth` exercised at least once. Not chasing a package-wide percentage.

## Determinism

All DB-backed tests use the shared `testutil` harness established in 3a (`sharedDB.RunWithPool`, `TestMain` already in `internal/api`). The concurrent-heartbeat test follows the same structural-invariant pattern as 3a's concurrent-auth tests (no panic/deadlock, definitive terminal state, exactly one row for the agent — not asserting which specific heartbeat's data "wins"). `-race` remains CI-only; local verification substitutes `-count=10` on the concurrency test.
