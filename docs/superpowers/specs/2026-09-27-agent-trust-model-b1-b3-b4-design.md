# Agent Trust Model Redesign — B1 (Per-Agent Identity), B3 (Transport Auth), B4 (Command Signing)

**Date:** 2026-09-27
**Status:** Approved for planning

## Context

The 2026-09-26 security assessment (`Assessment/AUDSPECT_ASSESSMENT_REPORT.md`, local-only, untracked from git) identified an agent trust model where:

- `AgentID = SHA-256(hostname)[:16]` (`agent/identity.go`) — deterministic, not a credential.
- A single `AgentSecret` string is shared across the entire agent fleet (`agent/config.go`; the field's own comment says "shared secret for X-Agent-Token + result HMAC signing").
- The orchestrator validates it with a single `h.agentSecret` field and a non-constant-time `provided == h.agentSecret` compare (`orchestrator/internal/api/handlers.go:88,232-242`).
- The secret travels as a WS query parameter (`agent/protocol/websocket.go:47-48`, `q.Set("agentSecret", agentSecret)`) as well as an `X-Agent-Token` HTTP header (`agent/protocol/enroll.go`).
- The orchestrator serves plain HTTP with **no TLS anywhere in the stack** — `orchestrator/cmd/server/main.go:773` calls `srv.ListenAndServe()`, and `packaging/compose/docker-compose.yml` publishes port 9443 straight from the orchestrator container with no reverse proxy or TLS terminator in front of it. The "443" in 9443 is naming convention only; traffic is cleartext today.
- `agent/agent.go`'s `ReadMessage()` → `switch msg.Type` → direct execution path has zero signature verification on command bundles.
- `agent/sched/riskgate.go` gates on resource-pressure policy only, not command-safety (out of scope for this redesign, already reviewed separately).

**Corrected threat framing (supersedes any unqualified "fleet-wide SYSTEM RCE" claim):** this architecture permits fleet-wide SYSTEM/root command execution **after** compromise of the orchestrator, interception of the agent-orchestrator channel, or acquisition of the shared `AgentSecret`. It is not evidence of an internet-facing zero-click exploit.

This spec covers **B1** (per-agent identity/credential), **B3** (transport authentication), and **B4** (cryptographic command-bundle authentication) as one unified redesign, per explicit direction that these should not be patched independently.

## Goals

1. Replace the single shared `AgentSecret` as the standing per-connection credential with per-agent mTLS client certificates.
2. Give the agent a way to verify the orchestrator it's talking to (mutual, not one-way, authentication) — closes the transport-trust gap (B3) as part of the same mechanism as B1, not separately.
3. Make execution-triggering commands cryptographically authenticated end-to-end (B4), as a trust domain independent of B1/B3, so that compromise of one does not silently compromise the other.
4. Ship without breaking the existing enrolled fleet — old agents keep working during a defined, temporary migration window.

## Non-goals / explicitly out of scope for this spec

- **B2** (removing the legacy plaintext/shared-secret listener entirely) — deferred until the existing fleet has actually migrated to mTLS. This spec defines where the migration seam lives (the temporary legacy listener on port 9000) but does not design its removal.
- **C1 / RLS** — Postgres row-level security activation is gated on a separate DB-role-hardening follow-up (`orchestrator/internal/db/postgres.go`'s own comment: `bas_user` must become `NOSUPERUSER`/`NOBYPASSRLS` first, or a superuser role silently bypasses every policy). Not addressed here.
- **Assessment groups D, G, H, I, J** (the remaining Medium/Low findings) — explicitly deferred; this redesign is scoped to B1/B3/B4 only.
- **`agent/sched/riskgate.go`** resource-pressure gating — already reviewed separately, not part of the trust model.
- Credential rotation for the AWS/Azure/OpenRouter secrets found in commit `976958d` — unrelated incident, already handled (or explicitly accepted as risk) in the P0 containment work that preceded this spec.
- Git history rewrite of commit `976958d` — separate, deliberately deferred operation.

## Architecture overview — two separate trust domains

```
Deployment CA                          Command-signing keypair
    │                                          │
    ├── Orchestrator's 9443 server cert        ├── Self-signed command-signing
    ├── Agent client certificates              │   certificate (its own trust
    │                                          │   anchor — NOT chained through
    ▼                                          │   the deployment CA)
mTLS identity / transport authentication       ▼
(B1 + B3)                              Signed CommandEnvelope
                                        (B4 — execution authorization)
```

Both private keys live only on the orchestrator host, with restrictive filesystem permissions, generated at install time. **They are deliberately not the same key and not chained to each other.** A compromise of the command-signing key lets an attacker forge command envelopes but not impersonate the orchestrator's TLS identity or issue new agent certificates, and vice versa.

**CA compromise is substantially more consequential than client-cert compromise** (full fleet impersonation vs. one agent) — this asymmetry is why the CA private key's storage/permissions must be the most tightly restricted secret on the orchestrator host, stricter than an individual agent's own key material would need to be if it were ever exposed.

## Section 1 — Listeners

Three listeners, not the two originally proposed (a two-listener design has a circular dependency: a brand-new agent has no client cert yet, so it cannot complete a handshake against a `RequireAndVerifyClientCert` listener to *get* one).

| Port | TLS mode | Purpose | Lifecycle |
|---|---|---|---|
| **9443** | `ClientAuth: tls.RequireAndVerifyClientCert` | Normal operation for already-enrolled agents (WS connect, heartbeat, all HTTP endpoints), **and** certificate renewal (the agent already holds a valid cert to authenticate the renewal CSR with — no circularity here) | Permanent, canonical secure endpoint |
| **9444** (new) | `ClientAuth: tls.NoClientCert`, server-authenticated only | Initial bootstrap enrollment **only**: agent verifies the orchestrator's cert against the installer-bundled CA root, then presents the bootstrap secret + CSR over this verified-but-not-mutual connection | **Permanent infrastructure** — every fresh install, forever, needs this to onboard an agent that has no cert yet. Not a migration bridge; still needed long after B2 retires port 9000. |
| **9000** | none (plaintext, today's behavior, unchanged) | Legacy shared-`AgentSecret` traffic for pre-migration agents only | **Temporary** — retired entirely when B2 executes. Deliberately narrow: only legacy enrollment/re-enrollment and whatever legacy agent endpoints strictly remain in use. No client-cert auth accepted here. Logged distinctly so B2's removal decision is based on actual remaining usage. |

All three listeners share the same handler/business logic layer (`orchestrator/internal/api` handlers) — only the transport/auth middleware differs per listener. This prevents the temporary port-9000 path from becoming a permanent fork of the API surface.

**Do not** weaken 9443 to `VerifyClientCertIfGiven` to make it double as a bootstrap endpoint — that would make the canonical secure endpoint support two fundamentally different authentication modes and undermine the clean boundary between "enrolled" and "not yet enrolled" traffic.

## Section 2 — Enrollment & certificate issuance

### Installer artifacts

The agent installer package now bundles four things (as a directory of separate files, not compiled into the agent binary — this allows CA/signing-cert rotation and offline installs without replacing the binary):

- Agent binary
- Deployment CA root certificate — `/etc/audspect/certs/deployment-ca.pem` (Linux) / `C:\ProgramData\Audspect\certs\deployment-ca.pem` (Windows)
- Command-signing public certificate (self-signed by the command-signing keypair, its own trust anchor — see Section 3) — same directory, e.g. `command-signing-ca.pem`
- Bootstrap secret — same distribution mechanism as today's `AGENT_SECRET`/`GetConnectionConfig` admin flow (`orchestrator/internal/api/handlers.go`'s `GET /api/config/connection`), just now understood as a one-time-ish issuance credential rather than a standing per-connection secret

### Flow

```
Agent (first run)
  │
  ├── Generate ECDSA P-256 keypair locally (private key never leaves the agent)
  ├── Generate CSR; CN = existing SHA-256(hostname)[:16] AgentID (unchanged derivation —
  │   nothing downstream that keys off AgentID needs to change)
  │
  ▼
TLS connection to :9444 (NoClientCert)
  │
  ├── Verify orchestrator's server cert against bundled deployment-ca.pem
  ├── Present bootstrap secret (header, as today's X-Agent-Token)
  └── Submit CSR
                 │
                 ▼
        Orchestrator (9444 handler)
                 │
                 ├── Validate bootstrap secret
                 ├── Reject if this AgentID already holds a valid, unexpired
                 │   certificate (see "Bootstrap reuse limit" below)
                 ├── Look up / validate identity against the `agents` table
                 │   and enrollment policy — the orchestrator, not the agent,
                 │   is authoritative for what identity gets stamped into
                 │   the signed cert's SAN
                 └── Sign CSR with deployment CA → client certificate
                 │
                 ▼
        Response: signed certificate + CA chain ONLY — never a private key
                 │
                 ▼
        Agent persists cert + its own already-local private key
                 │
                 ▼
        Normal operation resumes on :9443 (mTLS)
```

### Bootstrap secret reuse limit

An identity (`AgentID`) that already holds a valid, unexpired certificate is rejected from bootstrapping again via the shared secret on :9444 — it must renew via mTLS on :9443 instead, authenticated with its existing cert. A never-before-seen `AgentID` can still bootstrap freely on :9444 with the secret. This scopes the shared secret's blast radius down from "grants fleet-wide standing access forever" (today) to "grants one cert-issuance window per identity" (after this change) — matching the existing physical/network-access-gated trust model for genuinely new installs, without leaving already-enrolled identities re-bootstrappable by anyone who later learns the secret.

### Renewal

Same CSR flow, but submitted on :9443 (mTLS), authenticated by the agent's *current* valid certificate rather than the bootstrap secret. Triggered automatically at ~75% of the certificate's lifetime elapsed, or naturally by the existing re-enroll-on-upgrade cadence (agents already re-enroll after every binary upgrade — established pattern, see project memory on posture-check-picker), whichever comes first.

### Certificate lifetimes (defaults — adjustable operational parameters, not architectural constraints)

- Agent client certificate: 1 year
- Deployment CA root: 10 years, with overlapping-trust support for rotation (agent trust store can hold "current CA + next CA" simultaneously during a rollover, so the orchestrator can transition certificates without breaking the existing fleet mid-rotation)
- Command-signing certificate: versioned via the `CommandEnvelope`'s `version` field (see Section 3), supporting the same overlap pattern during rotation

## Section 3 — Command bundle signing (B4)

### What gets signed

Every **execution-triggering** WS message type, enumerated from `orchestrator/internal/models/schema.go`:

`command_scan`, `command_scenario`, `command_simulate`, `command_cancel`, `command_pause`, `command_resume`, `command_install_patches`, `command_attackpath_collect`, `command_stop_agent`, `command_uninstall_agent`

Informational/status message types (`heartbeat`, `agentUpdate`, `policy_update`, `run_event`, `notification`, `tamper_alert`, etc.) are **not** signed — they don't trigger code execution on the agent, so B4 doesn't apply.

### What this actually defends against

If the command-signing private key lives on the orchestrator host (it does — same host as the CA private key), B4 does **not** add protection against a fully-compromised orchestrator *process*: an attacker with that level of access already holds both keys and can forge anything. What it does add: defense-in-depth against a narrower compromise that can write into the command pipeline **without** full orchestrator-process RCE — e.g., a SQL-injection-only foothold, or a compromised downstream worker/queue consumer. Signing happens at the point a scenario step is compiled into a concrete command (see "Signing boundary" below), before persistence — so an attacker with DB/queue write access alone, but no access to the running orchestrator process's signing key, cannot forge a signature that will pass verification, even though they could insert a row.

### Signing boundary

**Invariant:** every execution-triggering command must pass through one mandatory command-compilation/signing function before it can become persistable or dispatchable. No execution command may be constructed downstream of that boundary.

Today, this is **not** centralized — command construction is scattered across 18 call sites in 8 files, verified directly against the current codebase:

- `orchestrator/internal/api/agent_uninstall_handlers.go:39`
- `orchestrator/internal/api/attackpath_handlers.go:524`
- `orchestrator/internal/api/attackpath_jobs.go:179`
- `orchestrator/internal/api/attackpath_scheduler.go:72`
- `orchestrator/internal/api/campaign_handlers.go:522,579,595`
- `orchestrator/internal/api/handlers.go:1085,1459,1504,1842,2099,3157,3253,3277`
- `orchestrator/internal/api/remediation_dispatch.go:84,131`
- `orchestrator/internal/api/variant_handlers.go:742`

This spec requires consolidating all of these behind a single new function (working name: `commandsign.Compile(ctx, agentID, cmdType, payload, runCtx) (models.WSMessage, error)`, living alongside `orchestrator/internal/integrity`) that every one of the 18 call sites is refactored to go through instead of constructing `models.WSMessage{...}` directly. This is real, material implementation scope — not a small addition — and should be reflected as its own task(s) in the implementation plan.

### Envelope shape

```
CommandEnvelope
├── version        — envelope/signing-key version, for trust-anchor selection during rotation
├── command_id      — stable identifier for log correlation (not the replay-protection field)
├── command_type    — one of the command_* types above
├── agent_id        — must match the agent's authenticated mTLS identity
├── run_id
├── scenario_id
├── step_id
├── issued_at
├── expires_at      — issued_at + 120s (secondary freshness bound, see replay protection below)
├── sequence        — persisted, strictly monotonic per-agent counter (primary replay-protection field)
├── payload
└── signature       — RSA-SHA256/PKCS1v15 over the canonicalized envelope (same crypto shape as
                       orchestrator/internal/integrity/signing.go's existing scenario/manifest
                       signing, but a distinct per-deployment keypair — see "Architecture overview")
```

Agent verification order, on receipt of any `command_*` message:

1. Signature valid against the bundled command-signing public certificate
2. Envelope `version` corresponds to a trust anchor the agent currently holds (current or next, during rotation)
3. `agent_id` matches this agent's own authenticated mTLS identity (prevents a captured envelope from being redirected to a different agent)
4. `command_type` is in the allowed set
5. `expires_at` has not passed
6. `sequence > last_persisted_sequence` (see below) — reject and log otherwise

### Replay protection — persistent monotonic sequence

An in-memory-only dedup cache was rejected: a 120s validity window plus a cache that's wiped on agent restart leaves a real window where a still-valid signed command could be replayed immediately after the agent restarts. Replaced with:

- **Orchestrator side**: a `next_command_seq` counter per agent (new column on the `agents` table), incremented atomically at the centralized signing boundary (Section 3's `commandsign.Compile`) every time a new command is compiled for that agent. Persisted in Postgres — restart-safe on the orchestrator side for free.
- **Agent side**: persists the highest **accepted** `sequence` value to a local state file, separate from the cert/key files (so cert renewal never touches it), durably written the moment a command is accepted as valid — before execution begins. Any envelope with `sequence <= last_persisted_sequence` is rejected outright, regardless of signature validity or expiry.

This does not reset on certificate renewal (the state file is independent of cert files, keyed to `AgentID`, not to the specific certificate) — resetting would reopen replay of previously-executed commands. On a full agent reimage/state-wipe (local state file gone, orchestrator's counter continues climbing from wherever it was), the agent's local counter restarts at 0; a freshly-issued command's `sequence` will always be greater than 0, so normal operation is unaffected. The only scenario where a wiped local state could theoretically re-permit an old captured envelope is bounded by `expires_at` (120s) — which will have long since passed for anything old enough to predate a reimage. Sequence and expiry are complementary, not redundant: sequence handles "restart with intact state," expiry handles "state wiped."

## Section 4 — Rollout / migration

1. Ship the orchestrator with all three listeners (9443 mTLS, 9444 enrollment, 9000 legacy) and the signing boundary in place.
2. New installs immediately get the full installer bundle (CA root, command-signing cert, bootstrap secret) and enroll via :9444 from day one — no transition period for fresh installs.
3. Existing enrolled agents continue operating unchanged on :9000 until their next binary upgrade, at which point the upgrade's existing re-enroll step is extended to perform the new CSR-based bootstrap on :9444 instead of the old shared-secret WS/HTTP path, after which that agent moves permanently to :9443.
4. Port 9000 traffic is logged distinctly throughout the migration so the eventual B2 decision to retire it is based on actual observed remaining usage, not an assumption that migration is complete.
5. B2 (out of scope here) later removes the :9000 listener and the legacy shared-secret code paths entirely, once fleet telemetry shows migration is complete.

## Data model changes

- `agents` table: add `next_command_seq BIGINT NOT NULL DEFAULT 0` (orchestrator-side sequence counter, incremented atomically at the signing boundary).
- New table or columns to track issued certificates per agent (serial number, issued-at, expires-at, revocation status) — needed both for the "already holds a valid cert" bootstrap-reuse check (Section 2) and for future cert lifecycle visibility in the admin UI. Exact schema is an implementation-plan detail, not an architectural one.

## Testing / verification approach

- Unit tests for the CSR issuance path (valid CSR → signed cert with correct SAN; reject CSR for an AgentID that already holds a valid cert; reject invalid bootstrap secret).
- Unit tests for `commandsign.Compile` (correct envelope construction, monotonic sequence assignment, signature verification round-trip).
- Unit tests for the agent's envelope verification (each of the 6 checks in Section 3, independently — including the restart-safety property: simulate a process restart between "accept command A" and "receive command A again," assert rejection).
- Integration test standing up all three listeners against a real TLS/mTLS handshake (not mocked) to catch the circular-dependency class of bug this spec exists to avoid reintroducing.
- Manual staging verification: fresh install → enroll via :9444 → confirm :9443 mTLS operation → confirm a legacy (pre-migration, simulated) agent still functions on :9000 → confirm a tampered/replayed command is rejected end-to-end.

## Open implementation-level details (for the plan to resolve, not architectural)

- Exact wire format/library for CSR submission on :9444 (JSON-wrapped PEM CSR over the existing enrollment HTTP pattern is the natural fit, consistent with `agent/protocol/enroll.go`'s existing `EnrollRequest`/`EnrollResponse` shape).
- Exact schema for the certificate-tracking table mentioned above.
- Exact local state file format/location for the agent's persisted `last_persisted_sequence` and cert/key material, per-platform (Windows: alongside the existing DPAPI-encrypted-secret storage already used for `AgentSecret` in `agent/config.go`'s `readEncryptedSecretPlatform`; Linux: filesystem path with restrictive permissions, equivalent role).
- `commandsign.Compile`'s exact signature and how each of the 18 existing call sites maps its current ad hoc `models.WSMessage{...}` construction onto the new function — this should be enumerated call-site-by-call-site in the implementation plan, not summarized.
