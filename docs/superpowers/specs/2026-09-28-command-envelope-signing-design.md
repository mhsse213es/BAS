# Deployment Command-Signing (B4) Design

## Context

Security assessment finding B4 ("Group B — Endpoint-agent trust model"):
zero signature verification exists anywhere in the agent's WS command
dispatch (`agent/agent.go:1343` onward). Any well-formed frame arriving
over an authenticated channel executes as-is. B1/B3 (per-agent mTLS,
shipped earlier) solved *transport* authentication — proving the channel
itself is talking to the real orchestrator and the real agent — but never
addressed *command* authorization: a compromised or rogue orchestrator
process, once it holds a valid channel, can dispatch arbitrary commands
and the agent has no independent way to tell a legitimate command from a
forged one.

This design was locked through direct discussion with the user (a prior
design pass this document did not itself originate from, plus a
confirming round of implementation-detail questions in this session).
Every architectural decision below is a direct transcription of that
locked design, not a proposal open for revision — this document exists to
pin it down precisely and give `writing-plans` real signatures and file
paths to build from.

## Goal

Every execution-triggering WS command the orchestrator sends to an agent
passes through one mandatory, impossible-to-bypass signing boundary before
it reaches the wire. The agent verifies that signature — covering the
complete resolved execution context (which command, for which agent, for
which run, under which policy, valid for how long) — before executing
anything, and rejects unknown command types outright regardless of
signature validity.

## Two independent cryptographic domains — do not conflate

This is the single most important architectural property of this design.

```
Vendor signing key (existing, unchanged)          Deployment command-signing key (NEW)
    │                                                  │
    ▼                                                  ▼
Builtin scenario / binary authenticity            Complete CommandEnvelope for every
    │                                              execution-triggering WS command
    ▼                                                  │
Verified once, at orchestrator startup,               ▼
when scenario files are loaded from disk          Agent-side verification, per command,
(orchestrator/internal/scenario/engine.go:86)     before execution
```

- The **vendor key** (`orchestrator/private_key.pem`, RSA-4096/PKCS1v15,
  public half compiled into the orchestrator binary as
  `integrity.ScenarioPublicKeyPEM`) answers *"did Audspect ship this
  builtin scenario?"*. It lives only on the release-build machine and
  never touches a running orchestrator. This property is why it's
  trustworthy, and this design does not change it, extend it, or let the
  running orchestrator hold it.
- The **deployment command-signing key** (new) answers *"did this
  specific Audspect deployment authorize this exact command, for this
  exact agent/run/context, within this validity period?"*. Its private
  half necessarily lives with the running orchestrator, because it signs
  commands generated at runtime — a fundamentally different trust
  purpose and threat model than the vendor key, with independent
  generation, storage, backup, and fail-closed handling (below).

Custom and intel scenarios remain intentionally unsigned as *files*
(`engine.go:82-84`'s existing behavior is untouched) — this design does
not make them vendor-authenticated. Their resulting *execution commands*
are deployment-signed exactly like builtin scenarios' commands are: the
CommandEnvelope signs the resolved, concrete command, not scenario
provenance.

## Scope: which commands, precisely

The 8 command types the agent's WS dispatch switch actually executes
today (`agent/agent.go:1343-1430`):

```
command_scenario
command_simulate
command_attackpath_collect
command_cancel
command_pause
command_resume
command_stop_agent
command_uninstall_agent
```

`command_install_patches` (`MsgCommandPatches`,
`orchestrator/internal/models/schema.go:596`) is explicitly **out of
scope**: it's a defined message-type constant with no agent-side handler
at all today (confirmed: no `case "command_install_patches"` anywhere in
`agent/agent.go`). Signing a command the agent silently ignores provides
no security benefit and expands the contract for nothing. When that
feature gets an actual agent-side implementation, it joins this same
CommandEnvelope boundary as part of that feature's own work — not
retrofitted here.

**Hard rule, load-bearing:** the agent rejects any command type outside
this exact set of 8, unconditionally, even if its signature verifies.
Signature validity must never be interpreted as authorization to execute
an unrecognized or future command type — that would let a signed-but-not-
yet-understood envelope become a silent authorization once a later
agent version adds a handler for it.

## CommandEnvelope

```go
// agent/protocol package (shared shape; orchestrator has its own
// construction-side type in internal/models, agent has its own
// verification-side type — see "Canonical serialization" below for why
// these are NOT the same Go type despite matching JSON shape).
type CommandEnvelope struct {
    Version     int             `json:"version"`
    CommandID   string          `json:"commandId"`   // primary replay-dedup identity
    CommandType string          `json:"commandType"` // one of the 8 above
    AgentID     string          `json:"agentId"`     // must match the mTLS-authenticated identity
    RunID       string          `json:"runId,omitempty"`
    ScenarioID  string          `json:"scenarioId,omitempty"` // optional: not every command type has one
    StepID      string          `json:"stepId,omitempty"`     // optional: ditto
    Mode        string          `json:"mode,omitempty"`
    Policy      json.RawMessage `json:"policy,omitempty"` // opaque to signing/verification; command-type-specific shape
    IssuedAt    time.Time       `json:"issuedAt"`
    ExpiresAt   time.Time       `json:"expiresAt"`
    Nonce       string          `json:"nonce"` // contributes signed entropy; NOT the dedup key (CommandID is)
    Payload     json.RawMessage `json:"payload"` // the resolved command-specific data, e.g. today's ScenarioCommand fields
    Signature   []byte          `json:"signature"` // NOT part of the signed bytes — appended after signing
}
```

`ScenarioID`/`StepID` are optional (`omitempty`) per the locked
correction: `command_cancel`, `command_pause`, `command_resume`, etc.
don't necessarily have a scenario/step context.

### Canonical serialization

The signature covers `json.Marshal` of every field **except**
`Signature` itself, using a struct with fixed, tagged fields (not a
`map[string]any`) — Go's `encoding/json` marshals a given struct type's
fields in a fixed, declaration-order sequence, so signing and verifying
the same struct shape is naturally canonical with no separate
canonicalization scheme (no JCS, no manual key-sorting) required, as long
as both sides marshal the identical field set in the identical order.
Concretely: define one `CommandEnvelope` struct (fields above, minus
`Signature`) used for signing, and marshal it once, hash that exact byte
sequence with SHA-256, sign with RSA-4096/PKCS1v15 (same algorithm choice
as the existing vendor scheme, for consistency — see "Algorithm" below).

```
scenario YAML (builtin) or custom/intel scenario (operator/connector-created)
     │
     ▼
parse / validate / resolve            (existing engine.Get() + dispatch-time
     │                                  construction — unchanged)
     ▼
concrete execution command             (today's ScenarioCommand /
     │                                  AttackPathCollectCommand / etc. —
     │                                  unchanged, becomes CommandEnvelope.Payload)
     ▼
canonical CommandEnvelope              (NEW: wraps the above with the
     │                                  execution-context fields)
     ▼
SHA-256 → RSA-4096 PKCS#1 v1.5         (NEW: signed with the deployment
     │                                  command-signing private key)
     ▼
WS (models.WSMessage.Data = signed CommandEnvelope, JSON-marshaled)
```

Raw scenario YAML is never sent to the agent and the agent never
independently fetches scenario content — it verifies the canonical
CommandEnvelope only, which already carries the fully-resolved execution
payload.

## The centralized signing boundary

`orchestrator/internal/ws/hub.go:109`'s `func (h *Hub) SendToAgent(agentID
string, msg models.WSMessage) (sent bool)` is **already** the single
function every one of the 16 existing dispatch call sites across 8 files
funnels through (`internal/api/agent_uninstall_handlers.go`,
`attackpath_handlers.go`, `attackpath_jobs.go`, `attackpath_scheduler.go`,
`campaign_handlers.go` ×2, `handlers.go` ×7, `remediation_dispatch.go`
×2, `variant_handlers.go`) — confirmed by grep, not assumed. This is the
mandatory boundary the locked design calls for: it already structurally
exists, so signing is implemented **inside `SendToAgent` itself**, not by
touching all 16 call sites individually. `SendToAgent` gains access to
the deployment signing key (constructor-injected, see below); for `msg`
whose `Type` is one of the 8 in-scope command types, it wraps `msg.Data`
into a signed `CommandEnvelope` before marshaling to JSON — every other
message type (heartbeat acks, browser-facing broadcasts, any WS message
type outside the 8) passes through completely unchanged. This makes the
boundary genuinely mandatory: there is no code path to reach an agent's
WS connection that doesn't go through this one function.

## Key lifecycle: independent from the deployment CA

```
./pki/                          ./signing/                    (NEW, separate)
├── ca-key.pem                  ├── command-signing.key
└── ca-cert.pem                 └── command-signing.crt
```

Deliberately **not** tied to `pki.LoadOrGenerateCA`'s lifecycle or
storage. Locked rationale: the two keys have different trust purposes: an
operational CA problem must never become a command-signing problem, and
compromise or replacement of one trust root must not imply replacement of
the other. The command-signing key gets:

- Its own generation function — `internal/pki/signing.go` (new file,
  mirrors `internal/pki/ca.go:46`'s `LoadOrGenerateCA(dir string) (*CA,
  error)` shape): `LoadOrGenerateSigningKey(dir string) (*SigningKey,
  error)`. RSA-4096, matching the vendor scheme's algorithm choice (see
  "Algorithm" below for the one open question this doesn't resolve).
- Its own persisted location — a new host bind-mount,
  `./signing:/etc/audspect/signing`, added to
  `packaging/compose/docker-compose.yml` alongside the existing
  `./pki:/etc/audspect/pki` mount (same pattern this session's
  deployment-topology plan already established for `pki`/`certs`).
- Its own permissions/ownership — `install.sh`'s `mode_install`/
  `mode_upgrade` both `mkdir -p .../signing`, `chown 65532:65532
  .../signing`, `chmod 700 .../signing`, mirroring the exact `pki`
  sequence already added this session (including the same upgrade-path
  fix: this must be added to `mode_upgrade` too, not just
  `mode_install`, learning directly from the Critical bug the final
  review just caught for `pki`).
- Its own fail-closed startup check — a new
  `checkSigningKeyNotSilentlyRotated`, structurally mirroring this
  session's `checkCANotSilentlyRotated` (`orchestrator/cmd/server/main.go`):
  refuses startup when a signing key was just freshly generated (empty
  `SigningDir`) but evidence of prior command-signing activity already
  exists for this deployment (exact evidence source TBD in the plan —
  candidates: a persisted `command_signing_keys` table analogous to
  `agent_certificates`, or a simpler marker file; the plan resolves this
  with the same real-code-verification discipline `checkCANotSilentlyRotated`
  itself was built with). Same `BAS_CONFIRM_NEW_CA`-style escape hatch
  pattern, its own distinctly-named env var (e.g.
  `BAS_CONFIRM_NEW_SIGNING_KEY`).
- Its own backup/restore requirement — `install.sh`'s `_package_config`
  tar command gains `signing` alongside the existing `pki` addition
  (mirrors this session's Task 10 for the CA).
- Its own rotation mechanism — out of full-implementation scope for this
  plan (see "Explicitly out of scope" below), but the wire format
  (`key_id`/version, below) is built to support it without a future
  protocol change.

Generated once, at initial orchestrator startup, independently from (but
alongside, in the same startup sequence) CA generation:

```
First installation
    │
    ├── Generate deployment CA               (existing, unchanged)
    │
    └── Generate command-signing keypair     (NEW, independent call)

Subsequent restarts:
    Existing CA           → load
    Existing signing key  → load

Missing either unexpectedly on an existing deployment
    → fail closed (independently — losing one must not silently regenerate
      either)
```

### Algorithm — one deliberately open point

The locked design specifies RSA-4096/PKCS1v15/SHA-256 for consistency
with the existing vendor scheme. Unlike the vendor key (generated once,
offline, by a human running `signer.go keygen`), this key generates
automatically on every fresh orchestrator startup, in-process — RSA-4096
keygen is measurably slower (typically ~1-3s) than the ECDSA P-256
keygen the deployment CA already uses (`pki.LoadOrGenerateCA`, near-
instant). This is very unlikely to matter (a one-time startup cost on
first install only) but the plan should confirm it's a non-issue in
practice rather than assume it, and should verify `crypto/rsa`'s
`GenerateKey(rand.Reader, 4096)` doesn't meaningfully regress orchestrator
startup latency before treating this as settled.

## Key distribution: the existing enrollment response

```
EnrollmentResponse (orchestrator/internal/api/enroll_csr_handlers.go's
enrollCSRResponse, extended)
├── certPem              (existing: agent's issued client certificate)
├── caPem                (existing: deployment CA root)
├── expiresAt            (existing)
└── commandSigningTrust  (NEW)
    ├── keyId            (e.g. "command-signing-key-v1" — forward-
    │                      compatibility for rotation; the actual
    │                      dual-key-acceptance rotation FLOW is out of
    │                      scope for this plan, see below)
    └── certPem           (the signing public certificate, not a bare key
                            — a certificate gives a clean place for key
                            identity/versioning now and rotation later)
```

**Trust model, precisely** (locked, do not weaken): the enrollment
response is an *authenticated transport* for delivering the signing
certificate, never the *root of trust* itself.

```
Installer
  └── pre-distributed deployment trust material (the CA root, already
      how the agent verifies it's really talking to this deployment's
      orchestrator — existing B1/B3 mechanism, unchanged)
          │
          ▼
Verified orchestrator TLS (the agent already validated the channel via
the existing chain-verification before ever trusting a response on it)
          │
          ▼
Enrollment response
          │
          └── command-signing public certificate (delivered here, trusted
              because the channel delivering it was already verified —
              not because it merely arrived)
```

The agent persists the signing certificate locally after successful
enrollment — alongside its other trust material (extends
`agent/certstore.go`'s `certPaths()` family with a new path, e.g.
`command-signing.pem`, in the same `BAS_CERT_DIR`) — and uses the
persisted copy for every subsequent command verification. It never
re-fetches per command.

## Agent-side verification

Replaces the raw `switch msg.Type { case "command_scenario": ... }`
entry in `agent/agent.go`'s `connectWS` read loop (`agent.go:1343`
onward) with an envelope-unwrap-and-verify step that runs before any
`case` branch executes. For the 8 in-scope types, the agent:

1. Parses `msg.Data` as a `CommandEnvelope`.
2. Rejects if `CommandType` is not one of the 8 known types — regardless
   of what follows. (Any type outside the 8 is rejected at this step;
   the switch below only ever sees already-validated types.)
3. Rejects if the RSA-4096/PKCS1v15/SHA-256 signature over the canonical
   envelope (minus `Signature`) does not verify against the persisted
   command-signing certificate's public key.
4. Rejects if `IssuedAt` is unreasonably in the future (clock-skew
   tolerance TBD in the plan — small, e.g. a few seconds, not the full
   TTL).
5. Rejects if `ExpiresAt` has passed, or if `ExpiresAt <= IssuedAt`
   (a malformed/backdated envelope).
6. Rejects if `Version` is unsupported (forward-compatibility gate for a
   future envelope format change).
7. Rejects if `AgentID` does not match this connection's own
   mTLS-authenticated identity (reuses the existing
   `AuthenticatedAgentID`/certificate-CN mechanism B1/B3 already
   established — binds the envelope to the specific agent connection it
   arrived on, so a captured envelope can't be replayed against a
   different agent even within its TTL).
8. Rejects if `CommandID` has already been consumed (replay cache, next
   section).
9. Only after all of the above pass: unwraps `Payload` into the existing
   command-specific struct (`ScenarioCommand`, etc. — unchanged) and
   proceeds into the existing `case "command_scenario":` handling logic,
   unmodified.

A rejection at any step logs clearly (which check failed) and does not
execute the command — matching this session's established
fail-closed-with-a-clear-reason pattern (`checkCANotSilentlyRotated`,
B3's `errBlocked`).

## Expiry & replay

`ExpiresAt = IssuedAt + 60s` (default; the plan should make the duration
configurable rather than hardcoded, in case real dispatch/queue latency
in production ever demonstrates 60s is too tight — but 60s is the locked
starting value, not to be silently loosened without evidence).

Rejection conditions (repeated here as the authoritative list — matches
"Agent-side verification" above exactly):
- signature invalid
- `IssuedAt` unreasonably in the future
- `ExpiresAt` has passed
- `ExpiresAt <= IssuedAt`
- envelope `Version` unsupported
- `CommandType` unsupported
- `AgentID` doesn't match the authenticated mTLS identity
- `CommandID` already consumed

**Replay cache**: in-memory on the agent, keyed by `CommandID` (not
`Nonce`) → expiry timestamp. `Nonce` remains part of the signed envelope
(contributes signed entropy/unpredictability) but `CommandID` is the
primary dedup identity. Prune entries whose expiry has passed,
periodically (exact interval TBD in the plan — cheap, e.g. tied to the
existing heartbeat tick).

**Why in-memory-only is acceptable** (locked correction — this exact
framing belongs in the plan and any future review, not the looser
"nothing to replay after a restart" framing this document's author
initially reached for): the replay cache provides duplicate-delivery
protection *within a single agent process* — it stops the same envelope
from executing twice while that process is up. The *short cryptographic
validity window* (60s) is what limits the usefulness of a captured
envelope *across* a process restart: a captured-and-replayed envelope
could in principle still be replayed after a restart if it's replayed
within its 60s TTL, but that window is short enough that this is a
narrow, low-value attack surface rather than something persistence would
meaningfully close.

## Explicitly out of scope for this plan

- `command_install_patches` — no agent-side handler exists; joins this
  boundary when that feature is actually built.
- The full key-rotation *flow* (accepting a current + next key
  simultaneously during a defined overlap period) — the wire format
  (`keyId`) is built to support it without a future protocol change, but
  the rotation mechanism itself (how an operator triggers it, how the
  overlap period is bounded, how agents are told to drop the old key) is
  a separate future design.
- Signing `command_install_patches`-adjacent or any other command type
  not in the locked list of 8.
- Making custom/intel scenario *files* vendor-signed — remains
  intentionally unsigned per `engine.go:82-84`'s existing, unchanged
  behavior.
- Any change to the vendor signing key's storage, algorithm, or
  offline-only property.

## Open questions for the implementation plan to resolve with code-level certainty

1. Exact evidence source for `checkSigningKeyNotSilentlyRotated`'s
   fail-closed check (a new DB table vs. a marker file) — resolve by
   investigating the real schema/migration conventions this session's
   `agent_certificates`-table-based `checkCANotSilentlyRotated` used, and
   picking the analogous, simplest correct mechanism.
2. Exact clock-skew tolerance for `IssuedAt`-in-the-future rejection.
3. Exact replay-cache pruning interval and whether it needs its own
   goroutine/ticker or can ride an existing one.
4. Whether `internal/pki`'s existing `CA` type/package is the right home
   for the new `SigningKey` type, or whether a sibling file/package is
   cleaner — resolve by reading `internal/pki/ca.go` in full before
   deciding, the same way this session's other Go work verified real
   signatures before writing plan tasks.
5. RSA-4096 keygen latency at orchestrator startup — confirm empirically
   it's not a meaningful regression before treating it as settled (see
   "Algorithm" above).
