# Agent Outbound Proxy Authentication — Design

## Problem

The agent's connection to its orchestrator (`agent/protocol/websocket.go`'s
`DialAgentWS`) uses `websocket.DefaultDialer` from `gorilla/websocket@v1.5.3`.
That dialer's proxy support (vendored in
`github.com/gorilla/websocket@v1.5.3/proxy.go:34-77`) has two hard limits,
confirmed by reading the library source directly:

1. It sends `Proxy-Authorization: Basic` **only** if the resolved proxy URL
   (from `HTTP_PROXY`/`HTTPS_PROXY`) has credentials embedded directly in it
   (`http://user:pass@host:port`), and sends it **preemptively** — it never
   inspects a `407` response and retries with credentials it has via another
   source.
2. Any `CONNECT` response other than exactly `200` closes the connection and
   returns a generic error immediately (`proxy.go:71-74`). No retry, no
   negotiation, no NTLM/Kerberos support of any kind.

For a branch office reaching a central orchestrator across a WAN (the
Mumbai-HQ / Delhi-branch pattern this design followed from), it is common —
especially in BFSI/AD-heavy Windows enterprises — for outbound traffic to
route through an authenticating forward proxy, frequently using
**NTLM** (Windows-integrated auth). Today, an agent behind such a proxy
fails at the `CONNECT` step on every single reconnect attempt, forever. The
symptom in logs is indistinguishable from "server unreachable" — the same
generic dial error whether the orchestrator is down, the WAN link is dead,
or the branch proxy simply wants a form of auth this dialer has never
attempted.

## Goal

The agent's outbound connection succeeds through an authenticating forward
proxy that requires **NTLM** (Windows) or **HTTP Basic** (any platform), and
when it can't, the failure is diagnosable — logs name what the proxy
required and what was/wasn't available, not a generic dial error.

## Scope

**In scope:**
- NTLM proxy authentication, **Windows only**, via SSPI using the agent's
  own Windows Service identity — no proxy password is ever stored.
- HTTP Basic proxy authentication via a proper `407`-challenge/retry flow
  (not just preemptive embedded-URL credentials), on **every platform**.
- New secure credential storage for Basic's explicit username/password,
  extending each platform's *existing* secret-storage mechanism (see
  Design) rather than introducing a new one.
- Diagnostic logging naming the offered vs. available auth mechanism on
  failure.
- A separate, longer backoff ceiling specifically for a *confirmed* bad
  credential (see "Account-lockout-aware backoff" below) — a real
  operational hazard for NTLM/AD-integrated proxies, distinct from generic
  connectivity backoff.

**Explicitly out of scope (non-goals, with reasoning):**
- **Kerberos/Negotiate proxy auth.** No confirmed deployment need yet;
  SPNEGO is a different problem shape again (ideally still SSPI-native on
  Windows, but ticket-cache-based rather than NTLM's challenge-response).
  Its own pass if it's ever actually needed.
- **NTLM on non-Windows agents.** There is no SSPI equivalent on
  Linux/macOS; supporting NTLM there would mean a full Go NTLM protocol
  implementation (new dependency, real crypto/protocol surface, its own
  test burden) plus explicitly stored NTLM-capable credentials. Deferred by
  explicit choice — non-Windows platforms get the Basic-via-407 fix only in
  this pass.
- **Changing orchestrator-side TLS/certificate handling.** Proxy
  authentication and the agent's TLS trust of the orchestrator's own
  certificate are two unrelated concerns — the proxy only ever sees the
  `CONNECT` line and headers; the TLS handshake happens *through* the
  established tunnel, end-to-end with the orchestrator, unchanged by this
  work.
- **Restructuring `connectWS()`'s existing backoff loop.** Only one new
  backoff *class* is added (confirmed-bad-credential); the existing
  generic-failure backoff (`agent/backoff.go`) is untouched.

## Design

### Architecture

Gorilla's `websocket.Dialer` exposes a `NetDialContext` hook
(`client.go:61`, confirmed in the vendored source) — a caller-supplied
function that returns an already-established `net.Conn` for a given
`host:port`. When set, gorilla performs its own TLS handshake and WS
upgrade *on top of* whatever connection this function returns
(`client.go:337`), exactly as it does for a direct connection today.

The fix replaces gorilla's built-in (limited) proxy handling by supplying
our own `NetDialContext` function that owns the entire TCP-establishment
step, including any proxy negotiation. Everything above that layer —
gorilla's TLS handshake, the WS upgrade, and `connectWS()`'s outer
reconnect/backoff loop — is completely unchanged.

The new dial function:
1. Resolves whether a proxy applies to this target using
   `http.ProxyFromEnvironment`'s own resolution logic (constructing a
   throwaway `*http.Request` for the target URL and calling it directly),
   so `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` continue to behave exactly as
   they do today. No proxy resolved → plain `net.Dial`, byte-for-byte the
   same as current behavior.
2. If a proxy is resolved: dial the proxy, send an unauthenticated
   `CONNECT <target-host:port>`.
3. `200` response → tunnel established, return the raw connection.
4. `407` response → read `Proxy-Authenticate` header(s) for what the proxy
   actually offers, and negotiate (see "Negotiation" below).
5. Any other outcome → a diagnostic error identifying exactly what
   happened, surfaced through the existing `connectWS()` error-logging path
   unchanged in shape, just with a more specific message.

### Credential storage

The proxy address itself keeps coming from `HTTP_PROXY`/`HTTPS_PROXY`,
unchanged — only the Basic-auth *credentials* get new, secure storage,
because embedding a password directly in a system environment variable
(today's only working path, and only for Basic) has no protection at rest.
This extends each platform's existing secret pattern rather than inventing
a new one:

- **Windows**: two new values under the same `paramKey` registry key
  `AgentSecret` already lives in (`agent/tamper.go`) — `BAS_PROXY_USER`
  (plain string) and `BAS_PROXY_PASSWORD_ENC` (a DPAPI blob, written and
  read via the same `EncryptSecret`/`DecryptSecret` machinery as
  `BAS_AGENT_SECRET_ENC`). Used only for the Basic-fallback path — SSPI/NTLM
  needs no stored credential of any kind, since it authenticates as
  whatever identity the Windows Service itself runs as.
- **POSIX (Linux/macOS)**: two new fields in the same systemd/launchd
  `EnvironmentFile=` that `BAS_AGENT_SECRET` already comes from
  (`agent/platform_posix.go`) — `BAS_PROXY_USER`/`BAS_PROXY_PASSWORD`,
  plaintext, matching the trust model already accepted for the agent secret
  on this platform (protected by file ownership/permissions, not
  encryption-at-rest — this is the existing precedent, not a new weaker
  one).
- If an operator's `HTTP_PROXY`/`HTTPS_PROXY` still has embedded
  `user:pass`, that keeps working as a fallback credential source (backward
  compatible) — it's simply no longer the recommended path since it has no
  at-rest protection.

### Negotiation

On a `407`, inspect every `Proxy-Authenticate` value present:

- `NTLM` offered **and** running on Windows → attempt the SSPI handshake
  (below). NTLM is connection-oriented: all three legs of the handshake
  happen over the *same* TCP connection to the proxy, never a fresh dial
  per leg.
- Else `Basic` offered **and** a credential resolved (stored value or
  legacy embedded-URL fallback) → retry `CONNECT` with
  `Proxy-Authorization: Basic <base64(user:pass)>`.
- Neither condition holds → fail with a message naming exactly what the
  proxy offered and what was/wasn't available (e.g. `"proxy requires
  authentication (offered: NTLM); SSPI unavailable on this platform and no
  Basic credentials configured"`).

When a proxy offers both `NTLM` and `Basic` on Windows, NTLM takes priority
(it needs no stored credential). If the SSPI handshake itself errors out
before completing — a hard failure mid-negotiation, not a completed attempt
the proxy rejected — this attempt fails as an ordinary negotiation error
(standard backoff, not the lockout-aware one below) rather than falling
back to Basic within the same connection attempt. The next reconnect cycle
tries NTLM first again. This keeps the negotiation logic simple and
predictable; if a real deployment needs same-attempt fallback, that's a
small, separately-scoped follow-up once there's evidence it's needed.

### SSPI NTLM handler (Windows only)

New file `agent/proxyauth_windows.go`, build-tagged `windows`. Uses
`github.com/alexbrainman/sspi`'s NTLM support — an established, actively
used Windows SSPI wrapper — rather than hand-rolling the NTLM
challenge-response protocol and its cryptography ourselves, which is
exactly the class of protocol code not worth reinventing.

Flow: `InitializeSecurityContext` (via the sspi package's NTLM helper)
produces a Type1 message → sent as `Proxy-Authorization: NTLM <base64>` on
the `CONNECT` retry → proxy's `407` response carries the Type2 challenge in
its own `Proxy-Authenticate: NTLM <base64>` value → fed back into the same
SSPI context to produce Type3 → sent as the final `CONNECT`'s
`Proxy-Authorization` → `200` on success. The identity used is whatever the
Windows Service process itself runs as — no separate credential is
requested, stored, or configured for this path.

### Basic-via-407 handler (cross-platform)

New file `agent/proxyauth.go` (no build tag — shared). Resolves a
credential (stored value per platform, or legacy embedded-URL fallback),
builds the `Proxy-Authorization: Basic` header, retries the `CONNECT` once.
This is the *only* new logic non-Windows platforms need.

### Account-lockout-aware backoff

A **confirmed** bad credential — a completed auth negotiation that the
proxy explicitly rejected (a `407`/`403` *after* a full NTLM or Basic
attempt, not merely "auth required" or "no mechanism available") — is a
distinct failure signal from ordinary connectivity trouble, and needs
different backoff behavior. Retrying a wrong NTLM credential against a
real AD-integrated proxy on the existing 1s→120s schedule risks tripping
the domain account's lockout policy — a real operational hazard, not a
theoretical one, since many enterprise lockout thresholds trip well within
the handful of minutes the existing backoff ceiling would produce repeated
attempts across.

On this specific failure class, the next retry uses a **separate, higher
backoff ceiling — capped at 30 minutes** — instead of the existing 120s
`wsBackoffMax`, reusing the exact same exponential-with-full-jitter shape
(`wsBackoffDelay`/`wsJitter` in `agent/backoff.go`) with only the ceiling
parameter changed. This value is a deliberately conservative, safety-first
choice, not evidence-derived (unlike e.g. this project's `T1018` timeout
tuning, which came from real staging termination data) — the cost of being
too conservative here is only a delayed reconnect, while the cost of being
too aggressive is a real, disruptive account lockout that can affect other
services sharing that account. Ordinary connectivity failures (proxy
unreachable, no mechanism available) keep using the existing 120s ceiling
unchanged — only a confirmed-rejected credential triggers the longer one.

## Testing strategy

- **Basic-via-407**: fully testable locally and deterministically — a
  small fake CONNECT proxy (a raw `net.Listener` that speaks just enough of
  the CONNECT protocol to reply `407` then `200` on a correct retry) drives
  the real negotiation code end-to-end, no Docker or external service
  needed.
- **No-proxy path**: a regression test confirming direct-dial behavior
  (when `http.ProxyFromEnvironment` resolves nothing) is unchanged from
  today.
- **NTLM/SSPI**: genuine end-to-end validation needs a real
  NTLM-authenticating proxy and a real Windows domain, impractical in an
  automated run — but the *negotiation shape* (correctly detecting `NTLM`
  in `Proxy-Authenticate`, producing a well-formed Type1, correctly feeding
  a Type2 challenge back into the SSPI context) is unit-testable against a
  stub proxy that speaks the header protocol without real cryptographic
  validation behind it. Full NTLM success against a genuine corporate proxy
  is called out explicitly as a manual/staging verification step — the
  same honesty this project already applies elsewhere to things that
  structurally can't be proven in a local/CI run (e.g. Phase 0A's
  staging-only orchestrator dispatch measurement).
- **Lockout-aware backoff**: fully testable as a pure function, same
  pattern as the existing `wsBackoffDelay`/`wsJitter` tests in
  `agent/backoff_test.go` — deterministic bounds-checking, no real network
  or timing dependency.

## Success criteria

1. An agent behind a Basic-authenticating forward proxy (any platform)
   connects successfully using stored credentials, verified against a
   local fake-proxy test.
2. An agent behind an NTLM-authenticating forward proxy on Windows connects
   successfully using its own service identity via SSPI — negotiation
   shape verified against a stub proxy locally; real success verified
   manually/on staging against a genuine NTLM proxy.
3. A proxy requiring a mechanism that isn't available (NTLM on non-Windows,
   or Basic with no configured credential) fails with a specific,
   actionable log message — not the generic dial error seen today.
4. A confirmed-rejected credential triggers the 30-minute-ceiling backoff,
   not the standard 120s one; ordinary connectivity failures still use the
   120s ceiling, verified by unit test.
5. The no-proxy path is provably unchanged (existing tests plus the new
   regression test all pass).
