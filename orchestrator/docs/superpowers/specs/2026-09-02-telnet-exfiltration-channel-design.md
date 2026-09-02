# Telnet Exfiltration Channel Design

**Date:** 2026-09-02  
**Author:** Audspect Research  
**Status:** Design Phase  
**Channel:** Telnet (Exfiltration Over Unencrypted Non-C2 Protocol, T1048.003)  
**Architecture:** Eighth and final sink-verified DLP channel

---

## Overview

This channel simulates exfiltration via Telnet — a legacy, stateful, text-mode remote-shell protocol (RFC 854) commonly used for remote system administration before SSH became standard. Modern enterprise Telnet usage is rare; however, legacy systems and industrial control networks still rely on it, and benchmarks show 298 test rows expecting Telnet exfiltration coverage.

**Key design decision:** This channel does NOT run an actual Telnet daemon (TCP/23). Instead, it simulates a complete Telnet conversation (connect → prompt → command → response → close) via a single HTTPS POST request to the orchestrator's existing API server. The conversation is represented explicitly as a JSON array of state transitions, preserving the semantic flow without requiring persistent session state or a separate listener.

**Why this approach?** The benchmark objective is DLP/content detection of sensitive data leaving through a Telnet-like channel, not protocol-level inspection of actual Telnet negotiation bytes. A single atomic request carrying an explicit conversation shape is deterministic, verifiable via the same `dlp_sink_tokens`/`dlp_sink_receipts` mechanism, and sufficient for DLP controls to recognize a Telnet-shaped exfiltration attempt. An actual Telnet daemon would add operational complexity (another listener, another port, another credential store) without improving the benchmark's DLP verification.

---

## Real Telnet Protocol Context

RFC 854 Telnet defines:

- **Transport:** TCP, traditionally port 23
- **Communication:** byte-oriented streams carrying printable ASCII text commands and server responses
- **Session flow:** server sends initial prompt → client sends command → server sends response → repeat
- **Auth:** none built into the protocol; authentication happens via login credentials sent as plaintext commands after the initial prompt
- **Control characters:** in-band telnet option negotiation (IAC codes) for negotiating echo mode, terminal type, etc. — ignored for this simulation

**For exfiltration purposes:** a Telnet session used to exfiltrate data follows this pattern:
1. Client connects to the Telnet server
2. Server sends a login prompt (e.g., "login: ")
3. Client sends a username (or, in an abuse scenario, the sensitive data itself)
4. Server sends a password prompt (e.g., "password: ")
5. Client sends a password (or more sensitive data)
6. Server sends a shell prompt (e.g., "$ ")
7. Client sends a command containing or referencing sensitive data
8. Server sends a response
9. Client disconnects

For the DLP validation suite, we model a subset: connect → prompt → command (containing token + synthetic record) → response → close.

---

## Channel Architecture

### New Package: `internal/telnet sink`

**Responsibilities:**
- Single HTTP route handler for POST `/api/dlp/sink/telnet/session`
- Parses JSON request body carrying the conversation array
- Extracts and validates the token from the command state
- Enforces rate limiting and max payload bytes (same as other channels)
- Writes receipt to `dlp_sink_receipts` if token matches
- Returns a success-shaped JSON response (mocking a real Telnet response)

**No server-side session state.** Each request is independent; the "session" lives entirely in the request body.

### Request Shape

**POST /api/dlp/sink/telnet/session**

```json
{
  "token": "{{SINK_TOKEN}}",
  "session": [
    {
      "type": "connect"
    },
    {
      "type": "prompt",
      "data": "login: "
    },
    {
      "type": "command",
      "data": "<token>\n<synthetic sensitive record>"
    },
    {
      "type": "response",
      "data": "Login successful\n$ "
    },
    {
      "type": "close"
    }
  ]
}
```

**Constraints:**
- `token` is a 32-byte hex string (same `dlp_sink_tokens` format as every other channel)
- `session` array must have at least 5 entries (connect, prompt, command, response, close)
- `type` must be one of: "connect", "prompt", "command", "response", "close"
- `data` fields (prompt, command, response) carry the conversation content; total payload (all `data` fields concatenated) must not exceed 64 KiB (same `MaxPayloadBytes` ceiling every channel enforces)
- The token in the request body (top-level `"token"` field) and the token embedded in the command's `data` field should match; if they differ, the server validates the top-level token and uses that for receipt writing (the command's embedded token is telemetry only)

### Response Shape

On success (200), return a JSON object simulating a Telnet server response:

```json
{
  "result": "ok",
  "message": "Session closed"
}
```

On failure (no-match token, rate-limited, oversized), still return 200 with a plausible Telnet response, but do NOT write a receipt. This matches the behavior of every other channel: success-shaped response regardless of local verification outcome; ground truth comes from the sink alone, never from the handler's own success/failure.

### Token Placement & Extraction

**Where the token lives in the request:**
- Top-level `"token"` field: validated before receipt write (required, 32-byte hex)
- Embedded in the command state's `data` field: convention only, for scenario readability (the PowerShell step constructs this; the server doesn't parse it)

**Extraction logic:** Use the top-level `token` field. Do not attempt to parse it from the command `data`; that parsing is the scenario's responsibility.

---

## Integration Points

### 1. Routes and RBAC

Mount the route in `internal/api/routes.go`:

```go
r.Mount("/telnet", telnet.Routes(h.db))
```

Add to `publicRoutes` in `internal/api/rbac_matrix_test.go`:

```go
"POST /telnet/session": true,
```

Same unauthenticated posture as `/cloudsink` and `/webhooksink`.

### 2. Placeholder Substitution

In `internal/api/dlp_sink.go`, `issueSinkTokensAndSubstitute()`, add a new branch after the webhook block:

```go
if strings.Contains(steps[i].Command, "{{SINK_TELNET_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_TELNET_PORT}}") {
  steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_TELNET_HOST}}", telnetSinkHost(publicBaseURL))
  steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_TELNET_PORT}}", telnetSinkPort(publicBaseURL))
}
```

Add helper functions following `webhookSinkHost`/`webhookSinkPort`:

```go
func telnetSinkHost(publicBaseURL string) string {
  if v := os.Getenv("SINK_TELNET_HOST"); v != "" {
    return v
  }
  return dnsServerHost(publicBaseURL)
}

func telnetSinkPort(publicBaseURL string) string {
  if v := os.Getenv("SINK_TELNET_PORT"); v != "" {
    return v
  }
  if u, err := url.Parse(publicBaseURL); err == nil && u.Port() != "" {
    return u.Port()
  }
  return "443"
}
```

Rationale: same as cloud storage and webhook channels. The Telnet routes are mounted on the existing HTTPS server, so the port comes from `publicBaseURL`, not a hardcoded default.

### 3. Scenario and Detection Profile

**Scenario:** `scenarios/dlp-exfiltration-telnet.yaml`
- One step: Telnet login session (T1048.003)
- PowerShell executor constructs the JSON conversation, Invoke-RestMethod POSTs it to `/telnet/session`
- Embeds `{{SINK_TOKEN}}` in the command state
- Synthetic record: same PAN/Aadhaar/SWIFT/UPI/credit-card pattern as every other channel
- Verdict resolved server-side via sink receipt, not by script success/failure

**Detection Profile:** Add `telnet-block` entry to `windows_dlp_exfiltration.yaml`
- ID: `dlp-telnet-block`
- Provider: `trellix_dlp`
- Technique: T1048.003 (already in the profile from SMTP; add Telnet to the entry's description)
- Expected outcome: Block
- Finding title: "DLP/network controls did not block Telnet-based exfiltration of regulated data"

Add T1048.003 to `technique_ids` if not already present (it should be, from SMTP).

---

## Rate Limiting and Payload Ceiling

**Rate limiter:** One shared instance per `internal/telnet sink` package (one request per source IP per second, max 5 requests/second).

**MaxPayloadBytes:** 64 KiB. Enforced via `http.MaxBytesReader` before buffering the request body.

Rationale: identical to every other channel. These surfaces only expect traffic from BAS agents running a scenario step; rate limiting protects against local abuse or misconfiguration.

---

## Testing Strategy

### Unit Tests: `internal/telnet sink/telnet_test.go`

1. **Happy path:** Construct a valid session JSON with a matching token; verify receipt is written.
2. **Unmatched token:** Send a session with a token that doesn't exist in `dlp_sink_tokens`; verify no receipt is written, but the response is still 200 + plausible "ok".
3. **Oversized payload:** Construct a session where concatenated `data` fields exceed 64 KiB; verify rejection (no receipt).
4. **Rate limiting:** Send 6 requests from the same IP within 1 second; verify the 6th is rejected (rate-limited).
5. **Missing required fields:** Omit the `token` field or send an empty `session` array; verify no crash, no receipt.
6. **Invalid type values:** Include a session state with `type: "invalid"`; verify no crash or unexpected behavior.

### Integration Tests: `internal/api/dlp_sink_test.go`

Add tests parallel to the existing cloud storage / webhook tests:

1. **`TestIssueSinkTokensAndSubstitute_TelnetPlaceholders`:** Verify `{{SINK_TELNET_HOST}}` and `{{SINK_TELNET_PORT}}` are substituted correctly.
2. **`TestTelnetSinkPort_DerivesFromPublicBaseURL`:** Verify the port is extracted from `publicBaseURL` and not hardcoded.
3. **`TestTelnetSinkHost_HonorsExplicitOverride`:** Verify `SINK_TELNET_HOST` env var overrides the derived host.
4. **`TestTelnetSinkDoesNotIssueOrphanedSecondToken`:** Verify only one token per run is issued, even if multiple steps have `{{SINK_TELNET_HOST}}/{{SINK_TELNET_PORT}}` placeholders.

### Full-Suite Verification

Run `go test ./internal/telnet sink/... ./internal/api/... ./internal/verifysync/... ./internal/reporting/...` to confirm:
- All telnet-specific tests pass
- `TestRBACMatrix_NoDrift` passes (routes are in the allowlist)
- No regressions in verifysync or reporting

---

## Special Considerations

### Why Not a Real Telnet Daemon?

An actual Telnet server (listening on TCP/23 or a non-standard port) would require:
1. A new listener and port binding in `docker-compose.yml` and `config/main.go`
2. Credentials or a fake login system
3. Session state tracking on the server
4. Additional container resource usage

**Against this:** The benchmark's objective is DLP detection of sensitive data, not protocol-level Telnet inspection. The JSON conversation shape is sufficient for a DLP control to recognize "exfiltration via Telnet-like session"; the data is still subject to inspection, and the sink receipt still proves it reached the orchestrator. An actual daemon adds complexity without improving the benchmark signal.

### Telnet Options Negotiation

Real Telnet includes in-band IAC (Interpret As Command) bytes for negotiating echo mode, terminal type, window size, etc. This simulation deliberately omits them because:
1. DLP controls typically don't inspect protocol negotiation; they inspect payload content
2. Including IAC bytes would require binary-safe JSON encoding (escape sequences), adding complexity
3. The benchmark doesn't require protocol-level fidelity

If a future requirement arises (e.g., "detect Telnet via IAC byte signatures"), this channel would need to be redesigned with a real Telnet listener or a binary-safe protocol layer.

### Statefulness

The JSON conversation array models state transitions declaratively (connect → prompt → command → response → close), not imperatively. This is sufficient for the benchmark because:
- The DLP control inspects the command's payload (where the token and sensitive data live)
- The orchestrator validates the token and writes a receipt
- The scenario confirms the test succeeded by checking for a receipt matching its run ID

No persistent server-side session state is needed; each request is atomic.

---

## Files Affected

**Create:**
- `orchestrator/internal/telnet sink/telnet.go` — rate limiter, byte ceiling, receipt writer, router
- `orchestrator/internal/telnet sink/telnet_test.go` — unit tests
- `orchestrator/scenarios/dlp-exfiltration-telnet.yaml` — one-step scenario
- `orchestrator/scenarios/dlp-exfiltration-telnet.yaml.sig` — signed scenario

**Modify:**
- `orchestrator/internal/api/routes.go` — mount `/telnet` routes
- `orchestrator/internal/api/rbac_matrix_test.go` — add route to `publicRoutes`
- `orchestrator/internal/api/dlp_sink.go` — add placeholder-substitution branch and helper functions
- `orchestrator/internal/api/dlp_sink_test.go` — add placeholder and port-derivation tests
- `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml` — add `dlp-telnet-block` entry
- `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig` — re-sign

---

## Success Criteria

1. New `internal/telnet sink` package loads without errors
2. POST `/api/dlp/sink/telnet/session` accepts a valid conversation JSON and writes a receipt
3. Scenario `dlp-exfiltration-telnet.yaml` loads and runs without errors
4. `TestRBACMatrix_NoDrift` passes (route is in the allowlist)
5. Full `internal/telnet sink`, `internal/api`, `internal/verifysync`, and `internal/reporting` suites pass
6. No new compiler warnings or gofmt issues
7. Scenario execution confirms receipt is written for a matching token

---

## Implementation Notes

- Follow the established pattern from `internal/cloudsink` and `internal/webhooksink`: same rate limiter shape, same receipt-write helper, same token-validation logic
- PowerShell scenario executor: use Invoke-RestMethod with -Body (ConvertTo-Json), -ContentType 'application/json', -Method Post
- Token extraction in the handler: read from top-level `"token"` field, not from the command `data`; this keeps the handler simple and the scenario's job clear
- Signature: sign the scenario YAML and detection-profile YAML via `go run scripts/signer.go sign private_key.pem <file>`

---

## Open Questions for Review

None — this design follows the established architecture exactly. The only novel aspect is the JSON conversation array, which is a straightforward data-structure choice, not an architectural question.
