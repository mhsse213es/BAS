# DLP Exfiltration Sink Service — Design

## Problem

First sub-project of a larger DLP-exfiltration-maturity program. The
platform's only framework-integrated DLP scenario
(`scenarios/dlp-exfiltration-validation.yaml`) verifies every one of its 5
channels (USB, clipboard, print, archive, local staging) by trusting a
self-printed marker line the step's own PowerShell script writes, based on
its own local `Test-Path`/`Get-Clipboard`/spool-queue check. The verifier
(`dlpVerifier`, `internal/reporting/dlp.go`) never asks a real DLP product
and never checks whether data actually reached anywhere — it grades the
script's opinion of itself.

A real-world reference point: a genuine commercial DLP-testing tool's
export (`data_exfiltration_csv_report.csv`, 5,456 rows) shows how mature
tools actually verify exfiltration — they perform real outbound transfers
with synthetic payloads and determine the verdict from whether the
transfer **actually completed at a real destination**, not from asking a
vendor's product API what it decided. That destination-side confirmation
is the piece this platform is missing entirely, and it's the correct place
to start: it's a more universal verification primitive than building N
per-vendor DLP product connectors, since it works regardless of which (if
any) DLP/CASB/proxy product a customer runs.

This is sub-project 1 of the larger program: a **sink service** that can
receive and verifiably confirm a synthetic exfiltration payload actually
arrived, replacing self-reported local success/failure as the source of
truth for any scenario step wired to it.

## Decisions

Confirmed with the user during brainstorming:

- **Sink location (V1): on-prem**, hosted on the customer's own
  orchestrator (new endpoint on the already-running, already-TLS'd
  process). Tests whether internal DLP/proxy content inspection catches
  the transfer before it leaves the endpoint or reaches an internal
  collection point. Does **not** test external egress-boundary controls
  (firewall/CASB rules against a genuinely external, unknown-reputation
  destination) — that requires real internet reachability, and is
  explicitly deferred to a later, opt-in, Audspect-hosted mode once this
  on-prem architecture is proven. Chosen because the platform is
  on-prem-first with real air-gapped support elsewhere (optional
  MISP/OpenCTI/OTX connectors, offline threat-intel bundles); a sink that
  requires internet reachability from V1 would contradict that for no
  proven benefit yet.
- **Receipt integrity: a signed, single-use token per attempt** — not
  plain arrival logging. At dispatch time the orchestrator generates a
  random token and gives it to the agent to include in its request; the
  sink just logs whatever it receives (no per-token logic there); the
  verifier looks up whether *that specific* token was received, exactly
  once, within the run's time window. This was confirmed necessary, not
  over-engineering: `newID()` (`internal/api/handlers.go:3128`,
  `fmt.Sprintf("%x", time.Now().UnixNano())`) is not cryptographically
  random — a nanosecond timestamp is guessable within a narrow window —
  so reusing an existing run ID as an anti-replay token would not
  actually be safe. A dedicated `crypto/rand` token is required.
- **Agent stays unchanged.** Consistent with this platform's existing
  "dumb executor" principle (agent is task receiver + executor only, all
  intelligence lives server-side), the token is substituted directly into
  the step's PowerShell text server-side before dispatch, via a
  `{{SINK_TOKEN}}` placeholder — not delivered via a new environment
  variable the agent would need to learn to set. (`$env:BAS_RUN_ID`,
  referenced in the existing DLP scenario's PowerShell, turns out to be
  dead code — grepped the entire agent codebase and nothing ever sets it;
  its `Get-Random` fallback is what always executes today. There is no
  existing per-run env-var injection mechanism to extend, confirming
  placeholder substitution is the right — and only practical — approach,
  not a shortcut around something already built.)
- **V1 scope is the architecture, not channel breadth.** One new channel
  (generic HTTPS POST) in a new standalone scenario file, proving the full
  loop end-to-end. The other ~18 channels visible in the Cymulate
  reference (S3/Azure/GCS, GitHub/GitLab, Slack/Teams, SFTP, DNS
  tunneling, etc.) are explicitly deferred to follow-on sub-projects.

## Design

### 1. Token issuance & step invocation

At dispatch time, for any step whose `command:` text contains
`{{SINK_TOKEN}}` (and `{{SINK_URL}}` for the sink's own address, so
scenario authors never hardcode a host/port), the orchestrator:

- Generates a token via `crypto/rand` (not `newID()` — see above).
- Substitutes both placeholders into the command text before sending it to
  the agent, exactly as today's dispatch already sends fully-formed
  PowerShell text — no new agent-side capability needed.
- Records `{token, runID, stepName, expiresAt}` server-side for the
  verifier to look up later.

The agent runs the resulting script exactly as it runs any other step —
it has no awareness a substitution happened.

### 2. Sink endpoint

New endpoint, e.g. `POST /api/dlp/sink`, on the orchestrator's existing
HTTPS server (same certificate, same process, no new infrastructure).
Deliberately **no conventional agent-JWT authentication** on this specific
endpoint: the point is testing whether *content* gets intercepted in
flight, not testing access control, and requiring standard auth would make
every attempt indistinguishable from a normal authenticated API call to
whatever's inspecting the traffic. The per-attempt token is what prevents
abuse — a garbage POST with an unrecognized token proves nothing and is
simply never matched to any run.

Accepts `{token, payload, channel}`. Hashes the payload (SHA-256) and
writes `{token, receivedAt, sourceIP, payloadHash, payloadSize, channel}`
to a new `dlp_sink_receipts` table. The raw payload is **not** stored —
even though it's always synthetic `[BAS-SIM-DLP]`-tagged data, there's no
reason to retain it beyond a hash for evidence.

### 3. Verifier integration

`dlpVerifier` (`internal/reporting/dlp.go`) gains a second observation
source. For a step whose command included `{{SINK_TOKEN}}`, the verdict
becomes **sink-receipt-primary**:

- Token received in `dlp_sink_receipts` within the run's window →
  `OperationSucceeded` (the data genuinely reached the destination — DLP
  failed to catch it).
- Token never received → `OperationBlocked`.

The existing self-printed local marker (`DLP_OBSERVATION: ...`) is kept as
secondary/diagnostic evidence for sink-wired steps (useful for triage —
did the local operation itself think it succeeded, even if the network
path disagreed) but is no longer the graded truth for those steps. Steps
without the placeholder — the current 5 in
`dlp-exfiltration-validation.yaml` — are completely unaffected; this is
additive, not a replacement of the existing mechanism.

### 4. V1 scenario content

A new, standalone scenario file, `scenarios/dlp-exfiltration-sink-https.yaml`
— one step: a generic `Invoke-RestMethod` HTTPS POST of the same synthetic
multi-type record (`[BAS-SIM-DLP]` PAN/Aadhaar/SWIFT/UPI/credit-card
pattern) the existing scenario already uses, carrying `{{SINK_TOKEN}}` and
posting to `{{SINK_URL}}`. Deliberately **not** added as a 6th step to the
existing 5-step file — that file is signed, working, and uses a different
(local-marker-only) verification model; mixing verification models within
one file would muddy what each step actually proves. The existing file's
own description already anticipates this ("Insider Risk, Cloud Storage,
Email, and other channels follow as later, separate scenarios under the
same pillar") — this fits that established pattern.

Expected outcome: `Block` (same as the existing 5 steps) — a real DLP/proxy
should recognize the regulated-data pattern and prevent the POST from
completing, meaning the sink never receives the token.

## Testing

- Go unit tests: token generation/lookup, the sink HTTP handler (valid
  token recorded correctly; unknown token accepted but never matched to
  any run — no error leaked to the caller either way, since revealing
  "that token isn't recognized" would itself be a signal to anything
  inspecting the response).
- `dlpVerifier` test: sink-receipt-primary logic — token received →
  `OperationSucceeded`; not received within the window → `OperationBlocked`;
  confirms the existing 5 local-marker-only steps are unaffected by the
  new code path.
- An integration-style test: dispatch a step, POST a real token to the
  sink endpoint, confirm `dlpVerifier` resolves the correct verdict from
  that receipt.

## Out of scope

- Any additional channel beyond the one generic HTTPS POST (S3, Azure
  Blob, GCS, GitHub/GitLab, Slack, Teams, SFTP, DNS tunneling, etc.) — all
  deferred to follow-on sub-projects once this architecture is proven.
- The internet-reachable / Audspect-hosted sink mode, and the
  egress-boundary-control testing it would enable — deferred pending a
  separate decision once the on-prem architecture ships.
- Per-vendor DLP product API connectors (Trellix/Purview/Forcepoint) —
  remain a secondary enrichment idea (why was it blocked), not required
  for this sink-based primary verdict.
- A synthetic-content generation engine (real .docx/.xlsx/.pdf/OCR-image
  construction) — the reused existing synthetic CSV record is sufficient
  for V1; content-format depth is a separate sub-project.
- The DLP compliance dashboard / drift-tracking reporting layer — has
  nothing to report on yet until sink-verified channels exist beyond this
  one.
