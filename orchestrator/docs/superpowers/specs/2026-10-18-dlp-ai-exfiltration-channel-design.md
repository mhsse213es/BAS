# DLP-AI Exfiltration Channel — Design

## Intent and why

`dlp.txt` §1.07 names "Generative AI and emerging exfiltration channels" as
one of the 8 DLP attack-surface areas, and §3B names `DLP-AI` ("Prompt
inspection, file uploads, enterprise AI tools, public AI services and
connector-mediated data exposure") as one of 10 exfiltration-channel
scenario families. Of those 10, `DLP-AI` has zero code today — no sink
package, no scenario, not even a grep hit for "genai"/"copilot" anywhere in
the repo (confirmed by audit, 2026-10-18).

Audspect already has 9 working exfiltration-channel sink packages
(`dnssink`/`sftpsink`/`smtpsink`/`cloudsink`×7 providers/`webhooksink`×4
providers/`telnetsink`), all sharing one architecture: a Go package exposes
HTTP routes mounted on the orchestrator's own API server that mimic a real
destination's request shape (path, method, body format), using the shared
`dlp_sink_tokens`/`dlp_sink_receipts` tables for destination-side-receipt
verification — the step's own local output is never trusted as ground
truth. `internal/webhooksink` is the closest precedent: 4 routes across 2
unrelated real services (Slack/Teams incoming webhooks, GitHub/GitLab
snippet-creation APIs), one `chi.Router`, one shared rate limiter.

`DLP-AI` fits this exact pattern. The "destination" being mimicked is a
generative-AI service's own prompt-submission or file-upload API — the
traffic shape a DLP product must inspect to catch sensitive data leaving
through an AI channel, not a real OpenAI/Microsoft/Google account. Exactly
like Slack/Teams in `webhooksink`, this never contacts a real vendor
endpoint.

## Goals

1. A new standalone package, `internal/aisink`, mimicking 2 genuinely
   different real-world AI integration shapes (not 2 near-identical ones):
   a public AI chat-completion API (OpenAI-compatible `POST
   /v1/chat/completions`, sensitive content embedded in the request body's
   `messages[].content`), and an enterprise AI connector/retrieval-ingestion
   API (mimicking Microsoft Graph's connector content-ingestion shape:
   `POST /v1.0/external/connections/{connectionId}/items/{itemId}`, a file
   upload rather than a chat message).
2. Destination-side-receipt verification only — identical discipline to
   every sibling sink: `dlp_sink_tokens`/`dlp_sink_receipts`, SHA-256 body
   hash, never raw content persisted, never a step's own local output
   trusted as the verdict.
3. A new scenario, `dlp-exfiltration-ai-prompt.yaml`, with steps covering
   both shapes and at least 2 of the existing data-type-diversity patterns
   (not only the stock BFSI/India payload — mirrors every sibling channel's
   own diversity, per `dlpfixture`/the content-type-diversity effort).
4. MITRE mapping: `T1567` (Exfiltration Over Web Service) — the parent
   technique, not a sub-technique. None of `T1567.002` (cloud storage),
   `.003` (removed/deprecated), `.004` (webhook) accurately describes a
   chat-completion or connector-ingestion API; the parent technique is the
   honest fit, same reasoning `dlp.txt` itself uses when it says these are
   "approved versus unapproved AI services," not a literal webhook.

## Non-goals

- Contacting any real AI vendor API (OpenAI, Anthropic, Microsoft Copilot,
  Google Gemini) — traffic-shape simulation only, identical boundary to
  every sibling sink.
- Prompt-injection, jailbreak, or model-output-safety testing — this is a
  DLP exfiltration-channel test (does sensitive data leaving via an AI
  channel get caught by DLP), not an AI red-team/LLM-security test. Those
  are a different capability family entirely.
- A real "approved vs. unapproved AI service" allowlist/policy integration
  — out of scope; this package only produces the two observable traffic
  shapes. Classifying which AI services an org has approved is a
  `dlppolicy`/`dlpprofile`-layer concern, not this package's.

## Anti-goals

- Must not become a 3rd way to call `dlp_sink_tokens`/`dlp_sink_receipts`
  — reuse the exact `tokenExists`/`writeReceipt` pattern `webhooksink` uses
  (duplicated per-package by existing precedent, since the type is
  unexported there too — do not refactor that precedent in this slice).
- Must not silently claim DLP-AI is now "fully covered" — `dlp.txt` names
  "connector-based retrieval" and "agent workflows" as sub-cases this
  2-route package does not attempt (no multi-turn conversation state, no
  RAG retrieval simulation). Scenario description and memory must name
  this gap explicitly, same honesty discipline as every other slice this
  session.

## Builder's call

**Package:** `internal/aisink`, mirroring `internal/webhooksink`'s file
layout (one file per route family, shared `aisink.go` for the router +
rate limiter + token/receipt helpers).

```go
package aisink

// MaxPayloadBytes matches every sibling channel's own ceiling.
const MaxPayloadBytes = 64 * 1024

// Routes returns the chi.Router mounted at /aisink by internal/api/routes.go.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Post("/v1/chat/completions", handleChatCompletion(db))
	r.Post("/v1.0/external/connections/{connectionId}/items/{itemId}", handleConnectorIngestion(db))
	return r
}
```

Audit of all 4 existing `webhooksink` handlers (`slack.go`/`teams.go`/
`github.go`/`gitlab.go`) found every one embeds the token inside the body
itself (first line of a text field, or a filename stem) — none uses a
header or path parameter, and `github.go`'s own comment explains why:
"the Authorization header's value is never validated... this channel
tests whether DLP inspected the traffic, not whether the caller
authenticated." Both new handlers below follow that exact precedent
rather than inventing a new token-carrying mechanism.

`handleChatCompletion`: accepts a JSON body shaped like an OpenAI
chat-completion request: `{"model": "...", "messages": [{"role": "user",
"content": "..."}]}`. The token is the first line of
`messages[0].content` (same `strings.SplitN(text, "\n", 2)[0]` pattern as
`slack.go`/`teams.go`), the rest of that line's content is the synthetic
sensitive record — this mirrors the real-world shape exactly: a user
pastes sensitive data into a chat prompt, and DLP must inspect the
outbound body before it leaves. Responds 200 with a minimal OpenAI-shaped
body (`{"choices":[{"message":{"content":"..."}}]}`) regardless of token
match.

`handleConnectorIngestion`: accepts a JSON body shaped like a Microsoft
Graph connector item: `{"id": "...", "content": {"value": "...", "type":
"text"}}`. Token is the first line of `content.value`, identical
extraction pattern. Responds 201 regardless of match.

Both handlers write the receipt's `channel` column as `"ai-chat-completion"`
/ `"ai-connector-ingestion"` respectively — free-text column, no migration
needed (confirmed: `dlp_sink_receipts.channel` has no CHECK constraint or
enum).

**Routes wiring:** `internal/api/routes.go`, same block pattern as
`/cloudsink`/`/webhooksink`: `r.Mount("/aisink", aisink.Routes(h.db))`.

**Scenario:** `scenarios/dlp-exfiltration-ai-prompt.yaml`. Steps (mirroring
the webhook scenario's own step count and diversity, `windows` only,
`framework: custom`, `executor: powershell`):
1. Chat-completion shape — stock BFSI/India multi-type record (same
   fabricated PAN/Aadhaar/SWIFT/UPI/card pattern every sibling channel's
   first step uses, for cross-channel comparability).
2. Chat-completion shape — a genuinely different data type not yet used by
   this specific scenario (e.g. source-code-shaped content, following the
   content-type-diversity precedent).
3. Connector-ingestion shape — stock BFSI/India record.
4. Connector-ingestion shape — a second distinct data type.

All 4 use `{{SINK_TOKEN}}`/`{{SINK_URL}}` placeholders exactly like every
sibling scenario — no new token-issuance code needed, `issueSinkTokensAndSubstitute`
already handles any step containing those placeholders regardless of
destination shape.

**Technique ID:** `T1567` on every step (not a sub-technique — see Goal 4).

## What's left to the builder

- Exact wording of each step's `Write-Output`/`blast_radius`/`description`
  text — follow the sibling scenarios' own phrasing conventions closely
  (e.g. "traffic-shape simulation only," "[BAS-SIM-DLP-AI-...]" tag
  prefix).
- Exact PowerShell `Invoke-RestMethod`/`Invoke-WebRequest` call shape per
  step — follow `dlp-exfiltration-webhook.yaml`'s own steps as the direct
  template, swapping body shape and auth-header placement per handler.
- Whether to add a short note to `scenarios/dlp-exfiltration-multichannel.yaml`'s
  description (already known-stale per `[[project_dlp_mastery_initiative]]`
  — not blocking, fix opportunistically only if touching that file is
  already in scope elsewhere).
