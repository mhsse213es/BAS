# Webhook / Code-Repository Exfiltration Channel — Design

## Problem

Seventh channel of the DLP exfiltration maturity program, following HTTPS,
DNS tunneling, SFTP, SMTP, and cloud storage (all DONE); ICMP tunneling
deferred (see its own spec's status notice). The DLP exfiltration channel
roadmap grouped Slack, MS Teams, GitHub, and GitLab together as
"webhook-style POST" and originally deprioritized all four as duplicating
HTTPS's test value ("all four ultimately resolve to the same POST → sink →
inspect path against the same on-prem hostname"). That framing turned out to
be only half right — see Decisions.

An external third-party DLP benchmark (`data_exfiltration_csv_report.csv`,
analyzed earlier this session) tests these four as distinct 298-row Attack
Type categories, confirming real-world DLP/CASB products treat them as
separate, meaningful test surfaces.

## Decisions

Confirmed during brainstorming:

- **Two genuinely different emulation families, not four instances of one
  shape.** Slack and MS Teams have a real "incoming webhook" primitive —
  push arbitrary JSON to a unique URL, no separate auth. GitHub and GitLab
  do not; their actual exfiltration-relevant abuse surface is their REST
  APIs (creating a private Gist / Snippet), which is a structurally
  different request (method/path/auth-header/body shape) mapping to a
  different MITRE technique entirely. Forcing GitHub/GitLab into a
  webhook-style POST for implementation convenience would misrepresent
  what's actually being tested and misattribute the technique.
- **Standing architectural principle, recorded here for every future
  channel:** BAS channels emulate the platform's real abuse primitive, not
  a common HTTP shape chosen for implementation convenience. When two
  providers' real abuse paths genuinely differ (as Slack/Teams vs.
  GitHub/GitLab do here), the channel design must preserve that
  difference — including mapping to different MITRE techniques when the
  real techniques differ — rather than flattening them into one shape.
- **MITRE techniques, confirmed against this repo's own bundled ATT&CK
  data** (`orchestrator/internal/reporting/attackdata/attack_enrichment.json`):
  - **T1567.004 — Exfiltration Over Webhook** for Slack and MS Teams. Its
    own ATT&CK description explicitly names Discord, Slack, and
    `webhook.site` as webhook *destinations* — GitHub/Jira/Trello appear
    only as event *sources* that push data into other services' webhooks,
    never as webhook destinations themselves. This directly rules out
    using T1567.004 for GitHub/GitLab.
  - **T1567.001 — Exfiltration to Code Repository** for GitHub and GitLab.
    Its own description explicitly names `api.github.com` as the kind of
    API such exfiltration uses.
- **Auth-header fidelity differs by provider, deliberately, matching each
  provider's real behavior:** Slack/Teams incoming webhooks carry no
  separate auth header in reality (the webhook URL itself is the secret),
  so the emulated requests carry none either. GitHub/GitLab's real Gist/
  Snippet-creation APIs always carry an auth header (`Authorization: token
  <PAT>` / `PRIVATE-TOKEN: <token>`), so the emulated requests include one
  too — a fixed, obviously-synthetic placeholder value, never a real
  credential, matching every other channel's "no real signing/auth" bar
  (this is presence-of-header fidelity, not cryptographic authenticity).
- **On-prem-only, same as every channel:** all four routes live on the
  orchestrator's own existing HTTPS API server (`internal/webhooksink`,
  mirroring `internal/cloudsink`'s isolation exactly) — no real
  slack.com/teams.microsoft.com/github.com/gitlab.com is ever contacted, no
  real account or credential is ever needed. No new listener, no new port,
  no new capability grant.
- **Token correlation, per provider's natural shape:** Slack/Teams carry
  the token embedded directly in the JSON body's message-text field (the
  same field real exfiltrated data would actually appear in). GitHub/
  GitLab carry it in the Gist/Snippet's filename — the same filename-token
  pattern SFTP and cloud storage's S3/Azure Blob handlers already
  established. Reuses the existing 32-byte/64-hex `{{SINK_TOKEN}}`
  unchanged.
- **Token validated against `dlp_sink_tokens` before any receipt is
  written** — same pattern as SMTP and cloud storage, not the
  accept-anything HTTP/SFTP pattern, for the same reasoning (four more open
  endpoints is a larger accidental-scanning surface worth gating).

## Design

### 1. Package structure and routes

New package `internal/webhooksink`, structured identically to
`internal/cloudsink` (shared rate limiter, `tokenExists`/`writeReceipt`
helpers, one `Routes(db *pgxpool.Pool) chi.Router` mounted at
`/webhooksink` by `internal/api/routes.go`, same public/unauthenticated
posture as every sink endpoint).

| Provider | Route | Real shape mimicked |
|---|---|---|
| Slack | `POST /webhooksink/slack/services/{a}/{b}/{c}` | Slack Incoming Webhook path structure; JSON body `{"text": "..."}` |
| MS Teams | `POST /webhooksink/teams/webhookb2/{guid}/IncomingWebhook/{guid2}/{guid3}` | Teams Incoming Webhook path structure; JSON body `{"text": "..."}` |
| GitHub | `POST /webhooksink/github/gists` | GitHub's real `POST /gists` path; `Authorization: token <synthetic>` header; JSON body with `files` map |
| GitLab | `POST /webhooksink/gitlab/api/v4/snippets` | GitLab's real `POST /api/v4/snippets` path; `PRIVATE-TOKEN: <synthetic>` header; JSON body |

`{a}`/`{b}`/`{c}` and the Teams GUIDs are fixed synthetic literals baked
into the scenario step (not placeholders, not secrets) — matching every
prior channel's fixed-literal-identifier precedent (SFTP's `dlptest@`,
SMTP's fixed address, cloud storage's `bas-sim-bucket`).

### 2. Per-provider body shapes and token placement

**Slack** (`text` field carries token + record together):
```json
{"text": "<64-hex-token>\n[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard\n..."}
```

**MS Teams** (same field, same reasoning):
```json
{"text": "<64-hex-token>\n[BAS-SIM-DLP] ..."}
```

**GitHub** (token in filename, record as file content):
```json
{
  "description": "bas-sim",
  "public": false,
  "files": { "<64-hex-token>.dat": { "content": "[BAS-SIM-DLP] ..." } }
}
```

**GitLab** (same pattern, GitLab's own field names):
```json
{
  "title": "bas-sim",
  "visibility": "private",
  "file_name": "<64-hex-token>.dat",
  "content": "[BAS-SIM-DLP] ..."
}
```

Each handler extracts the token from wherever its own provider naturally
carries it (JSON `text` field's leading line for Slack/Teams; the `files`
map's key for GitHub; `file_name` for GitLab) — four different extraction
functions, matching how cloud storage's seven handlers each had their own
provider-specific extraction logic.

### 3. Token generation and placeholder substitution

`issueSinkTokensAndSubstitute` (`internal/api/dlp_sink.go`) gains one new
placeholder branch for `{{SINK_WEBHOOK_HOST}}`/`{{SINK_WEBHOOK_PORT}}`,
structured exactly like cloud storage's block — triggered independently,
relying on the existing unconditional `{{SINK_TOKEN}}` block. `webhookSinkPort`
mirrors `cloudSinkPort`'s corrected design exactly (derives from
`publicBaseURL`'s own port, not a hardcoded default — this is the same
server as the main API, not an independently-bound port):

```go
if strings.Contains(steps[i].Command, "{{SINK_WEBHOOK_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_WEBHOOK_PORT}}") {
    steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_WEBHOOK_HOST}}", webhookSinkHost(publicBaseURL))
    steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_WEBHOOK_PORT}}", webhookSinkPort(publicBaseURL))
}
```

### 4. Receipt persistence

Same insert shape every channel uses, `channel` column distinguishing all
four (and visibly encoding the technique split): `webhook-slack`,
`webhook-teams`, `coderepo-github`, `coderepo-gitlab`.

Because `dlp_sink_receipts` and its consumers already only check "does at
least one receipt exist for this token," no changes are needed to
`internal/verifysync` or `internal/reporting`.

### 5. Security hardening

Same bar as cloud storage: `MaxPayloadBytes` ceiling on the request body
(64KB, consistent with every channel), one shared rate limiter across all
four routes, token validated before any receipt write, logging never
includes token or payload content — only size and hash.

### 6. V1 scenario content

**Two scenarios**, matching the two-technique split (not one scenario with
four steps under a false shared technique):

- `scenarios/dlp-exfiltration-webhook.yaml` — two steps (Slack, Teams),
  both `technique_id: T1567.004`.
- `scenarios/dlp-exfiltration-coderepo.yaml` — two steps (GitHub, GitLab),
  both `technique_id: T1567.001`.

Each step: `Invoke-RestMethod` directly (no tool-presence check — built-in
PowerShell cmdlet, same "always there" category as every prior HTTP-based
channel), writes the synthetic `[BAS-SIM-DLP]` record into the
provider-appropriate field, captures `DLP_OBSERVATION:`/success-failure as
diagnostic evidence only — never the graded verdict.

Two new detection-profile entries in
`scenarios/detection-profiles/windows_dlp_exfiltration.yaml` —
`dlp-webhook-block` (T1567.004) and `dlp-coderepo-block` (T1567.001) —
each covering its own two steps, matching the profile's existing
one-entry-per-technique shape.

## Testing

- Go unit tests in `internal/webhooksink`, one per provider handler: token
  extraction from that provider's specific location, correct receipt on a
  matched token (with the right `channel` value), correct no-op on an
  unmatched token, `MaxPayloadBytes` rejection.
- `internal/api/dlp_sink_test.go`: `{{SINK_WEBHOOK_HOST}}`/
  `{{SINK_WEBHOOK_PORT}}` substitution, the 32-byte-token-reused
  regression check, and the orphaned-second-token regression test every
  channel since SFTP has included from the start.
- `internal/api/rbac_matrix_test.go`: add all four new routes to
  `publicRoutes` in the same task that adds the routes — this exact
  regression (routes registered but not added to the RBAC drift allowlist)
  was caught and fixed during cloud storage's implementation; the plan
  must not repeat it.
- Regression confirmation: full `internal/verifysync` and
  `internal/reporting` suites re-run to prove neither needs any change.
- Integration-style tests: for each provider, dispatch a step-shaped
  request against a real `httptest.Server` wrapping `webhooksink.Routes`,
  confirm a `dlp_sink_receipts` row lands with the correct channel/hash/
  size.

## Out of scope

- Real Slack/Teams/GitHub/GitLab accounts, API tokens, or webhook URLs —
  every request's real destination is this on-prem orchestrator; no
  external service is ever contacted, matching every prior channel's
  identical constraint.
- Real signing/authentication validity for GitHub/GitLab's auth headers —
  presence-of-header fidelity only, per the Decisions section.
- Other webhook-capable services (Discord, Jira, Trello, generic
  `webhook.site`-style endpoints) — the roadmap's benchmark cross-check
  only identified Slack/Teams/GitHub/GitLab as tested categories; adding
  more providers is a future decision, not assumed needed here.
- Telnet — next and last item in the current DLP exfiltration channel
  roadmap after this one.
