# SMTP Exfiltration Channel — Design

## Problem

Fourth sub-project of the DLP exfiltration maturity program, following
HTTPS, DNS tunneling, and SFTP (see their specs in this same directory).
Per the user's own prioritized roadmap
([[project_dlp_exfiltration_channel_roadmap]]), SMTP/E-mail is next: a
genuinely different exfiltration technique — data leaving as an email
message over its own SMTP session — that tests whether mail-gateway and
network-layer DLP controls catch regulated data being emailed out,
independent of the HTTP-body, DNS-query-label, and SFTP-file-upload
channels already covered.

Unlike SFTP, this channel's client-side story is simple: `Send-MailMessage`
is built into PowerShell's `Microsoft.PowerShell.Utility` module on both
Windows PowerShell 5.1 and PowerShell 7+ — zero-install, always present,
the same "always there" category as `Invoke-RestMethod` (HTTPS) and
`nslookup` (DNS). It's marked deprecated in PS7 (emits a warning) but
remains fully functional. **This channel does not need SFTP's
`skip:`-if-absent pattern at all** — there is no realistic "tool missing"
case to handle.

## Decisions

Confirmed during brainstorming:

- **Client: `Send-MailMessage`, always present, no absence handling.**
  Confirmed built into both PowerShell generations shipped on Windows;
  unlike `sftp.exe`, there is no plausible "not installed" case for this
  scenario to guard against. The step's command is unconditional —
  straight to sending, no `Get-Command` check, no `skip:` branch.
- **Port: `587` (the SMTP "submission" port), no internal/external
  split.** Unlike SFTP's port-22-vs-host-sshd collision (near-certain on
  every deployment target) or DNS's port-53-vs-systemd-resolved collision
  (also fixed this program), port 587 carries much lower collision risk:
  a host's local MTA (postfix/sendmail/exim), if one is even running,
  conventionally listens on port 25, not 587. The container-internal
  listener and the host-published port are the same value —
  `SINK_SMTP_PORT`, default `587` — no SFTP-style split needed. Network
  reachability of 587 from the agent's own network position remains an
  environmental condition like any other; it is never assumed either way
  and is not treated specially by the verdict model (see below).
- **Verdict stays strictly sink-primary — `Succeeded` (token reached the
  sink) or `Blocked` (it didn't), same as HTTPS/DNS/SFTP.** Because the
  client tool is always present here, the three-way `skip: / Succeeded /
  Blocked` split SFTP needed collapses back to the original two-way model
  every earlier channel used: `Send-MailMessage`'s own success or failure
  is captured as `DLP_OBSERVATION:` secondary evidence only, exactly like
  SFTP's local exit code — never the graded truth. A `Send-MailMessage`
  failure (connection refused, timeout, whatever) is not distinguished
  from "sent cleanly but a mail gateway silently dropped it before it
  reached the sink" — both resolve to `Blocked`, matching the same
  reasoning SFTP's design settled on for its own local-failure cases.
- **Server: `github.com/emersion/go-smtp` for the real SMTP protocol
  (EHLO/MAIL FROM/RCPT TO/DATA), not a hand-rolled implementation.** Same
  "don't hand-roll wire protocol" lesson DNS established with
  `github.com/miekg/dns` and SFTP established with `github.com/pkg/sftp`
  — this listener accepts binary, agent-influenced input on an open port,
  and SMTP's line-based-but-stateful protocol (command sequencing, DATA
  terminator handling) has real hazards a hand-rolled parser is likely to
  get subtly wrong.
- **No AUTH required or advertised.** Same philosophy as SFTP's
  `NoClientAuth` and the HTTP sink's "garbage POST proves nothing" stance
  — the point is testing content/protocol inspection, not access control.
  `MAIL FROM`/`RCPT TO` accept any address without validation
  (open-relay-style for this synthetic-traffic-only listener). No
  credential generation or distribution needed anywhere in this design.
- **Token placement: the `Subject` header is the sole correlation key;
  the body carries a duplicate for DLP content-scanning realism but is
  never used for matching.** Unlike SFTP's filename-based correlation
  (no filename concept exists for an email), the token has to live
  somewhere in the message itself. Subject was chosen over a custom
  `X-`header because subject-line content is exactly what mail-security/DLP
  products actually scan, keeping the test meaningful — a header most
  inspection engines never look at would be a weaker test. Duplicating the
  token into the body gives content-inspection engines a second realistic
  place to catch it, but correlation is deterministic and single-sourced:
  if `Subject` doesn't exact-match a known token, the message is not
  correlated to any run, full stop — never falling back to scanning the
  body for a token, which would create a second, weaker correlation path
  and muddy the contract.
- **`{{SINK_TOKEN}}` reused directly — no new token byte-length variant.**
  Same reasoning as SFTP: no DNS-style length constraint exists for an
  email Subject header, so the existing 32-byte/64-hex-char token from
  the HTTP channel's path is reused unchanged.
- **`MAIL FROM`/`RCPT TO` use a fixed, synthetic literal address — not a
  placeholder.** `dlptest@sink.audspect.local` for both, baked directly
  into the scenario's PowerShell text, matching SFTP's fixed literal
  `dlptest@` username and DNS's fixed `dnssink.audspect.local` domain
  suffix: not a secret, not per-run-unique, no substitution needed. The
  domain is a naming convention only, never a real delegated/deliverable
  mail domain — this listener is the only thing that ever sees a message
  addressed there.

## Design

### 1. Deployment

New package `internal/smtpsink`, mirroring `internal/sftpsink`'s
isolation from the HTTP sink and every other channel — its own listener
lifecycle, independently enable/disable-able (`SMTP_SINK_ENABLED`,
default `true`). `cmd/server/main.go` starts its listener goroutine
alongside the HTTPS server, DNS listener, and SFTP listener:

```go
if cfg.SMTPSinkEnabled {
    smtpsink.StartListener(context.Background(), ":587", pool)
} else {
    log.Println("[smtpsink] disabled via SMTP_SINK_ENABLED=false")
}
```

`docker-compose.yml` adds `"${SINK_SMTP_PORT:-587}:587/tcp"` to the
`ports:` block — no `NET_BIND_SERVICE` capability needed for this one,
since 587 is an unprivileged port (unlike 53 and 22, which the container
already has the capability for regardless).

### 2. Token generation and placeholder substitution

No new `generateSinkToken` call shape — `issueSinkTokensAndSubstitute`
(`internal/api/dlp_sink.go`) gains a fourth placeholder branch, structured
exactly like the SFTP block it sits beside: triggered independently by
`{{SINK_SMTP_HOST}}`/`{{SINK_SMTP_PORT}}` presence, substituting only the
two placeholders it's uniquely responsible for, relying on the
already-unconditional `{{SINK_TOKEN}}` block (present earlier in the same
function) to issue and substitute the token itself whenever a step's
command contains it — which every real SMTP-wired step's command does,
as the `Subject` value. This mirrors the exact correction made to SFTP's
own placeholder-substitution code during implementation (the original
SFTP draft mistakenly re-issued its own token; the corrected, shipped
version does not), applied here from the start rather than repeated as a
second bug:

```go
if strings.Contains(steps[i].Command, "{{SINK_SMTP_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_SMTP_PORT}}") {
    steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SMTP_HOST}}", smtpSinkHost(publicBaseURL))
    steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SMTP_PORT}}", smtpSinkPort())
}
```

`smtpSinkHost`/`smtpSinkPort` mirror `sftpSinkHost`/`sftpSinkPort`
exactly: an optional `SINK_SMTP_HOST` environment override (for
deployments where the externally reachable address differs from
`publicBaseURL`'s host, e.g. behind NAT), otherwise the same
`dnsServerHost()` derivation every channel's host placeholder already
uses; `SINK_SMTP_PORT` resolves the configured value, defaulting to
`587`.

### 3. SMTP server and receipt persistence

`smtpsink.StartListener` opens a `go-smtp` server bound to `:587` with a
custom `Backend`/`Session` implementation:

- **`Mail`/`Rcpt`**: accept any address unconditionally — no validation,
  matching the "content inspection, not access control" philosophy above.
- **`Data`**: reads the message body up to a fixed size ceiling (`64KB`,
  matching SFTP's `MaxUploadBytes` for consistency across channels;
  rejects/truncates anything larger before it can grow an unbounded
  buffer), parses it with the standard library's `net/mail.ReadMessage`
  (sufficient for a simple single-part plain-text message — no MIME
  multipart/attachment handling needed for V1, since `Send-MailMessage`'s
  default output is exactly that shape), and extracts the `Subject`
  header.
- **Token match**: exact-match the extracted `Subject` against
  `dlp_sink_tokens`. On match: hash the full message body (SHA-256, the
  same "hash only, never the raw content" rule every prior channel
  follows), write one `dlp_sink_receipts` row (`channel='smtp'`) — same
  insert shape `internal/sftpsink`'s `sessionWriter.Close()` and the HTTP
  sink's `DLPSink` handler both already use. On no match: the message is
  simply not correlated to anything; the SMTP transaction still completes
  cleanly (`250 OK`) so a malformed or unrelated message never produces a
  scary-looking failure for whatever sent it — matching DNS's "every
  valid query gets a clean response" precedent, applied here to "every
  well-formed message gets accepted," not to file-write-shape validation
  the way SFTP's filename check works (there's no equivalent "reject the
  transaction outright" case for SMTP, since a real DLP/mail-security
  product intercepting the message is exactly what should look like a
  transaction that completed but the payload never reached the sink).

Because `dlp_sink_receipts` and its consumers
(`internal/verifysync.annotateSinkReceipts`,
`internal/reporting.dlpVerifier`) already only check "does at least one
receipt exist for this token," **no further changes are needed to either
of those** — the sink-primary verdict logic applies to this channel
automatically once the listener writes into the same table, exactly as
established for DNS and SFTP.

### 4. Security hardening

Same bar as every prior channel, adapted for an SMTP/TCP listener:

- Bounded per-message byte ceiling (`64KB`) — reject/abort a `DATA`
  stream once it exceeds this before it can grow an unbounded buffer.
- Bounded total in-memory session state across all concurrent
  connections.
- Idle-session timeout on a connection that opens but never completes a
  transaction within a bounded window.
- A coarse per-source-IP rate limit, matching SFTP's/DNS's identical
  per-source-IP guards (same duplicated-not-shared `rateLimiter` type
  shape, since it stays unexported in each sibling package).
- Reject any message with more than one `RCPT TO` recipient, or any
  multipart/attachment-bearing message — this listener has no legitimate
  use for either; a single plain-text part addressed to exactly one
  recipient is the only shape it needs to understand.
- Logging never includes message content — only the token (once matched),
  size, and hash, consistent with every prior channel's "never log the
  sensitive payload" principle.

### 5. V1 scenario content

New scenario `scenarios/dlp-exfiltration-smtp.yaml`, one step, technique
**T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol**, confirmed
against this repo's own bundled ATT&CK enrichment data
(`orchestrator/internal/reporting/attackdata/attack_enrichment.json`) —
its own description explicitly lists unencrypted protocols like this as
the exact pattern this technique covers. PowerShell:

1. Writes the same synthetic `[BAS-SIM-DLP]` multi-type record
   (PAN/Aadhaar/SWIFT/UPI/credit-card) every prior channel uses, as the
   message body.
2. Calls `Send-MailMessage` directly — no tool-presence check needed —
   with `-Subject "{{SINK_TOKEN}}"`, `-Body` containing the same token
   plus the synthetic record, `-To`/`-From` set to the fixed
   `dlptest@sink.audspect.local` literal, `-SmtpServer {{SINK_SMTP_HOST}}`,
   `-Port {{SINK_SMTP_PORT}}`.
3. Captures the command's own success/failure (`$?`, `$Error[0]`) as
   `DLP_OBSERVATION:` secondary evidence only — never the graded verdict,
   per the Decisions section above.

Tagged `[BAS-SIM-DLP-SMTP]`. New detection-profile entry
(`dlp-smtp-block`) added to
`scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, following
the same `outcome_family: dlp`, `expected_outcome: Block` shape every
existing entry already uses.

## Testing

- Go unit tests in `internal/smtpsink`: `Subject` extraction from a
  parsed message, correct `dlp_sink_receipts` row written only on a
  matched token, correct no-op (still `250 OK`, no receipt) on an
  unmatched token, correct rejection of each security-hardening case
  (oversized message, more than one recipient, multipart/attachment
  content).
- `internal/api/dlp_sink_test.go`: the new
  `{{SINK_SMTP_HOST}}`/`{{SINK_SMTP_PORT}}` placeholder substitution,
  confirming the existing 32-byte token path is reused unchanged, and a
  dedicated regression test proving exactly one `dlp_sink_tokens` row
  exists per run+technique (the same orphaned-second-token class of bug
  caught and fixed during SFTP's implementation, guarded against here
  from the start).
- Regression confirmation: full `internal/verifysync` and
  `internal/reporting` suites re-run to prove neither needs any change.
- An integration-style test: dispatch a step, send a real SMTP message to
  a listener instance bound to an ephemeral port (not 587, to keep tests
  runnable without any port-availability assumptions), confirm a
  `dlp_sink_receipts` row lands with the correct hash/size, and confirm
  `dlpVerifier` resolves `Succeeded` from it exactly as it would for
  HTTPS/DNS/SFTP.

## Out of scope

- STARTTLS / SMTPS (encrypted submission) — V1 is plaintext SMTP only,
  matching T1048.003's own "unencrypted" framing; an encrypted variant
  would be a different technique (T1048.002-adjacent, already covered by
  SFTP) and a separate future sub-project if ever prioritized.
- AUTH LOGIN/PLAIN support — deliberately unauthenticated throughout, per
  the Decisions section.
- Multipart MIME / file attachments — a single plain-text part is
  sufficient for V1; attachment-based exfiltration is a distinct test
  from what this channel validates (message-body/subject content
  inspection) and is explicitly rejected, not silently accepted, by the
  security-hardening rules above.
- ICMP tunneling, cloud storage APIs, webhook-style channels, telnet,
  removable device — next in priority order per the user's own roadmap,
  each its own sub-project.
- A dashboard/UI surface for the SMTP listener's health status — the
  status is queryable server-side (a future `Status()`-consuming view
  could be added later), matching every prior channel's precedent.
