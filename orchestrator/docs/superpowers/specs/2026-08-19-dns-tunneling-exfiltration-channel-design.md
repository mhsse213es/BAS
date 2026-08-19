# DNS Tunneling Exfiltration Channel — Design

## Problem

Second sub-project of the DLP exfiltration maturity program, following the
sink-verified HTTPS channel (`docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md`).
That channel proved the sink-verification architecture — a per-attempt
token, a destination-side receipt, a sink-primary verdict — but it and any
other webhook-style channel (Slack, Teams, GitHub, GitLab) all resolve to
the same underlying test: *does DLP/proxy content inspection catch a
regulated-data pattern in an outbound HTTP(S) POST body?* Adding more
webhook-shaped channels would inflate scenario count without adding new
detection coverage.

DNS tunneling is a genuinely different exfiltration technique — data
encoded into DNS query labels rather than an HTTP body — and tests whether
network-layer controls (DLP, IDS/IPS, DNS security products) catch
protocol-based exfiltration regardless of payload content-inspection
capability. This is the highest-priority remaining channel because it adds
new *protocol* coverage, not just new *scenario* count. Distinct
non-HTTP channels (SFTP, SMTP, ICMP tunneling) are prioritized to follow
this one, in that order, for the same reason; cloud storage APIs and
webhook-style channels (Slack/Teams/GitHub/GitLab) are deferred further —
the former requires its own architectural decision about mimicking
real vendor upload-API shapes, the latter mostly duplicates the existing
HTTPS channel's test in V1's on-prem-only model.

## Decisions

Confirmed during brainstorming:

- **Bind real port 53/UDP, not a non-standard port.** A network-layer
  inspector that filters by port would never see traffic on a
  non-standard port like 5353 — that would defeat the purpose of testing
  protocol-based detection. The orchestrator container gets
  `cap_add: [NET_BIND_SERVICE]` in `docker-compose.yml` rather than
  running as root. The listener must attempt the bind, fail loudly and
  visibly (never silently fall back to another port) if UDP/53 is already
  owned by something else, and expose its own health status
  independently of the rest of the orchestrator.
- **Use `github.com/miekg/dns` for wire parsing, not a hand-rolled
  parser.** This listener accepts binary, attacker/agent-influenced input
  on an open, unauthenticated UDP port — DNS wire format has real parsing
  hazards (compression pointers, malformed label lengths) that a
  hand-rolled parser is likely to get subtly wrong in ways that matter for
  a network-facing listener. `miekg/dns` is the mature, widely-used Go DNS
  library (CoreDNS, Consul, etc.). Scope is deliberately narrow: use it
  only for `dns.Msg.Unpack()`/response serialization, never as a
  recursive resolver or general-purpose DNS server.
- **Architecturally separate from the existing HTTP sink**
  (`internal/api/dlp_sink.go`), even though both currently run inside the
  same orchestrator process. New package `internal/dnssink` with its own
  listener lifecycle, independently enable/disable-able
  (`DNS_SINK_ENABLED` env var, default on). This keeps the door open for
  SFTP/SMTP/ICMP listeners later without turning the HTTP sink into a
  protocol-specific monolith.
- **Reuse the existing `dlp_sink_tokens`/`dlp_sink_receipts` schema and
  verification path unchanged.** No new tables. The only schema-adjacent
  change is generalizing `generateSinkToken()` to accept a byte-length
  parameter — 32 bytes (current behavior) for HTTP-style channels, 8
  bytes (16 hex chars, 64 bits of entropy) for DNS, short enough to sit in
  a single 63-character DNS label. Because `internal/verifysync`'s
  `annotateSinkReceipts` and `internal/reporting`'s `dlpVerifier` already
  key purely on "was any receipt recorded for this token," neither
  requires any change for this channel — the existing V1 architecture
  extends to a structurally different transport with zero changes to the
  verification path itself.
- **Full reassembly required for a `Succeeded` verdict; anything less
  resolves `Blocked`.** No new "partial" outcome state — consistent with
  the existing binary succeeded/blocked model `dlpVerifier` already uses.
  A partial chunk set that never completes before the reassembly timeout
  is treated the same as zero chunks received: DLP is credited with
  having prevented full exfiltration.
- **Every query gets a `NOERROR` response with a fixed, harmless A
  record — never `NXDOMAIN`.** The agent's `nslookup`-based script should
  complete cleanly on every call with no retries or error-looking output;
  this also matches how real DNS-tunneling tools behave, keeping the
  channel functioning smoothly end-to-end.
- **Security hardening is part of V1, not a follow-up.** Because this
  listener is unauthenticated and open to the network by necessity (same
  rationale as the HTTP sink — testing whether content/protocol
  inspection catches the traffic, not testing access control), it ships
  from the start with: max UDP packet size, max QNAME/label length, max
  labels processed, rejection of malformed packets and any non-A/AAAA
  query type, a per-campaign reassembly byte/chunk-count ceiling, a
  reassembly timeout (reusing the existing 10-minute `sinkTokenTTL`),
  bounded total in-memory reassembly state with eviction of expired
  campaigns, a coarse per-source-IP rate limit, and QNAMEs are never
  logged in full — only the campaign ID and sequence number, never the
  encoded data itself.

## Design

### 1. Deployment

New package `internal/dnssink`. `cmd/server/main.go` starts its listener
goroutine alongside the existing HTTP server, gated by `DNS_SINK_ENABLED`
(default `true`). `docker-compose.yml` adds:

```yaml
cap_add:
  - NET_BIND_SERVICE
ports:
  - "53:53/udp"
```

On startup, the listener attempts `net.ListenUDP("udp", &net.UDPAddr{Port:
53})`. On failure (port already owned), it logs the failure clearly,
records a `FAILED` status with the reason, and returns — the rest of the
orchestrator (HTTP API, existing HTTP sink) starts and runs normally
regardless. A small exported status struct (e.g. `dnssink.Status() (state
string, reason string)`) makes this queryable; no dashboard surface is
required for V1 (matches the existing HTTPS channel's "no frontend
changes needed" precedent — a future dashboard view can read this without
today's plumbing needing to also ship a view for it).

### 2. Token generation

`generateSinkToken` (`internal/api/dlp_sink.go`) changes from a
zero-argument function to `generateSinkToken(n int) (string, error)`,
generating `n` random bytes via `crypto/rand` and hex-encoding them. The
existing HTTP-sink call site becomes `generateSinkToken(32)` (unchanged
behavior, unchanged token length). A new call
`generateSinkToken(8)` produces a 16-hex-character campaign ID for DNS —
short enough to fit in a single DNS label with room to spare, still
unguessable within the 10-minute TTL window. Both call sites persist to
the same `dlp_sink_tokens` table via the same insert path; only the byte
length differs.

### 3. Placeholder substitution

`issueSinkTokensAndSubstitute` (`internal/api/dlp_sink.go`) gains
awareness of a second placeholder set. A step whose command contains
`{{SINK_DNS_CAMPAIGN_ID}}` triggers the 8-byte token path instead of the
existing 32-byte one, and the following placeholders are substituted:

- `{{SINK_DNS_CAMPAIGN_ID}}` — the 16-hex-char token, persisted to
  `dlp_sink_tokens` exactly as the HTTP channel's token is today.
- `{{SINK_DNS_SERVER}}` — the orchestrator's own IP address (not
  hostname — `nslookup <query> <server>` takes a server IP directly,
  avoiding any dependency on the customer's internal DNS routing, the
  same "explicit target" principle already used for `{{SINK_URL}}`).
  Derived from the same source `{{SINK_URL}}` already uses today
  (`h.publicBaseURL`'s host component), not a new config value.
- `{{SINK_DNS_DOMAIN}}` — a fixed label suffix, e.g.
  `dnssink.audspect.local`. This is a naming convention only, never a
  real delegated DNS zone — the query never goes through recursive
  resolution, it targets `{{SINK_DNS_SERVER}}` directly.

A step may use either placeholder set, never both — `dispatchRun`'s
existing single substitution call handles both cases via `strings.Contains`
checks, unchanged in shape from the current HTTP-only implementation.

### 4. Wire protocol

Query shape: `<seq>.<base32-chunk>.<campaign-id>.<dns-domain>`. Each
dot-separated component is its own DNS label (independently bounded at 63
characters), matching the diagram from brainstorming.

- **Encoding:** Base32 (not base64 — DNS labels are case-insensitive),
  applied to the same synthetic `[BAS-SIM-DLP]` multi-type record
  (PAN/Aadhaar/SWIFT/UPI/credit-card) the HTTPS channel already uses.
- **`seq = 000`** is a reserved header record. Its "chunk" field encodes
  the total chunk count (base32) rather than payload data — this tells
  the listener when it has everything, rather than inferring completion
  from a timeout or from parsing terminator content out of a data chunk.
- **`seq = 001..NNN`** carry the actual base32-encoded data chunks, in
  order.
- The agent script issues one `nslookup <query> {{SINK_DNS_SERVER}}` per
  record (header first, then each data chunk in sequence) — matching the
  existing `nslookup`-based precedent already used in
  `apt29-kill-chain.yaml`/`apt36-kill-chain.yaml` for DNS beaconing, so no
  new agent-side primitive is introduced (dumb-executor principle
  preserved: the agent runs plain PowerShell text built entirely
  server-side).

### 5. Reassembly and verification

The listener buffers received chunks per campaign ID in memory. On
receiving the `000` header record, it learns the expected total chunk
count for that campaign; once all `1..total` chunks have arrived, it
concatenates them in sequence order, base32-decodes the result, computes
a SHA-256 hash (mirroring the HTTP sink's "never store the raw payload"
rule exactly), and writes one row to `dlp_sink_receipts`
(`token=<campaign-id>`, `channel='dns-tunnel'`, `payload_hash=<hash>`,
`payload_size=<decoded length>`, `source_ip=<UDP source>`) — using the
same insert shape `DLPSink` already uses today, just triggered from the
DNS listener instead of the HTTP handler.

Because `dlp_sink_receipts` and its consumers
(`internal/verifysync.annotateSinkReceipts`,
`internal/reporting.dlpVerifier`) already only check "does at least one
receipt exist for this token," **no changes are needed to either of
those** — the existing sink-primary verdict logic (`Succeeded` if a
receipt landed, `Blocked` if the token expired with none) applies to this
channel automatically, once the DNS listener writes into the same table.
A reassembly that's still incomplete when the campaign's TTL (reusing the
existing `sinkTokenTTL`, 10 minutes) expires is simply never written —
resolving `Blocked`, matching the "anything less than full reassembly is
treated as prevented" decision above. Per-campaign buffered state is
evicted at the same TTL boundary regardless of completion, bounding
memory use.

### 6. Response semantics

Every valid query — header or data chunk — receives a `NOERROR` response
carrying a fixed, non-sensitive A record (e.g. `192.0.2.1`, a TEST-NET-1
documentation address, never a real routable IP). This is deliberate:
`NXDOMAIN` is a valid *DNS* outcome but reads as an *error* to
`nslookup`'s own output and exit-code handling, which would make the
agent script's per-query success/failure logic ambiguous. A clean,
consistent `NOERROR` response lets every query in the sequence complete
without triggering retries, and matches how real DNS-tunneling C2 tooling
behaves (keeping the channel indistinguishable from ordinary DNS traffic
at the transport level — the point being tested is whether *content/
protocol* inspection catches it, not whether the wire-level exchange looks
broken).

### 7. Security hardening

Enforced inside `internal/dnssink`, checked before any reassembly logic
runs:

- Reject any UDP packet exceeding a fixed maximum size (DNS-over-UDP is
  bounded well below 65535 in practice; a generous but firm ceiling, e.g.
  512–4096 bytes, rejects clearly-malformed or abusive packets outright).
- Reject any QNAME exceeding the standard 253-byte total / 63-byte
  per-label DNS limits (this is largely enforced by `miekg/dns` itself
  during unpack, but re-validated explicitly before this listener's own
  logic touches the parsed labels).
- Reject any query whose label count exceeds what the `seq.chunk.
  campaign-id.domain` shape requires (4 labels plus however many the
  fixed domain suffix contributes) — anything with more labels than that
  is not a shape this listener needs to understand and is dropped.
- Only `A`-type queries are treated as tunneling records — the agent's
  `nslookup` calls never need to issue anything else. Any other query
  type (`AAAA`, `TXT`, `MX`, etc.) still gets the same fixed `NOERROR`
  response with no answer section, but is never parsed as a tunneling
  record.
- Per-campaign reassembly state is capped (max chunk count, max total
  reassembled bytes) — a header record declaring an implausibly large
  total chunk count is rejected rather than allocating unbounded buffer
  space.
- Total in-memory reassembly state across all campaigns is bounded; the
  oldest/expired campaigns are evicted first when a ceiling is reached.
- A coarse per-source-IP rate limit bounds how many queries per second
  a single source can send to the listener.
- Logging never includes a full QNAME or the encoded chunk data — only
  the campaign ID and sequence number, consistent with the existing sink
  endpoint's "never store the raw payload" principle extended to the logs
  themselves.

### 8. V1 scenario content

New scenario `scenarios/dlp-exfiltration-dns-tunnel.yaml`, one step,
technique T1048.003 (Exfiltration Over Unencrypted/Obfuscated
Non-C2 Protocol) or T1071.004 (Application Layer Protocol: DNS) — exact
technique ID confirmed at plan-writing time against MITRE ATT&CK's current
naming, mirroring the existing `apt29-kill-chain.yaml`/
`apt36-kill-chain.yaml` DNS-beacon steps' technique choice for
consistency. PowerShell builds the header + data-chunk queries and issues
one `nslookup` call per record against `{{SINK_DNS_SERVER}}`, tagged
`[BAS-SIM-DLP-DNS-TUNNEL]`. A new detection-profile entry
(`dlp-dns-tunnel-block`) is added to
`scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, following
the same `outcome_family: dlp`, `expected_outcome: Block` shape as the
existing five entries plus the HTTPS channel's entry.

## Testing

- Go unit tests in `internal/dnssink`: wire-format parsing of a
  synthetic header + chunk sequence via `miekg/dns`, correct reassembly
  and base32 decoding, correct `dlp_sink_receipts` row written only on
  full reassembly, correct rejection of each security-hardening case
  (oversized packet, over-length QNAME, wrong query type, oversized
  declared chunk count, rate-limit trip), correct `NOERROR`+fixed-A-record
  response shape for every valid query.
- `generateSinkToken(n int)` test confirming both the existing 32-byte
  and new 8-byte call sites still produce unique, unpredictable values,
  and that the 8-byte case fits within a single DNS label's 63-character
  limit once base32-encoded alongside sequence/campaign-id components.
- Regression confirmation that `internal/verifysync` and
  `internal/reporting`'s existing DLP verification tests are unaffected
  — no code changes are needed there, but the full suite is re-run to
  prove it.
- An integration-style test: drive a full header+chunks UDP exchange
  against a real listener instance bound to an ephemeral port (not 53, to
  keep tests runnable without elevated privileges), confirm a
  `dlp_sink_receipts` row lands with the correct hash/size, and confirm
  `dlpVerifier` resolves `Succeeded` from it exactly as it would for the
  HTTP channel.

## Out of scope

- TCP/53 fallback (DNS tunneling tools sometimes fall back to TCP for
  larger transfers) — UDP-only for this sub-project.
- SFTP, SMTP/E-mail, and ICMP tunneling listeners — next in priority
  order per the user's own roadmap, each its own sub-project.
- Cloud storage APIs (S3/Azure Blob/Google Storage/OneDrive/Google
  Drive/Dropbox) and webhook-style channels (Slack/Teams/GitHub/GitLab) —
  deferred; the former needs its own design decision about mimicking real
  vendor upload-API shapes, the latter mostly duplicates the existing
  HTTPS channel's test value in the on-prem-only V1 model.
- Any real DNS zone delegation or recursive resolution — this listener is
  a direct-IP-target endpoint only, exactly like the existing HTTPS sink.
- A dashboard/UI surface for the DNS listener's health status — the
  status is queryable server-side (`dnssink.Status()`) for a future view
  to consume, but no frontend work ships in this sub-project.
