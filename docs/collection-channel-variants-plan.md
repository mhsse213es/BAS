# Exfiltration Channel Variants Probe: validation expansion plan

Status: PLAN ONLY. No scenario change until the decisions in section 6 are approved.
Current file: scenarios/collection-channel-variants-exfil.yaml (4 steps, signed, on main, commit 831f7e3b).

## 1. Defects in the current scenario

1. **Real network operations toward .invalid.** Channel 1 opens a TCP connection (SSH port) and channel 2 opens one toward SMB port 445. Channels 3 and 4 send an HTTP POST with a body. The spec forbids arbitrary outbound connections and any transmission of data. Being unable to resolve `.invalid` does not make these safe to keep.
2. **Channel 3 sends data.** A "C2-shaped beacon carrying data" transmits a body. The spec allows synthetic beacon metadata only.
3. **Channel 4 uploads.** A cloud-storage upload attempt sends a body. The spec forbids real file uploads and any transmission of data.
4. **Failure is treated as a result.** Each step decides its verdict from whether the connection or POST failed. A failed attempt is not a block. The same false-FAIL / DNS-as-control pattern was fixed in the clipboard probe (Stage 3, commit ea363cb4 and 5bc71e22).
5. **No event correlation.** No step queries firewall, proxy, DNS or DLP telemetry, so no step can report a correlated block or a detection.
6. **No freshness check.** Nothing checks whether a telemetry source is current, so stale evidence cannot be caught.
7. **No prevention / detection separation.** A verdict does not say which control acted, or whether any did.

## 2. Verdict model (from the spec, adopted as written)

| Evidence | Result |
|---|---|
| Policy configured, enforcement unverified | CONFIGURED (never scores) |
| Actual correlated block event | PASS |
| Actual successful unauthorized transfer | FAIL |
| No integration configured | NOT_CONFIGURED |
| Integration available, no usable or fresh evidence | UNVERIFIED |
| Query or execution error | ERROR |

Prevention and detection are reported on separate lines. A DNS result is RESOLUTION_ONLY and is never a verdict on any channel.

## 3. Proposed tests (24)

| Area | Tests | Action in the probe | Evidence source |
|---|---|---|---|
| SFTP / SSH (4) | Resolve SSH destination; SSH egress policy read; firewall/proxy correlation for the resolver probe; synthetic transfer detection | Resolver-only; read-only firewall rule read; adapter queries | Firewall rule config; egress/DNS logs; EDR |
| SMB outbound (4) | Resolve SMB destination; TCP 445 outbound rule read; firewall block correlation; SMB client telemetry availability | Resolver-only; read-only rule read; event log presence check | Windows Firewall rules; SMBClient log; egress logs |
| C2-style HTTPS (5) | Synthetic beacon metadata (run id only, no body); HTTPS egress policy read; proxy detection; DLP event correlation; periodicity pattern check | Resolver-only; read-only config; adapter queries; periodicity check moved to a Go test (decision 6.2) | Proxy logs; DLP events |
| Cloud storage (4) | Destination classification against a fixed local list (no connection); upload policy configuration read; DLP policy evaluation; proxy/firewall enforcement evidence | Local classification only; read-only config; adapter queries | Proxy logs; DLP policy |
| Egress firewall and proxy (4) | Outbound default-deny state read; proxy enforcement evidence; firewall block evidence for the probe run id; policy drift check | Read-only config; adapter queries | Firewall and proxy logs |
| DLP and telemetry correlation (3) | DLP detection of the synthetic pattern; telemetry source availability; event freshness against the threshold | Adapter queries; event log presence; timestamps | DLP events; event log channels |

Total: 24.

Correlation key: every resolver name and beacon field carries the run id (`bas-sim-<channel>-<runId>.invalid`), so firewall, proxy and DNS queries can match the probe's own events and nothing else.

## 4. Changes to the four existing channels

- **Channel 1 (SFTP/SSH):** remove the TCP connection. Replace with a resolver probe plus the SSH egress policy read and correlation tests.
- **Channel 2 (SMB):** remove the TCP 445 connection. Replace with a resolver probe plus the TCP 445 rule read and correlation tests.
- **Channel 3 (C2-shaped beacon):** remove the POST body. Keep a resolver probe and synthetic beacon metadata containing only the run id and a fixed string. Periodicity analysis moves to Go tests (decision 6.2).
- **Channel 4 (cloud upload):** remove the POST. Keep local destination classification and the policy and enforcement tests.

Each channel's FAIL verdict is removed unless a correlated successful transfer event exists, which by design never happens in this probe. A channel with no correlated block event returns UNVERIFIED or NOT_CONFIGURED, never PASS.

## 5. Safety rules

1. No file is read, uploaded or copied.
2. No credential or token is sent or read.
3. No connection is opened to any host. Resolution is the only network action, and only for `.invalid` names carrying the run id.
4. No real C2 infrastructure is used. Beacon metadata is synthetic and contains no payload.
5. Read-only configuration queries only: no firewall, proxy or policy is changed.
6. Integrations are opt-in adapters, as in the clipboard probe. A configured integration reports UNVERIFIED until an operational probe exists.
7. Telemetry freshness: evidence older than the threshold is UNVERIFIED, never PASS.

## 6. Decisions for you

1. **Remove all connections and POSTs first.** Approve a fix commit that removes the TCP connects and POSTs and reports SKIP/UNVERIFIED instead of FAIL, as done for Stage 3 (recommended, before the expansion).
2. **Periodicity detection.** Move the periodic-pattern test to a Go unit test against recorded telemetry fixtures (recommended), or drop it from the scenario? A scenario step cannot evaluate Audspect's own detector.
3. **Read-only firewall queries.** Allow `Get-NetFirewallRule` and proxy configuration reads as CONFIGURED evidence only (recommended), as in the clipboard probe?
4. **Freshness threshold.** Use 15 minutes for telemetry freshness (recommended), or another value?
5. **Correlation key.** Confirm the run-id-in-name scheme: `bas-sim-<channel>-<runId>.invalid` (recommended).
6. **Integrations.** Reuse the clipboard probe's adapters (Defender, Purview, Trellix, egress) rather than adding new ones (recommended).
7. **Fix order.** Approve decision 6.1 as its own commit before the expansion, like the clipboard fix.

## 7. Status

No YAML edits, no signature change, no tests written. This plan is uncommitted. Approve section 6 and the work follows the same order as sections 3 and 4.
