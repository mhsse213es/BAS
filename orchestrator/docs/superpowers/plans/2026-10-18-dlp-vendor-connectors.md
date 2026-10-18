# DLP Mastery Priority 5: Microsoft Purview + Trellix DLP connector clients

## Locked scope (user decision)

Build both vendor connector clients now, even without live tenant/API access to either vendor. Research real API shapes via the internet rather than guessing. Build request-building/response-mapping proven against `httptest`, exactly as this codebase's own established precedent for the same situation (`docs/emailgw-mastery-qa-log.md` item 1b: `AnalyzedEmailEvidenceProvider` built and proven against `httptest` before Defender-for-O365 tenant access existed). Log live-tenant verification as deferred in a new `docs/dlp-mastery-qa-log.md`, following the exact convention of `docs/{av,emailgw,waf,webgw}-mastery-qa-log.md`.

## Research findings (grounded via WebSearch, cited)

**Microsoft Purview DLP** — evidence lives in the **Office 365 Management Activity API**, content type `DLP.All` ([O365 Management Activity API reference](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference)). Auth: Entra ID OAuth2 client-credentials (2-legged, Application permissions, admin consent required), scope `https://manage.office.com/.default`, permissions `ActivityFeed.Read` + `ActivityFeed.ReadDlp` for DLP-specific event detail. Flow: list/start a content subscription for `DLP.All`, poll `activity/feed/subscriptions/content` for available content blobs in a time window, fetch each blob's `contentUri` for the actual DLP audit records. Prerequisite: Unified Audit Logging must be enabled tenant-side (can't be verified via API error alone — documented, not detected). Known limitation: only server-side time filtering; IP/hostname/user filtering is client-side.

**Trellix DLP** — incidents surfaced via a regional **Events API v2** (`https://arevents.manage.trellix.com/eventservice/api/v2/events?type=incidents`, with separate US/Singapore/Frankfurt/Sydney/India hosts — [Response codes](https://docs.trellix.com/v1/docs/events-api-response-codes)). Auth: Trellix IAM client-credentials grant, JWT with license-scoped `scope` claims, Basic-auth-style credential submission ([Managing client credentials](https://docs-dr.trellix.com/network-and-platform/docs/managing-client-credentials)) — **not** the Entra flow, so this needs its own small token-fetch function, not `msauth.EntraTokenSource`. Research surfaced a genuine, unresolved version/domain conflict across Trellix's own docs (`iam.cloud.trellix.com/iam/v1.0/token` vs. legacy `iam.mcafee-cloud.com/iam/v1.1/token`) — this is flagged honestly in the code (overridable defaults, doc comment), not silently picked as if certain.

## Design — follow the established `internal/vendors/defender` pattern exactly

Both new packages mirror `defender.Config`/`defender.Client`/`defender.New`: a `Config` struct, a `Client` with exported, test-overridable `BaseURL`/`TokenURL` fields (so `httptest.Server` substitution works exactly like `defender`'s own tests), one primary `Query...` method, explicit `HTTP 401/403` branches naming the exact missing permission (mirroring `SendMail`'s `"is Mail.Send application permission granted with admin consent for %s?"` precedent), and a `TestConnection` smoke-test method.

**Not in scope:** flipping `trellix_dlp`/`microsoft_purview` in `internal/scenario/providers.go` from `VerificationManual` — `microsoft_sentinel` already has a real, tested client (`internal/detectverify`) and *stays* `VerificationManual`, because `apiVerifier` (the `VerificationAPI` dispatch target) is still an unconditional `StatusPending` stub for every domain, not just DLP (`detection_validation.go:200-206`). Flipping the catalog entry here would be misleading, not a real capability gain — building generic SP3 automatic-API-verification wiring is separate, larger, cross-domain work, not part of this connector-client slice.

### `orchestrator/internal/vendors/purview/client.go`

```go
type Config struct { TenantID, ClientID, ClientSecret string }
type Client struct {
    BaseURL string // defaults to https://manage.office.com/api/v1.0/{tenantId}, overridable for tests
    tokens  *msauth.EntraTokenSource // scope https://manage.office.com/.default, reused exactly like defender/detectverify
    httpClient *http.Client
}
func New(cfg Config) *Client
func (c *Client) EnsureSubscriptionStarted(ctx context.Context) error // idempotent start of the DLP.All content subscription; "already enabled" treated as success, not an error
func (c *Client) QueryDLPEvents(ctx context.Context, start, end time.Time) ([]DLPEvent, error) // list content blobs in [start,end], fetch each, flatten+normalize
```

`DLPEvent` fields drawn from Microsoft's published DLP audit schema: `Workload`, `Operation`, `CreationTime`, `UserID`, `ObjectID`, `PolicyName`, `RuleName`, `Actions []string` (e.g. `BlockAccess`, `NotifyUser`), `RawJSON json.RawMessage` (same "keep the raw record" precedent as `defender.Alert.RawJSON`).

### `orchestrator/internal/vendors/trellixdlp/client.go`

```go
type Config struct { ClientID, ClientSecret string }
type Client struct {
    TokenURL     string // defaults to https://iam.cloud.trellix.com/iam/v1.0/token -- UNVERIFIED default, see doc comment on the conflicting legacy/regional alternatives
    EventsURL    string // defaults to the US events host; other regions require an explicit override
    httpClient   *http.Client
    // local token cache/fetch -- NOT msauth.EntraTokenSource (different grant mechanics)
}
func New(cfg Config) *Client
func (c *Client) QueryDLPIncidents(ctx context.Context, start, end time.Time) ([]Incident, error)
```

`Incident` fields are a best-effort, conservative shape (`ID`, `Timestamp`, `Severity`, `PolicyName`, `Action`, `Status`, `RawJSON`) with a prominent doc comment: **field names are not confirmed against Trellix's official DLP incident schema** (research found the general Events API shape but not a published DLP-incident-specific field reference) — must be validated against the real API once credentials exist, exactly like `QueryMailAlerts`' own "provisional correlation heuristic... unverified" precedent in `defender/client.go:165-174`.

## Tests

Both packages: `httptest`-backed, mirroring `defender/client_test.go`'s `tokenMock`/`newTestClient` pattern exactly —
- Successful query returns normalized events/incidents.
- HTTP 401/403 from the vendor returns a descriptive error naming the specific missing permission/license (`ActivityFeed.ReadDlp` for Purview; the relevant Trellix scope for Trellix).
- Empty result window returns an empty slice, not an error.
- `TestConnection` smoke test.
- Purview-specific: `EnsureSubscriptionStarted` treats an "already enabled" vendor error as success, not a failure.

## QA log

New `docs/dlp-mastery-qa-log.md`, same structure as `docs/emailgw-mastery-qa-log.md`: one open item per vendor, stating exactly what's blocked (no live Purview-licensed tenant / Graph admin consent; no Trellix DLP license/API credentials), what's already resolved (the API shape research above, with citations), and what remains unverified until real access exists (exact Trellix response field names; Purview subscription-already-started error text; rate limits/pagination for both).

## Review focus for final review

- Confirm both clients compile and are fully exercised by `httptest`-backed tests — no live network call anywhere in the test suite.
- Confirm neither client is wired into `internal/scenario/providers.go`'s `Verifier` field, `apiVerifier`, or `internal/reporting/dlp.go` — this slice is the connector clients only, consumption wiring is separate future work.
- Confirm every genuinely unverified fact (Trellix response schema, exact Purview "already subscribed" error text, which Trellix docs domain/version is current) is flagged in a doc comment and in the QA log, not asserted as fact.
- Confirm the Purview client reuses `msauth.EntraTokenSource` (not a new parallel Entra auth implementation) and the Trellix client's own token fetch is justified (different, non-Entra grant mechanics), not an unnecessary duplicate abstraction.
