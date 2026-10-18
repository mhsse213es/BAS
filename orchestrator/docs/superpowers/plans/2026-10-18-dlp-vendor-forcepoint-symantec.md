# Forcepoint DLP + Symantec DLP Vendor Connectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build 2 new standalone vendor evidence-client packages, `internal/vendors/forcepointdlp` and `internal/vendors/symantecdlp`, closing the remaining 2 of `dlp.txt` §5's 4 named enterprise DLP products (Purview and Trellix already exist).

**Architecture:** Each package is a self-contained HTTP client (`Config`/`Client`/`New`/auth exchange/`QueryDLPIncidents`/`TestConnection`), following `internal/vendors/trellixdlp`'s exact file shape and disclaimer style. Each vendor's auth mechanics are genuinely different (Forcepoint: 2-step refresh-token→access-token exchange; Symantec: forms-based username/password login) so neither reuses another package's token code.

**Tech Stack:** Go stdlib (`net/http`, `encoding/json`, `net/url`) only — no new dependencies, matching `purview`/`trellixdlp`.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-vendor-forcepoint-symantec-design.md`.

## Global Constraints

- Every exported type/function doc comment that makes a factual claim about the vendor's real API must match the spec's Research section exactly — no claim beyond what was actually confirmed by research.
- Both packages' `Config` struct fields and `New` defaults must be overridable in tests (same `TokenURL`/`EventsURL`-style public fields `trellixdlp.Client` exposes) — no hardcoded unexported URL that a test cannot redirect to an `httptest.Server`.
- `QueryDLPIncidents` must return an empty slice, never an error, when the vendor's own response contains zero incidents (matching `trellixdlp`'s `TestQueryDLPIncidents_EmptyEvents_ReturnsEmptyNotError` contract) — a correctly-authenticated call that finds nothing is success, not failure.
- A permission-denied response (HTTP 401/403) must produce an error whose message names the likely cause (license/role/scope), matching `trellixdlp`'s `TestQueryDLPIncidents_PermissionDenied_NamesTheMissingScope` contract — never a bare "HTTP 403" with no guidance.
- Package doc comments must explicitly flag unverified claims per the spec's Research section, mirroring `trellixdlp/client.go`'s own doc comment structure (what's confirmed, what's not, pointer to `docs/dlp-mastery-qa-log.md`).

## Review Focus

- Forcepoint's 2-step token exchange (refresh-token endpoint, then access-token endpoint) must genuinely chain both calls in the right order — a test that only mocks one of the two endpoints and asserts success would miss a bug where the second exchange is skipped or the first token is used directly as the access token.
- Forcepoint's incident request must send a filters-mode body, never an ID-list body, for `QueryDLPIncidents` — and must declare exactly one of `INCIDENTS`/`DISCOVERY` as the incident type (never both, never neither) since the real API returns only one type per call.
- Symantec's forms-login must send credentials as form fields (username/password), not JSON and not HTTP Basic auth — confusing this with Purview's or Trellix's own auth style would silently produce a client that fails against every real Symantec deployment while still passing a test that assumes the wrong format.
- A login/token failure (the auth step itself returning non-2xx) must prevent the incidents call from ever firing, for BOTH vendors — matching `trellixdlp`'s `TestQueryDLPIncidents_TokenFetchFails_ReturnsError` contract (the events mock handler asserts it is never called). This matters doubly for Symantec given the documented account-lockout risk after repeated failed logins — a client that retries or double-fires login on an already-failed attempt would make that lockout risk worse, not just redundant.
- Both `Incident` structs' exported field names must stay internally consistent with their own package's query *filter* vocabulary named in the spec's Research section (Forcepoint: policy/department/riskLevel; Symantec: status/severity/incidentType) — a mismatch between what you can filter by and what the struct returns would silently make a caller's own filter choice unobservable in the result.

---

### Task 1: Forcepoint DLP client

**Files:**
- Create: `orchestrator/internal/vendors/forcepointdlp/client.go`
- Test: `orchestrator/internal/vendors/forcepointdlp/client_test.go`

**Interfaces:**
- Consumes: nothing new (stdlib only).
- Produces: `forcepointdlp.Config{BaseURL, Username, Password}`, `forcepointdlp.Client`, `forcepointdlp.New(cfg Config) *Client`, `(*Client).QueryDLPIncidents(ctx, start, end time.Time) ([]Incident, error)`, `(*Client).TestConnection(ctx) error` — consumed by nothing else in this plan (standalone, matching Purview/Trellix's own current non-wired state).

**Package doc comment** (top of `client.go`, adapt verbatim from the spec's Research section — confirmed: 2-step refresh/access token exchange against `/dlp/rest/v1/auth/refresh-token` and `/dlp/rest/v1/auth/access-token`, incidents via `POST /dlp/rest/v1/incidents` with a filters-mode body, max 10,000/response, one of `INCIDENTS`/`DISCOVERY` per call; NOT confirmed: incident response field names, token caching lifetime, exact date-filter parameter name):

```go
// Package forcepointdlp is a Forcepoint DLP incident evidence client.
//
// UNVERIFIED against a live tenant -- see docs/dlp-mastery-qa-log.md.
// Research (WebSearch, 2026-10-18; see
// docs/superpowers/plans/2026-10-18-dlp-vendor-forcepoint-symantec.md for
// citations) confirmed the auth flow (a 2-step refresh-token then
// access-token exchange against /dlp/rest/v1/auth/{refresh-token,
// access-token}, requiring a local Application-type administrator
// account) and the incidents endpoint shape (POST /dlp/rest/v1/incidents,
// filters-mode request body, max 10,000 rows per response, exactly one of
// INCIDENTS or DISCOVERY per call). It did NOT confirm the exact JSON
// field names in an incident response record, the token's cache lifetime,
// or the exact date-range filter parameter name -- the request/response
// shapes below are this package's best-effort implementation of the
// documented general pattern, flagged here so nobody mistakes "builds and
// passes httptest" for "proven against the real API." Same lab-gated
// posture as internal/vendors/trellixdlp.
package forcepointdlp
```

**Config/Client shape** (mirror `trellixdlp.Config`/`Client` exactly, renamed for Forcepoint's own fields):

```go
type Config struct {
	BaseURL  string // DLP Manager host:port, e.g. "https://dlpmgr.example.com:9443"
	Username string
	Password string
}

type Client struct {
	RefreshTokenURL string // overridable for tests; default BaseURL + "/dlp/rest/v1/auth/refresh-token"
	AccessTokenURL  string // overridable for tests; default BaseURL + "/dlp/rest/v1/auth/access-token"
	IncidentsURL    string // overridable for tests; default BaseURL + "/dlp/rest/v1/incidents"
	httpClient      *http.Client

	username, password string
	mu                  sync.Mutex
	cachedAccessToken   string
	tokenExpiresAt      time.Time // best-effort: no confirmed lifetime, cache for a conservative fixed duration (see Step 3 note)
}
```

- [ ] **Step 1: Write the failing tests**

```go
package forcepointdlp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func refreshTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "admin" || body["password"] != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_credentials"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"refreshToken": "rtok"})
	}))
}

func accessTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["refreshToken"] != "rtok" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_refresh_token"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"accessToken": "atok"})
	}))
}

func newTestClient(t *testing.T, refreshURL, accessURL, incidentsURL string) *Client {
	t.Helper()
	c := New(Config{Username: "admin", Password: "pw"})
	c.RefreshTokenURL = refreshURL
	c.AccessTokenURL = accessURL
	c.IncidentsURL = incidentsURL
	return c
}

func TestQueryDLPIncidents_ChainsRefreshThenAccessToken(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()

	ts := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if _, hasIDs := req["ids"]; hasIDs {
			t.Error("request must be filters-mode, must not include an ids list")
		}
		if req["type"] != "INCIDENTS" {
			t.Errorf("type = %v, want INCIDENTS", req["type"])
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer atok" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer atok")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"incidents": []map[string]any{
				{"id": "fp-1", "timestamp": ts.Format(time.RFC3339), "policy": "BFSI Credit Card Policy", "severity": "high", "action": "block", "status": "open"},
			},
		})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), ts.Add(-time.Hour), ts.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 1 || incidents[0].ID != "fp-1" || incidents[0].Policy != "BFSI Credit Card Policy" {
		t.Errorf("incidents = %+v, want 1 incident id=fp-1 policy=\"BFSI Credit Card Policy\"", incidents)
	}
}

func TestQueryDLPIncidents_EmptyIncidents_ReturnsEmptyNotError(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 0 {
		t.Fatalf("incidents = %+v, want empty", incidents)
	}
}

func TestQueryDLPIncidents_PermissionDenied_NamesTheMissingScope(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "license") && !strings.Contains(err.Error(), "role") && !strings.Contains(err.Error(), "Application") {
		t.Errorf("error = %q, want it to mention the likely cause (license/role/Application account type)", err.Error())
	}
}

func TestQueryDLPIncidents_RefreshTokenFails_NeverCallsAccessTokenOrIncidents(t *testing.T) {
	refreshSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_credentials"}`))
	}))
	defer refreshSrv.Close()
	accessSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("access-token endpoint must never be called when the refresh-token step itself failed")
	}))
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("incidents endpoint must never be called when the refresh-token step itself failed")
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error when the refresh-token endpoint rejects the credentials, got nil")
	}
}

func TestTestConnection_Success(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessSrv := accessTokenMock(t)
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: %v", err)
	}
}

func TestQueryDLPIncidents_CachesAccessToken_DoesNotRefetchPerCall(t *testing.T) {
	refreshSrv := refreshTokenMock(t)
	defer refreshSrv.Close()
	accessCalls := 0
	accessSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessCalls++
		json.NewEncoder(w).Encode(map[string]string{"accessToken": "atok"})
	}))
	defer accessSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, refreshSrv.URL, accessSrv.URL, incidentsSrv.URL)
	for i := 0; i < 3; i++ {
		if _, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now()); err != nil {
			t.Fatalf("QueryDLPIncidents call %d: %v", i, err)
		}
	}
	if accessCalls != 1 {
		t.Errorf("access-token endpoint called %d times, want exactly 1 (cached)", accessCalls)
	}
}
```

(add `"strings"` to the imports for the permission-denied test's `strings.Contains` calls)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/vendors/forcepointdlp/... -v`
Expected: FAIL (package does not exist yet — build failure)

- [ ] **Step 3: Implement**

`client.go` per the package doc comment and Config/Client shape above, plus:
- `New(cfg Config) *Client`: sets `RefreshTokenURL`/`AccessTokenURL`/`IncidentsURL` defaults from `cfg.BaseURL + "/dlp/rest/v1/auth/refresh-token"` etc. (empty `BaseURL` is fine — tests always override all 3 URLs directly, matching `trellixdlp.newTestClient`'s pattern).
- `refreshToken(ctx)`: POST `{"username":..., "password":...}` as JSON to `RefreshTokenURL`, parse `{"refreshToken": "..."}`.
- `accessToken(ctx)`: cache-checked (mutex-guarded, same shape as `trellixdlp.token`); on miss, calls `refreshToken` then POSTs `{"refreshToken": "..."}` as JSON to `AccessTokenURL`, parses `{"accessToken": "..."}`. Cache for a conservative fixed duration since no lifetime is confirmed — use 15 minutes (`time.Now().Add(15 * time.Minute)`), documented inline as a best-effort default, not a confirmed token lifetime.
- `Incident` struct: `ID, Timestamp time.Time, Policy, Department, RiskLevel, Severity, Action, Status string, RawJSON json.RawMessage` (Department/RiskLevel included for field-vocabulary consistency with the spec's Review Focus item on filter/field alignment, even though the test fixtures above don't populate them — parse them when present, leave zero-value when absent).
- `QueryDLPIncidents(ctx, start, end)`: get access token; POST a filters-mode body `{"type": "INCIDENTS", "filters": {"dateRange": {"start": ..., "end": ...}}}` (RFC3339 timestamps) to `IncidentsURL` with `Authorization: Bearer <token>`; on 401/403 return an error naming "license/role/Application-type account" as the likely cause; parse `{"incidents": [...]}`, map each into `Incident` (missing/malformed fields → zero value, never a parse failure for the whole batch, matching `trellixdlp.parseIncident`'s per-record tolerance — but for this plan's own tests, include only fields the fixtures provide to keep Step 4 passing without extra unexercised logic).
- `TestConnection(ctx)`: calls `QueryDLPIncidents` with a 1-hour window, returns its error.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/vendors/forcepointdlp/... -v`
Expected: PASS (all 6 tests)

- [ ] **Step 5: `gofmt -l`, `go vet`**

Run: `gofmt -l orchestrator/internal/vendors/forcepointdlp/` and `go vet github.com/audspect/bas/internal/vendors/forcepointdlp/...`
Expected: no output from either (verify any `gofmt -l` hit with a CRLF-stripped diff before concluding it's real)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/vendors/forcepointdlp/
git commit -m "feat(dlp-vendors): add Forcepoint DLP incident evidence client"
```

---

### Task 2: Symantec DLP client

**Files:**
- Create: `orchestrator/internal/vendors/symantecdlp/client.go`
- Test: `orchestrator/internal/vendors/symantecdlp/client_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `symantecdlp.Config{BaseURL, Username, Password}`, `symantecdlp.Client`, `symantecdlp.New(cfg Config) *Client`, `(*Client).QueryDLPIncidents(ctx, start, end time.Time) ([]Incident, error)`, `(*Client).TestConnection(ctx) error` — standalone, consumed by nothing else in this plan.

**Package doc comment** (adapt verbatim from the spec's Research section — confirmed: forms-based username/password login, not OAuth; filterable by earliest-time/status/severity/incidentType; default page size 50; account lockout risk after repeated failed logins (default max 6 attempts / 60-minute lockout); NOT confirmed: exact login endpoint path, session-token/cookie mechanics, exact incident-list endpoint and field names, which of 2 API generations — 15.7 REST vs. 16+ Incident Reporting — a given license maps to):

```go
// Package symantecdlp is a Symantec (Broadcom) DLP incident evidence
// client.
//
// UNVERIFIED against a live tenant -- see docs/dlp-mastery-qa-log.md.
// Research (WebSearch, 2026-10-18; see
// docs/superpowers/plans/2026-10-18-dlp-vendor-forcepoint-symantec.md for
// citations) confirmed Symantec DLP's REST-adjacent integrations use
// forms-based username/password authentication against the Enforce
// server -- not OAuth -- and that incidents are filterable by earliest
// time, status, severity and incident type with a default page size of
// 50. It also confirmed a real operational risk: the service account can
// lock after repeated failed logins (documented default: 6 attempts, 60
// minute lockout) -- this client must never retry a login after a
// rejected attempt. It did NOT confirm the exact login endpoint path,
// the session-token/cookie mechanics after a successful login, the exact
// incident-list endpoint path or response field names, or which of
// Symantec's two documented API generations (the 15.7+ REST API vs. the
// 16+ "Incident Reporting and Update API") a given license maps to. The
// request/response shapes below are this package's best-effort
// implementation of the documented general pattern -- same lab-gated
// posture as internal/vendors/trellixdlp.
package symantecdlp
```

**Config/Client shape:**

```go
type Config struct {
	BaseURL  string // Enforce server host:port, e.g. "https://enforce.example.com"
	Username string
	Password string
}

type Client struct {
	LoginURL     string // overridable for tests; default BaseURL + "/ProtectManager/webservices/v2/authenticate"
	IncidentsURL string // overridable for tests; default BaseURL + "/ProtectManager/webservices/v2/incidents"
	httpClient   *http.Client

	username, password string
	mu                  sync.Mutex
	cachedSessionToken  string
	sessionExpiresAt    time.Time // best-effort: no confirmed lifetime, see Step 3 note
}
```

- [ ] **Step 1: Write the failing tests**

```go
package symantecdlp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func loginMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Errorf("Content-Type = %q, want form-urlencoded (forms-based auth, not JSON/OAuth)", ct)
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("username") != "svcacct" || form.Get("password") != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_credentials"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"sessionToken": "sess-1"})
	}))
}

func newTestClient(t *testing.T, loginURL, incidentsURL string) *Client {
	t.Helper()
	c := New(Config{Username: "svcacct", Password: "pw"})
	c.LoginURL = loginURL
	c.IncidentsURL = incidentsURL
	return c
}

func TestQueryDLPIncidents_LogsInWithFormsAuth_NotJSONOrBasic(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()

	ts := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization header = %q, want empty (session carried another way, not Bearer/Basic)", auth)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"incidents": []map[string]any{
				{"incidentId": "sym-1", "detectionDate": ts.Format(time.RFC3339), "status": "new", "severity": "high", "incidentType": "Network"},
			},
		})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), ts.Add(-time.Hour), ts.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 1 || incidents[0].ID != "sym-1" || incidents[0].IncidentType != "Network" {
		t.Errorf("incidents = %+v, want 1 incident id=sym-1 incidentType=Network", incidents)
	}
}

func TestQueryDLPIncidents_EmptyIncidents_ReturnsEmptyNotError(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	incidents, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("QueryDLPIncidents: %v", err)
	}
	if len(incidents) != 0 {
		t.Fatalf("incidents = %+v, want empty", incidents)
	}
}

func TestQueryDLPIncidents_PermissionDenied_NamesTheMissingScope(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "license") && !strings.Contains(err.Error(), "role") && !strings.Contains(err.Error(), "permission") {
		t.Errorf("error = %q, want it to mention the likely cause (license/role/permission)", err.Error())
	}
}

func TestQueryDLPIncidents_LoginFails_NeverCallsIncidentsOrRetries(t *testing.T) {
	loginAttempts := 0
	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginAttempts++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_credentials"}`))
	}))
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("incidents endpoint must never be called when login itself failed")
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	_, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error when login rejects the credentials, got nil")
	}
	if loginAttempts != 1 {
		t.Errorf("login attempted %d times, want exactly 1 -- must never retry a rejected login (account lockout risk)", loginAttempts)
	}
}

func TestTestConnection_Success(t *testing.T) {
	loginSrv := loginMock(t)
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: %v", err)
	}
}

func TestQueryDLPIncidents_CachesSession_DoesNotReloginPerCall(t *testing.T) {
	loginCalls := 0
	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginCalls++
		json.NewEncoder(w).Encode(map[string]string{"sessionToken": "sess-1"})
	}))
	defer loginSrv.Close()
	incidentsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"incidents": []map[string]any{}})
	}))
	defer incidentsSrv.Close()

	c := newTestClient(t, loginSrv.URL, incidentsSrv.URL)
	for i := 0; i < 3; i++ {
		if _, err := c.QueryDLPIncidents(context.Background(), time.Now().Add(-time.Hour), time.Now()); err != nil {
			t.Fatalf("QueryDLPIncidents call %d: %v", i, err)
		}
	}
	if loginCalls != 1 {
		t.Errorf("login endpoint called %d times, want exactly 1 (cached session)", loginCalls)
	}
}
```

(add `"io"` to the imports for `loginMock`'s body read)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/vendors/symantecdlp/... -v`
Expected: FAIL (package does not exist yet — build failure)

- [ ] **Step 3: Implement**

`client.go` per the package doc comment and Config/Client shape above, plus:
- `New(cfg Config) *Client`: sets `LoginURL`/`IncidentsURL` defaults from `cfg.BaseURL + "/ProtectManager/webservices/v2/authenticate"` / `.../incidents` (tests override both directly).
- `login(ctx)`: cache-checked (mutex-guarded). On miss, POST `url.Values{"username": ..., "password": ...}.Encode()` with `Content-Type: application/x-www-form-urlencoded` to `LoginURL` (never JSON, never `SetBasicAuth` — this is the Review Focus item distinguishing Symantec's auth from every other vendor in this family). On non-2xx, return the error immediately and never retry within the same call (the account-lockout risk named in the doc comment — `login` is called exactly once per `QueryDLPIncidents` invocation when the cache is cold, with no internal retry loop at all). Parse `{"sessionToken": "..."}`. Cache for a conservative fixed duration (15 minutes, same best-effort-default reasoning as Forcepoint's).
- `Incident` struct: `ID, DetectionDate time.Time, Status, Severity, IncidentType string, RawJSON json.RawMessage` (field names `ID`/`DetectionDate`/`Status`/`Severity`/`IncidentType` chosen to mirror the confirmed filter vocabulary — time/status/severity/incidentType — per the spec's Review Focus item).
- `QueryDLPIncidents(ctx, start, end)`: get session token (never send `Authorization` header — session carried via whatever cookie/query mechanism `net/http.Client`'s own cookie jar would normally handle in a real deployment; for this best-effort client, append the session token as a query parameter `?sessionToken=...` on the incidents request, documented inline as a best-effort guess since the exact mechanics are unconfirmed); GET `IncidentsURL` with query params `earliestTime`/`status`/`severity`/`incidentType` as applicable (start/end become `earliestTime`/`latestTime` in RFC3339); on 401/403 return an error naming "license/role/permission" as the likely cause; parse `{"incidents": [...]}`, map each record's `incidentId`→`ID`, `detectionDate`→`DetectionDate`, `status`→`Status`, `severity`→`Severity`, `incidentType`→`IncidentType`.
- `TestConnection(ctx)`: calls `QueryDLPIncidents` with a 1-hour window, returns its error.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/vendors/symantecdlp/... -v`
Expected: PASS (all 6 tests)

- [ ] **Step 5: `gofmt -l`, `go vet`, full module build**

Run: `gofmt -l orchestrator/internal/vendors/symantecdlp/`, `go vet github.com/audspect/bas/internal/vendors/symantecdlp/...`, `go build github.com/audspect/bas/...`
Expected: no output from the first two, clean build from the third

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/vendors/symantecdlp/
git commit -m "feat(dlp-vendors): add Symantec DLP incident evidence client"
```

---

### Task 3: QA log entries

**Files:**
- Modify: `docs/dlp-mastery-qa-log.md`

**Interfaces:**
- Consumes: Task 1 and Task 2's package doc comments (summarize, don't duplicate verbatim).
- Produces: nothing consumed elsewhere.

- [ ] **Step 1: Add item 4 (Forcepoint) and item 5 (Symantec) to the Open items section**, matching items 1/2's structure (Status / What's needed / What's still unverified / What this means / Resolution path) — content drawn directly from the spec's Research section and this plan's Task 1/2 package doc comments. No test for a documentation-only change.
- [ ] **Step 2: Commit**

```bash
git add docs/dlp-mastery-qa-log.md
git commit -m "docs(dlp-vendors): log Forcepoint/Symantec DLP unverified-schema gaps"
```

---

## Self-Review Notes

- **Spec coverage:** Goal 1 → Task 1. Goal 2 → Task 2. Goal 3 (doc-comment disclaimers) → both tasks' Step 1 package doc comments. Goal 4 (QA log entries) → Task 3.
- **Step scan:** auth-mechanics prose (2-step exchange vs. forms-login) is described, not transcribed into full code, since the test fixtures above already pin the exact request/response shape each implementation must match.
- **Type consistency:** both `Incident` structs' field names were cross-checked against each package's own test fixtures above (`Policy`/`Department`/`RiskLevel` for Forcepoint matching its filter vocabulary; `Status`/`Severity`/`IncidentType` for Symantec matching its filter vocabulary) — no drift between Task 1/2's Interfaces block and their Step 3 implementation notes.
- **Review Focus:** all 5 items have a named test above (Forcepoint 2-step chaining, Forcepoint filters-mode + single-type body, Symantec forms-not-JSON/Basic auth, both vendors' login-failure-blocks-incidents-call with Symantec's explicit no-retry assertion, both `Incident` structs' field-vocabulary alignment).
- **Proportion check:** 3 tasks (2 code + 1 doc), each sized like `trellixdlp` itself (~200 lines + ~170 lines of tests) — proportionate to adding 2 of the same kind of package already built twice in this initiative.
- **Anti-goal check:** neither package imports `internal/platform/msauth` or copies another vendor package's token code verbatim — each owns its own auth exchange, matching the spec's stated reason (4 genuinely different auth mechanisms across Purview/Trellix/Forcepoint/Symantec).
