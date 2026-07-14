# Detection Verification Connectors (SP1 first slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically verify off-host detections against Microsoft Sentinel and Microsoft Defender XDR after a run completes, replacing the manual analyst-attestation step for those two vendors.

**Architecture:** A new, self-contained `internal/detectverify` package holds pure connector logic (Entra OAuth, Sentinel KQL query, Defender XDR Graph query, host+window+technique matching, and per-run orchestration) with zero database access. `internal/api` owns all persistence: a new `detection_connectors` config table, CRUD handlers, an on-demand trigger endpoint, and fire-and-forget goroutines wired into `SubmitScenarioResult` (mirroring the existing `AutoCorrelateSIEM` pattern exactly). Results land in the already-shipped `verification.Store` with `Source=api`; the reporting engine needs no changes at all.

**Tech Stack:** Go, pgx/pgxpool, chi router, `net/http`/`httptest` (no new dependencies).

## Global Constraints

- Follow the design spec exactly: `docs/superpowers/specs/2026-07-14-detection-verification-connectors-design.md`.
- `internal/siem` is not modified by this plan — this is a deliberate, separate package (see spec "Architecture").
- Every container-backed test (anything using `sharedDB.RunWithPool`) must start with `if testing.Short() { t.Skip(...) }`.
- A connector error must never produce a false `NotDetected` attestation — on error, write nothing (see spec "Error Handling").
- `Verdict=Detected` → `Attest(Result=Detected, WorkflowState=Approved)`. `Verdict=NotDetected` → `Attest(Result=NotDetected, WorkflowState=NeedsReview)`.
- Run `gofmt -l`, `go build ./...`, and `go vet ./...` before every commit in this plan; run the full validation chain (gofmt, build, vet, staticcheck, full test suite) in the final task before pushing.
- Git push immediately after every commit (existing project convention).

---

### Task 1: Core types and pure matching logic

**Files:**
- Create: `orchestrator/internal/detectverify/connector.go`
- Create: `orchestrator/internal/detectverify/match.go`
- Test: `orchestrator/internal/detectverify/match_test.go`

**Interfaces:**
- Produces: `Config` struct (`ID, Name, Provider, Enabled, AutoVerify, TenantID, ClientID, ClientSecret, WorkspaceID, VerifyDelaySeconds`); `VerifyRequest` (`RunID, ExpectationID, TechniqueID, HostName, HostIP, StepExecutedAt, WindowStart, WindowEnd`); `MatchedAlert` (`AlertID, RuleName, Timestamp, Severity, RawJSON`); `VerifyResult` (`Verdict, Confidence, MatchedAlerts, DetectionLatency, InvestigationURL`); `Connector` interface (`Verify(ctx, VerifyRequest) (VerifyResult, error)`, `TestConnection(ctx) error`); constants `VerdictDetected`, `VerdictNotDetected`, `ConfidenceHigh`, `ConfidenceMedium`; `normalizedAlert` struct and `matchAlerts(req VerifyRequest, alerts []normalizedAlert) VerifyResult` (package-private, used by later connector tasks).

- [ ] **Step 1: Create the package directory and write `connector.go`**

```go
// orchestrator/internal/detectverify/connector.go

// Package detectverify queries Microsoft Sentinel and Microsoft Defender XDR
// for whether they detected a run's executed techniques, then writes the
// verdict into the Verification Store (internal/verification) with
// Source=api. It is deliberately independent of internal/siem — see
// docs/superpowers/specs/2026-07-14-detection-verification-connectors-design.md
// for why the two packages are not merged.
//
// This package does no database I/O. internal/api owns the
// detection_connectors config table and calls VerifyRun (orchestrate.go)
// with everything it needs already loaded.
package detectverify

import (
	"context"
	"encoding/json"
	"time"
)

// Verdicts a connector can return for one expectation.
const (
	VerdictDetected    = "Detected"
	VerdictNotDetected = "NotDetected"
)

// Confidence levels matchAlerts assigns to a Detected verdict.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
)

// Config holds the connection settings for one detection connector —
// persisted in detection_connectors, loaded by internal/api and passed to
// NewConnector (added in Task 5).
type Config struct {
	ID                 string
	Name               string
	Provider           string // "microsoft_sentinel" | "microsoft_defender"
	Enabled            bool
	AutoVerify         bool
	TenantID           string
	ClientID           string
	ClientSecret       string
	WorkspaceID        string // Sentinel only; empty for Defender XDR
	VerifyDelaySeconds int
}

// VerifyRequest is one expectation to check against a provider, scoped to a
// single host and time window.
type VerifyRequest struct {
	RunID          string
	ExpectationID  string
	TechniqueID    string
	HostName       string
	HostIP         string
	StepExecutedAt time.Time // the step's actual execution time — used for latency
	WindowStart    time.Time // padded query window start
	WindowEnd      time.Time // padded query window end
}

// MatchedAlert is one vendor alert that satisfied a VerifyRequest.
type MatchedAlert struct {
	AlertID   string          `json:"alertId"`
	RuleName  string          `json:"ruleName"`
	Timestamp time.Time       `json:"timestamp"`
	Severity  string          `json:"severity"`
	RawJSON   json.RawMessage `json:"raw,omitempty"`
}

// VerifyResult is the outcome of checking one expectation against a provider.
type VerifyResult struct {
	Verdict          string // Detected | NotDetected
	Confidence       string // high | medium ("" when NotDetected)
	MatchedAlerts    []MatchedAlert
	DetectionLatency time.Duration // 0 when NotDetected
	InvestigationURL string
}

// Connector is one vendor's detection-verification API client.
type Connector interface {
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
	TestConnection(ctx context.Context) error
}
```

- [ ] **Step 2: Write `match.go`**

```go
// orchestrator/internal/detectverify/match.go
package detectverify

import (
	"encoding/json"
	"strings"
	"time"
)

// normalizedAlert is the vendor-agnostic shape a connector reduces its raw
// query response into before matchAlerts decides a verdict. Each connector
// (sentinel.go, defenderxdr.go) does its own parsing but produces this.
type normalizedAlert struct {
	AlertID          string
	RuleName         string
	Timestamp        time.Time
	Severity         string
	Techniques       []string // ATT&CK technique IDs tagged on the alert, if any
	InvestigationURL string
	RawJSON          json.RawMessage
}

// matchAlerts decides Detected/NotDetected and confidence from the alerts a
// connector already scoped to the request's host + time window (that scoping
// happens in the connector's query itself — this function only judges
// technique-tag confidence and picks the earliest matching alert).
//
// High confidence: the earliest alert tagged with the requested technique.
// Medium confidence: no alert carries a technique tag (older/custom rules
// often don't), so the earliest alert of any kind is used instead.
func matchAlerts(req VerifyRequest, alerts []normalizedAlert) VerifyResult {
	if len(alerts) == 0 {
		return VerifyResult{Verdict: VerdictNotDetected}
	}

	var best *normalizedAlert
	confidence := ConfidenceHigh
	for i := range alerts {
		a := &alerts[i]
		if !containsTechnique(a.Techniques, req.TechniqueID) {
			continue
		}
		if best == nil || a.Timestamp.Before(best.Timestamp) {
			best = a
		}
	}
	if best == nil {
		confidence = ConfidenceMedium
		for i := range alerts {
			a := &alerts[i]
			if best == nil || a.Timestamp.Before(best.Timestamp) {
				best = a
			}
		}
	}

	matched := make([]MatchedAlert, 0, len(alerts))
	for _, a := range alerts {
		matched = append(matched, MatchedAlert{
			AlertID: a.AlertID, RuleName: a.RuleName, Timestamp: a.Timestamp,
			Severity: a.Severity, RawJSON: a.RawJSON,
		})
	}

	return VerifyResult{
		Verdict:          VerdictDetected,
		Confidence:       confidence,
		MatchedAlerts:    matched,
		DetectionLatency: best.Timestamp.Sub(req.StepExecutedAt),
		InvestigationURL: best.InvestigationURL,
	}
}

func containsTechnique(techniques []string, want string) bool {
	if want == "" {
		return false
	}
	for _, t := range techniques {
		if strings.EqualFold(strings.TrimSpace(t), want) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Write `match_test.go`**

```go
// orchestrator/internal/detectverify/match_test.go
package detectverify

import (
	"testing"
	"time"
)

func TestMatchAlerts_NoAlerts_NotDetected(t *testing.T) {
	result := matchAlerts(VerifyRequest{TechniqueID: "T1059.001"}, nil)
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want %q", result.Verdict, VerdictNotDetected)
	}
	if len(result.MatchedAlerts) != 0 {
		t.Fatalf("MatchedAlerts = %+v, want none", result.MatchedAlerts)
	}
}

func TestMatchAlerts_TechniqueTaggedAlert_HighConfidence(t *testing.T) {
	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(90 * time.Second)
	req := VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: stepTime}
	alerts := []normalizedAlert{
		{AlertID: "a1", Timestamp: alertTime, Techniques: []string{"T1059.001"}, InvestigationURL: "https://example/a1"},
	}

	result := matchAlerts(req, alerts)
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if result.DetectionLatency != 90*time.Second {
		t.Fatalf("DetectionLatency = %v, want 90s", result.DetectionLatency)
	}
	if result.InvestigationURL != "https://example/a1" {
		t.Fatalf("InvestigationURL = %q", result.InvestigationURL)
	}
}

func TestMatchAlerts_UntaggedAlert_MediumConfidence(t *testing.T) {
	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	req := VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: stepTime}
	alerts := []normalizedAlert{
		{AlertID: "a1", Timestamp: stepTime.Add(time.Minute)}, // no Techniques tag
	}

	result := matchAlerts(req, alerts)
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceMedium {
		t.Fatalf("result = %+v, want Detected/medium", result)
	}
}

func TestMatchAlerts_PrefersEarliestTechniqueTaggedAlert(t *testing.T) {
	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	req := VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: stepTime}
	alerts := []normalizedAlert{
		{AlertID: "later", Timestamp: stepTime.Add(3 * time.Minute), Techniques: []string{"T1059.001"}},
		{AlertID: "earlier", Timestamp: stepTime.Add(1 * time.Minute), Techniques: []string{"T1059.001"}},
		{AlertID: "untagged", Timestamp: stepTime.Add(10 * time.Second)}, // earliest overall, but untagged
	}

	result := matchAlerts(req, alerts)
	if result.DetectionLatency != time.Minute {
		t.Fatalf("DetectionLatency = %v, want 1m (from the earliest TAGGED alert, not the earliest overall)", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 3 {
		t.Fatalf("MatchedAlerts = %d, want all 3 alerts recorded", len(result.MatchedAlerts))
	}
}

func TestContainsTechnique_CaseInsensitiveAndTrimmed(t *testing.T) {
	if !containsTechnique([]string{" t1059.001 "}, "T1059.001") {
		t.Fatal("expected a case-insensitive, whitespace-tolerant match")
	}
	if containsTechnique([]string{"T1055"}, "T1059.001") {
		t.Fatal("expected no match for a different technique")
	}
	if containsTechnique(nil, "") {
		t.Fatal("expected no match when the wanted technique is empty")
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `cd orchestrator && go test ./internal/detectverify/... -run TestMatchAlerts -v` and `go test ./internal/detectverify/... -run TestContainsTechnique -v`
Expected: all PASS (this task has no dependency on any I/O, so nothing should fail once the code compiles).

- [ ] **Step 5: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/detectverify
go build ./...
go vet ./internal/detectverify/...
git add internal/detectverify/connector.go internal/detectverify/match.go internal/detectverify/match_test.go
git commit -m "feat(detectverify): add core types and host/window/technique matching logic"
git push
```

---

### Task 2: Entra ID (Azure AD) client-credentials token source

**Files:**
- Create: `orchestrator/internal/detectverify/entra_auth.go`
- Test: `orchestrator/internal/detectverify/entra_auth_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `newEntraTokenSource(tenantID, clientID, clientSecret, scope string) *entraTokenSource`; method `(*entraTokenSource) Token(ctx context.Context) (string, error)`; field `tokenURL` (unexported, overridable by same-package tests). Both the Sentinel and Defender XDR connectors (Tasks 3–4) construct one of these each.

- [ ] **Step 1: Write `entra_auth.go`**

```go
// orchestrator/internal/detectverify/entra_auth.go
package detectverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// entraTokenSource fetches and caches an Entra ID (Azure AD) OAuth2
// client-credentials token for one (tenant, client, scope) triple. Both the
// Sentinel and Defender XDR connectors use this — they differ only in scope
// (api.loganalytics.io vs graph.microsoft.com).
type entraTokenSource struct {
	tenantID, clientID, clientSecret, scope string
	tokenURL                                string // overridable in tests; defaults to login.microsoftonline.com
	httpClient                              *http.Client

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func newEntraTokenSource(tenantID, clientID, clientSecret, scope string) *entraTokenSource {
	return &entraTokenSource{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:        scope,
		tokenURL:     "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/token",
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Token returns a cached token when it has more than 60s left, else fetches
// a fresh one via the client-credentials grant.
func (e *entraTokenSource) Token(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cached != "" && time.Now().Before(e.expiresAt) {
		return e.cached, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {e.clientID},
		"client_secret": {e.clientSecret},
		"scope":         {e.scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("entra token: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("entra token: HTTP %d: %s", resp.StatusCode, data)
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("entra token: unexpected response: %s", data)
	}

	e.cached = out.AccessToken
	e.expiresAt = time.Now().Add(time.Duration(out.ExpiresIn-60) * time.Second)
	return e.cached, nil
}
```

- [ ] **Step 2: Write `entra_auth_test.go`**

```go
// orchestrator/internal/detectverify/entra_auth_test.go
package detectverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEntraTokenSource_FetchesAndCaches(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", r.FormValue("grant_type"))
		}
		if r.FormValue("scope") != "https://api.loganalytics.io/.default" {
			t.Errorf("scope = %q", r.FormValue("scope"))
		}
		w.Write([]byte(`{"access_token":"tok-1","expires_in":3600}`))
	}))
	defer srv.Close()

	ts := newEntraTokenSource("tenant-1", "client-1", "secret-1", "https://api.loganalytics.io/.default")
	ts.tokenURL = srv.URL

	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("token = %q, want tok-1", tok)
	}

	tok2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok2 != "tok-1" {
		t.Fatalf("cached token = %q, want tok-1", tok2)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (the second Token() call should reuse the cache)", calls)
	}
}

func TestEntraTokenSource_HTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	ts := newEntraTokenSource("tenant-1", "client-1", "bad-secret", "scope")
	ts.tokenURL = srv.URL

	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected an error from a 401 token response")
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `cd orchestrator && go test ./internal/detectverify/... -run TestEntraTokenSource -v`
Expected: both PASS.

- [ ] **Step 4: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/detectverify
go build ./...
go vet ./internal/detectverify/...
git add internal/detectverify/entra_auth.go internal/detectverify/entra_auth_test.go
git commit -m "feat(detectverify): add Entra ID client-credentials token source"
git push
```

---

### Task 3: Microsoft Sentinel connector

**Files:**
- Create: `orchestrator/internal/detectverify/sentinel.go`
- Test: `orchestrator/internal/detectverify/sentinel_test.go`

**Interfaces:**
- Consumes: `Config`, `entraTokenSource`/`newEntraTokenSource` (Task 2), `normalizedAlert`/`matchAlerts` (Task 1).
- Produces: `newSentinelConnector(cfg Config) *sentinelConnector`, satisfying `Connector`.

- [ ] **Step 1: Write `sentinel.go`**

```go
// orchestrator/internal/detectverify/sentinel.go
package detectverify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// sentinelConnector queries Microsoft Sentinel's underlying Log Analytics
// workspace for SecurityAlert rows mentioning the run's host in the
// requested window. Authenticates via Entra client-credentials.
type sentinelConnector struct {
	queryURL   string // overridable in tests; defaults to the Log Analytics API
	tokens     *entraTokenSource
	httpClient *http.Client
}

func newSentinelConnector(cfg Config) *sentinelConnector {
	return &sentinelConnector{
		queryURL: "https://api.loganalytics.io/v1/workspaces/" + cfg.WorkspaceID + "/query",
		tokens: newEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://api.loganalytics.io/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type logAnalyticsResponse struct {
	Tables []struct {
		Columns []struct {
			Name string `json:"name"`
		} `json:"columns"`
		Rows [][]any `json:"rows"`
	} `json:"tables"`
}

func (s *sentinelConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	kql := fmt.Sprintf(
		`SecurityAlert | where TimeGenerated between (datetime(%s) .. datetime(%s)) | where ExtendedProperties has "%s" or ExtendedProperties has "%s" | project TimeGenerated, AlertName, AlertSeverity, SystemAlertId, Techniques`,
		req.WindowStart.UTC().Format(time.RFC3339), req.WindowEnd.UTC().Format(time.RFC3339),
		escapeKQLString(req.HostName), escapeKQLString(req.HostIP))
	data, err := s.query(ctx, kql)
	if err != nil {
		return VerifyResult{}, err
	}
	alerts, err := parseLogAnalyticsAlerts(data)
	if err != nil {
		return VerifyResult{}, err
	}
	return matchAlerts(req, alerts), nil
}

func (s *sentinelConnector) TestConnection(ctx context.Context) error {
	_, err := s.query(ctx, "SecurityAlert | take 1")
	return err
}

func (s *sentinelConnector) query(ctx context.Context, kql string) ([]byte, error) {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"query": kql})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.queryURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sentinel query: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("sentinel query: HTTP %d: %s", resp.StatusCode, data)
	}
	return data, nil
}

func parseLogAnalyticsAlerts(data []byte) ([]normalizedAlert, error) {
	var resp logAnalyticsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("sentinel: parse response: %w", err)
	}
	if len(resp.Tables) == 0 {
		return nil, nil
	}
	table := resp.Tables[0]
	col := map[string]int{}
	for i, c := range table.Columns {
		col[c.Name] = i
	}
	var out []normalizedAlert
	for _, row := range table.Rows {
		a := normalizedAlert{}
		if i, ok := col["TimeGenerated"]; ok && i < len(row) {
			if ts, ok := row[i].(string); ok {
				a.Timestamp, _ = time.Parse(time.RFC3339, ts)
			}
		}
		if i, ok := col["AlertName"]; ok && i < len(row) {
			a.RuleName, _ = row[i].(string)
		}
		if i, ok := col["AlertSeverity"]; ok && i < len(row) {
			a.Severity, _ = row[i].(string)
		}
		if i, ok := col["SystemAlertId"]; ok && i < len(row) {
			a.AlertID, _ = row[i].(string)
		}
		if i, ok := col["Techniques"]; ok && i < len(row) {
			if techs, ok := row[i].(string); ok && techs != "" {
				a.Techniques = strings.Split(techs, ",")
				for j := range a.Techniques {
					a.Techniques[j] = strings.TrimSpace(a.Techniques[j])
				}
			}
		}
		a.InvestigationURL = "https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/AlertBlade/alertId/" + a.AlertID
		raw, _ := json.Marshal(map[string]any{
			"alertId": a.AlertID, "ruleName": a.RuleName, "timestamp": a.Timestamp,
			"severity": a.Severity, "techniques": a.Techniques,
		})
		a.RawJSON = raw
		out = append(out, a)
	}
	return out, nil
}

func escapeKQLString(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
```

- [ ] **Step 2: Write `sentinel_test.go`**

```go
// orchestrator/internal/detectverify/sentinel_test.go
package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func newTestSentinelConnector(t *testing.T, tokenURL, queryURL string) *sentinelConnector {
	t.Helper()
	c := newSentinelConnector(Config{
		Provider: "microsoft_sentinel", TenantID: "t1", ClientID: "c1", ClientSecret: "s1", WorkspaceID: "w1",
	})
	c.tokens.tokenURL = tokenURL
	c.queryURL = queryURL
	return c
}

func TestSentinelVerify_TechniqueTaggedAlert_Detected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(90 * time.Second)
	queryResp := map[string]any{
		"tables": []map[string]any{
			{
				"columns": []map[string]string{
					{"name": "TimeGenerated"}, {"name": "AlertName"}, {"name": "AlertSeverity"},
					{"name": "SystemAlertId"}, {"name": "Techniques"},
				},
				"rows": [][]any{
					{alertTime.Format(time.RFC3339), "Suspicious PowerShell", "High", "alert-1", "T1059.001"},
				},
			},
		},
	}
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(queryResp)
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1059.001", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-2 * time.Minute), WindowEnd: stepTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if result.DetectionLatency != 90*time.Second {
		t.Fatalf("DetectionLatency = %v, want 90s", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 1 || result.MatchedAlerts[0].AlertID != "alert-1" {
		t.Fatalf("MatchedAlerts = %+v", result.MatchedAlerts)
	}
}

func TestSentinelVerify_NoAlerts_NotDetected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"tables": []map[string]any{{"columns": []map[string]string{}, "rows": [][]any{}}},
		})
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestSentinelVerify_QueryHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 500 query response, not a fabricated NotDetected")
	}
}

func TestSentinelTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	querySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tables": []map[string]any{}})
	}))
	defer querySrv.Close()

	c := newTestSentinelConnector(t, tokenSrv.URL, querySrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `cd orchestrator && go test ./internal/detectverify/... -run TestSentinel -v`
Expected: all 4 PASS.

- [ ] **Step 4: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/detectverify
go build ./...
go vet ./internal/detectverify/...
git add internal/detectverify/sentinel.go internal/detectverify/sentinel_test.go
git commit -m "feat(detectverify): add Microsoft Sentinel connector"
git push
```

---

### Task 4: Microsoft Defender XDR connector + NewConnector dispatcher

**Files:**
- Create: `orchestrator/internal/detectverify/defenderxdr.go`
- Test: `orchestrator/internal/detectverify/defenderxdr_test.go`
- Modify: `orchestrator/internal/detectverify/connector.go` (add `NewConnector`)
- Test: `orchestrator/internal/detectverify/connector_test.go`

**Interfaces:**
- Consumes: `Config`, `entraTokenSource` (Task 2), `normalizedAlert`/`matchAlerts` (Task 1).
- Produces: `newDefenderXDRConnector(cfg Config) *defenderXDRConnector` (satisfies `Connector`); `NewConnector(cfg Config) (Connector, error)` — the dispatcher `internal/api` (Tasks 6–7) will call.

- [ ] **Step 1: Write `defenderxdr.go`**

```go
// orchestrator/internal/detectverify/defenderxdr.go
package detectverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defenderXDRConnector queries Microsoft Defender XDR's Graph security alerts
// API (alerts_v2) for alerts in the run's window whose evidence names the
// run's host. Authenticates via Entra client-credentials.
type defenderXDRConnector struct {
	baseURL    string // overridable in tests; defaults to Microsoft Graph
	tokens     *entraTokenSource
	httpClient *http.Client
}

func newDefenderXDRConnector(cfg Config) *defenderXDRConnector {
	return &defenderXDRConnector{
		baseURL: "https://graph.microsoft.com/v1.0",
		tokens: newEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type graphAlert struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	CreatedDateTime string   `json:"createdDateTime"`
	Techniques      []string `json:"techniques"`
	Evidence        []struct {
		DeviceDNSName string `json:"deviceDnsName"`
	} `json:"evidence"`
}

type graphAlertsResponse struct {
	Value []json.RawMessage `json:"value"`
}

func (d *defenderXDRConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	raws, err := d.queryAlerts(ctx, req.WindowStart, req.WindowEnd)
	if err != nil {
		return VerifyResult{}, err
	}
	var alerts []normalizedAlert
	for _, raw := range raws {
		var ga graphAlert
		if err := json.Unmarshal(raw, &ga); err != nil {
			continue
		}
		if !alertMentionsHost(ga, req.HostName) {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, ga.CreatedDateTime)
		alerts = append(alerts, normalizedAlert{
			AlertID:          ga.ID,
			RuleName:         ga.Title,
			Timestamp:        ts,
			Severity:         ga.Severity,
			Techniques:       ga.Techniques,
			InvestigationURL: "https://security.microsoft.com/alerts/" + ga.ID,
			RawJSON:          raw,
		})
	}
	return matchAlerts(req, alerts), nil
}

// alertMentionsHost reports whether ga's evidence names hostName. When
// hostName is empty (agent has no known hostname) every alert is accepted —
// better to over-match at medium confidence than silently verify nothing.
func alertMentionsHost(ga graphAlert, hostName string) bool {
	if hostName == "" {
		return true
	}
	for _, e := range ga.Evidence {
		if strings.EqualFold(e.DeviceDNSName, hostName) {
			return true
		}
	}
	return false
}

func (d *defenderXDRConnector) TestConnection(ctx context.Context) error {
	_, err := d.queryAlerts(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}

func (d *defenderXDRConnector) queryAlerts(ctx context.Context, start, end time.Time) ([]json.RawMessage, error) {
	token, err := d.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/security/alerts_v2?$filter=createdDateTime ge %s and createdDateTime le %s",
		d.baseURL, start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("defender xdr query: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("defender xdr query: HTTP %d: %s", resp.StatusCode, data)
	}
	var out graphAlertsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("defender xdr: parse response: %w", err)
	}
	return out.Value, nil
}
```

- [ ] **Step 2: Write `defenderxdr_test.go`**

```go
// orchestrator/internal/detectverify/defenderxdr_test.go
package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestDefenderXDRConnector(t *testing.T, tokenURL, graphURL string) *defenderXDRConnector {
	t.Helper()
	c := newDefenderXDRConnector(Config{Provider: "microsoft_defender", TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	c.tokens.tokenURL = tokenURL
	c.baseURL = graphURL
	return c
}

func TestDefenderXDRVerify_HostMatchedTechniqueTaggedAlert_Detected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(2 * time.Minute)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Suspicious process", "severity": "high",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "HOST1"}},
				},
				{
					"id": "alert-2", "title": "Unrelated host alert", "severity": "low",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "OTHERHOST"}},
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1055", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-2 * time.Minute), WindowEnd: stepTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if len(result.MatchedAlerts) != 1 || result.MatchedAlerts[0].AlertID != "alert-1" {
		t.Fatalf("MatchedAlerts = %+v, want only alert-1 (the OTHERHOST alert must be filtered out)", result.MatchedAlerts)
	}
}

func TestDefenderXDRVerify_NoMatchingHost_NotDetected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "alert-1", "createdDateTime": time.Now().Format(time.RFC3339), "evidence": []map[string]any{{"deviceDnsName": "OTHERHOST"}}},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1055", HostName: "HOST1", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestDefenderXDRVerify_GraphHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1055", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 403 Graph response, not a fabricated NotDetected")
	}
}
```

- [ ] **Step 3: Add `NewConnector` to `connector.go`**

Append to the end of `orchestrator/internal/detectverify/connector.go` (and add `"fmt"` to the import block):

```go
// NewConnector builds the Connector for cfg.Provider. Returns an error for
// any provider not yet implemented — QRadar/Splunk/Elastic/CrowdStrike/
// Trellix arrive in later slices using this same framework.
func NewConnector(cfg Config) (Connector, error) {
	switch cfg.Provider {
	case "microsoft_sentinel":
		return newSentinelConnector(cfg), nil
	case "microsoft_defender":
		return newDefenderXDRConnector(cfg), nil
	default:
		return nil, fmt.Errorf("detectverify: provider %q not supported", cfg.Provider)
	}
}
```

- [ ] **Step 4: Write `connector_test.go`**

```go
// orchestrator/internal/detectverify/connector_test.go
package detectverify

import "testing"

func TestNewConnector_DispatchesKnownProviders(t *testing.T) {
	if _, err := NewConnector(Config{Provider: "microsoft_sentinel", WorkspaceID: "w1"}); err != nil {
		t.Errorf("microsoft_sentinel: %v", err)
	}
	if _, err := NewConnector(Config{Provider: "microsoft_defender"}); err != nil {
		t.Errorf("microsoft_defender: %v", err)
	}
}

func TestNewConnector_UnsupportedProvider_ReturnsError(t *testing.T) {
	if _, err := NewConnector(Config{Provider: "qradar"}); err == nil {
		t.Fatal("expected an error for a provider not yet implemented in this slice")
	}
}
```

- [ ] **Step 5: Run the tests**

Run: `cd orchestrator && go test ./internal/detectverify/... -run 'TestDefenderXDR|TestNewConnector' -v`
Expected: all PASS.

- [ ] **Step 6: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/detectverify
go build ./...
go vet ./internal/detectverify/...
git add internal/detectverify/defenderxdr.go internal/detectverify/defenderxdr_test.go internal/detectverify/connector.go internal/detectverify/connector_test.go
git commit -m "feat(detectverify): add Microsoft Defender XDR connector and NewConnector dispatcher"
git push
```

---

### Task 5: Per-run orchestration (`VerifyRun`)

**Files:**
- Create: `orchestrator/internal/detectverify/orchestrate.go`
- Test: `orchestrator/internal/detectverify/orchestrate_test.go`

**Interfaces:**
- Consumes: `Connector` (Task 1), `scenario.Engine`/`scenario.Step`/`scenario.ExpectedDetection`/`scenario.ResolveVerification`/`scenario.ResolveDomain`/`scenario.VerificationAPI` (existing `internal/scenario` package), `verification.AttestInput`/`verification.Record`/`verification.EvidenceInput`/`verification.Evidence`/`verification.SourceAPI`/`verification.ResultDetected`/`verification.ResultNotDetected`/`verification.StateApproved`/`verification.StateNeedsReview` (existing `internal/verification` package), `models.SimulationResult`/`models.ResultFail` (existing `internal/models` package).
- Produces: `ScenarioResolver` interface, `Store` interface, `VerifyRunParams` struct (`RunID, ScenarioID, HostName, HostIP, Results, Scenarios, Store, Connectors`), `VerifyRunSummary` struct (`Checked, Attested, Errors`), `func VerifyRun(ctx context.Context, p VerifyRunParams) VerifyRunSummary` — `internal/api` (Task 7) calls this with real `*scenario.Engine` and `*verification.Store`.

- [ ] **Step 1: Write `orchestrate.go`**

```go
// orchestrator/internal/detectverify/orchestrate.go
package detectverify

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

// preWindow/postWindow match internal/siem/correlator.go's tuning exactly —
// no need to invent new SIEM-ingestion-lag numbers for this package.
const (
	preWindow  = 2 * time.Minute
	postWindow = 5 * time.Minute
)

// ScenarioResolver is the slice of the scenario engine VerifyRun needs to
// resolve a run's per-step detection expectations. *scenario.Engine satisfies
// it; kept as an interface so orchestration is testable without a real engine
// (mirrors reporting.ScenarioResolver).
type ScenarioResolver interface {
	Get(id string) (*scenario.Scenario, bool)
	ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef)
}

// Store is the slice of the Verification Store VerifyRun writes to.
// *verification.Store satisfies it.
type Store interface {
	Attest(ctx context.Context, in verification.AttestInput) (verification.Record, error)
	AddEvidence(ctx context.Context, in verification.EvidenceInput) (verification.Evidence, error)
}

// VerifyRunParams is the input to VerifyRun. The caller (internal/api) loads
// all of this from the database — this package does no I/O beyond the
// connectors and store it is handed.
type VerifyRunParams struct {
	RunID      string
	ScenarioID string
	HostName   string
	HostIP     string
	Results    []models.SimulationResult
	Scenarios  ScenarioResolver
	Store      Store
	Connectors map[string]Connector // keyed by Provider Registry key, e.g. "microsoft_sentinel"
}

// VerifyRunSummary reports what VerifyRun did, for logging/audit.
type VerifyRunSummary struct {
	Checked  int // expectations examined
	Attested int // attestations written
	Errors   int // connector/store errors (no attestation written for that expectation)
}

// VerifyRun resolves every step's api-verified expectations for a run and
// checks each one against its provider's connector, attesting the result.
//
// An expectation is skipped (not counted in Checked) when: the step wasn't
// executed or didn't fail (Pass/Blocked technique produces no alertable
// behaviour — the same rule internal/siem/correlator.go uses), the
// expectation's resolved verification model isn't "api", or no connector is
// configured for its provider.
//
// A connector or store error leaves the expectation exactly as it was before
// (see Global Constraints in the plan/spec: never fabricate a NotDetected).
func VerifyRun(ctx context.Context, p VerifyRunParams) VerifyRunSummary {
	var summary VerifyRunSummary
	if p.Scenarios == nil || p.ScenarioID == "" {
		return summary
	}
	sc, ok := p.Scenarios.Get(p.ScenarioID)
	if !ok {
		return summary
	}

	resultByTech := map[string]models.SimulationResult{}
	for _, r := range p.Results {
		resultByTech[r.Technique.ID] = r
	}

	for _, step := range sc.Steps {
		res, ok := resultByTech[step.TechniqueID]
		if !ok || res.Result != models.ResultFail {
			continue
		}
		exps, _ := p.Scenarios.ResolveStepExpectations(step)
		for _, exp := range exps {
			if scenario.ResolveVerification(exp) != scenario.VerificationAPI {
				continue
			}
			conn, ok := p.Connectors[normalizeProvider(exp.Provider)]
			if !ok {
				continue
			}
			summary.Checked++

			req := VerifyRequest{
				RunID:          p.RunID,
				ExpectationID:  exp.ID,
				TechniqueID:    step.TechniqueID,
				HostName:       p.HostName,
				HostIP:         p.HostIP,
				StepExecutedAt: res.ExecutedAt,
				WindowStart:    res.ExecutedAt.Add(-preWindow),
				WindowEnd:      res.ExecutedAt.Add(time.Duration(res.DurationMs)*time.Millisecond + postWindow),
			}
			result, err := conn.Verify(ctx, req)
			if err != nil {
				summary.Errors++
				log.Printf("[detectverify] run %s expectation %s: %v", p.RunID, exp.ID, err)
				continue
			}

			in := verification.AttestInput{
				RunID:         p.RunID,
				ExpectationID: exp.ID,
				TechniqueID:   step.TechniqueID,
				Domain:        scenario.ResolveDomain(exp),
				Provider:      exp.Provider,
				Source:        verification.SourceAPI,
				VerifiedBy:    "connector:" + exp.Provider,
				Note:          result.InvestigationURL,
			}
			if result.Verdict == VerdictDetected {
				in.Result = verification.ResultDetected
				in.WorkflowState = verification.StateApproved
				if len(result.MatchedAlerts) > 0 {
					in.AlertID = result.MatchedAlerts[0].AlertID
				}
			} else {
				in.Result = verification.ResultNotDetected
				in.WorkflowState = verification.StateNeedsReview
			}

			rec, err := p.Store.Attest(ctx, in)
			if err != nil {
				summary.Errors++
				log.Printf("[detectverify] run %s expectation %s: attest: %v", p.RunID, exp.ID, err)
				continue
			}
			summary.Attested++

			if result.Verdict == VerdictDetected && len(result.MatchedAlerts) > 0 {
				attachMatchedAlertEvidence(ctx, p.Store, rec.ID, exp.Provider, result.MatchedAlerts)
			}
		}
	}
	return summary
}

// attachMatchedAlertEvidence records the connector's matched alerts as JSON
// evidence on the just-written attestation, via the existing SP2 evidence
// system — no schema change needed. Failure here is logged, not fatal: the
// attestation itself already succeeded.
func attachMatchedAlertEvidence(ctx context.Context, store Store, verificationID, provider string, alerts []MatchedAlert) {
	raw, err := json.Marshal(alerts)
	if err != nil {
		return
	}
	if _, err := store.AddEvidence(ctx, verification.EvidenceInput{
		VerificationID:   verificationID,
		OriginalFilename: "connector-alerts.json",
		DisplayFilename:  provider + "-matched-alerts.json",
		MIME:             "application/json",
		UploadedBy:       "connector:" + provider,
		Bytes:            raw,
	}); err != nil {
		log.Printf("[detectverify] verification %s: attach evidence: %v", verificationID, err)
	}
}

func normalizeProvider(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}
```

- [ ] **Step 2: Write `orchestrate_test.go`**

```go
// orchestrator/internal/detectverify/orchestrate_test.go
package detectverify

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

type fakeScenarios struct {
	sc *scenario.Scenario
}

func (f *fakeScenarios) Get(id string) (*scenario.Scenario, bool) {
	if f.sc == nil || f.sc.ID != id {
		return nil, false
	}
	return f.sc, true
}

func (f *fakeScenarios) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	return step.ExpectedDetections, nil
}

type fakeConnector struct {
	result VerifyResult
	err    error
	calls  int
}

func (f *fakeConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	f.calls++
	return f.result, f.err
}
func (f *fakeConnector) TestConnection(ctx context.Context) error { return nil }

type fakeStore struct {
	attested  []verification.AttestInput
	evidence  []verification.EvidenceInput
	attestErr error
}

func (f *fakeStore) Attest(ctx context.Context, in verification.AttestInput) (verification.Record, error) {
	if f.attestErr != nil {
		return verification.Record{}, f.attestErr
	}
	f.attested = append(f.attested, in)
	return verification.Record{ID: "rec-" + in.ExpectationID}, nil
}

func (f *fakeStore) AddEvidence(ctx context.Context, in verification.EvidenceInput) (verification.Evidence, error) {
	f.evidence = append(f.evidence, in)
	return verification.Evidence{ID: "ev-1"}, nil
}

func testScenario(exp scenario.ExpectedDetection) *scenario.Scenario {
	return &scenario.Scenario{
		ID: "sc-1",
		Steps: []scenario.Step{
			{Name: "step1", TechniqueID: "T1059.001", ExpectedDetections: []scenario.ExpectedDetection{exp}},
		},
	}
}

func baseParams(exp scenario.ExpectedDetection, conn Connector, store *fakeStore, result models.CheckResult) VerifyRunParams {
	return VerifyRunParams{
		RunID: "run-1", ScenarioID: "sc-1", HostName: "HOST1", HostIP: "10.0.0.5",
		Results: []models.SimulationResult{
			{Technique: models.AttackTechnique{ID: "T1059.001"}, Result: result, ExecutedAt: time.Now(), DurationMs: 1000},
		},
		Scenarios:  &fakeScenarios{sc: testScenario(exp)},
		Store:      store,
		Connectors: map[string]Connector{"microsoft_sentinel": conn},
	}
}

func apiExpectation() scenario.ExpectedDetection {
	return scenario.ExpectedDetection{ID: "exp-1", Provider: "microsoft_sentinel", Verification: scenario.VerificationAPI, Confidence: scenario.ConfidenceRequired}
}

func TestVerifyRun_DetectedVerdict_AttestsApprovedAndAttachesEvidence(t *testing.T) {
	conn := &fakeConnector{result: VerifyResult{
		Verdict: VerdictDetected, Confidence: ConfidenceHigh,
		MatchedAlerts: []MatchedAlert{{AlertID: "a1"}},
	}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultFail))

	if summary.Checked != 1 || summary.Attested != 1 || summary.Errors != 0 {
		t.Fatalf("summary = %+v, want Checked=1 Attested=1 Errors=0", summary)
	}
	if len(store.attested) != 1 {
		t.Fatalf("attested = %d, want 1", len(store.attested))
	}
	got := store.attested[0]
	if got.Result != verification.ResultDetected || got.WorkflowState != verification.StateApproved {
		t.Fatalf("attestation = %+v, want Result=Detected WorkflowState=Approved", got)
	}
	if got.Source != verification.SourceAPI {
		t.Fatalf("Source = %q, want %q", got.Source, verification.SourceAPI)
	}
	if got.AlertID != "a1" {
		t.Fatalf("AlertID = %q, want a1", got.AlertID)
	}
	if len(store.evidence) != 1 {
		t.Fatalf("evidence = %d, want 1 (matched alert JSON attached)", len(store.evidence))
	}
}

func TestVerifyRun_NotDetectedVerdict_AttestsNeedsReview(t *testing.T) {
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictNotDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultFail))

	if summary.Attested != 1 {
		t.Fatalf("Attested = %d, want 1", summary.Attested)
	}
	got := store.attested[0]
	if got.Result != verification.ResultNotDetected || got.WorkflowState != verification.StateNeedsReview {
		t.Fatalf("attestation = %+v, want Result=NotDetected WorkflowState=NeedsReview", got)
	}
	if len(store.evidence) != 0 {
		t.Fatalf("evidence = %d, want 0 for a NotDetected verdict", len(store.evidence))
	}
}

func TestVerifyRun_SkipsNonAPIVerification(t *testing.T) {
	exp := apiExpectation()
	exp.Verification = scenario.VerificationManual
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(exp, conn, store, models.ResultFail))

	if summary.Checked != 0 || conn.calls != 0 {
		t.Fatalf("summary = %+v, conn.calls = %d, want a manual-verification expectation to be skipped entirely", summary, conn.calls)
	}
}

func TestVerifyRun_SkipsWhenStepDidNotFail(t *testing.T) {
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultBlocked))

	if summary.Checked != 0 || conn.calls != 0 {
		t.Fatalf("summary = %+v, want a Blocked step to be skipped (nothing to alert on)", summary)
	}
}

func TestVerifyRun_SkipsWhenNoConnectorForProvider(t *testing.T) {
	exp := apiExpectation()
	exp.Provider = "splunk" // no connector registered under this key
	conn := &fakeConnector{result: VerifyResult{Verdict: VerdictDetected}}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(exp, conn, store, models.ResultFail))

	if summary.Checked != 0 || conn.calls != 0 {
		t.Fatalf("summary = %+v, want an expectation with no configured connector to be skipped", summary)
	}
}

func TestVerifyRun_ConnectorError_NoAttestationWritten(t *testing.T) {
	conn := &fakeConnector{err: context.DeadlineExceeded}
	store := &fakeStore{}
	summary := VerifyRun(context.Background(), baseParams(apiExpectation(), conn, store, models.ResultFail))

	if summary.Errors != 1 || summary.Attested != 0 {
		t.Fatalf("summary = %+v, want Errors=1 Attested=0", summary)
	}
	if len(store.attested) != 0 {
		t.Fatalf("attested = %d, want 0 — a connector error must never fabricate a verdict", len(store.attested))
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `cd orchestrator && go test ./internal/detectverify/... -run TestVerifyRun -v`
Expected: all 6 PASS.

- [ ] **Step 4: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/detectverify
go build ./...
go vet ./internal/detectverify/...
git add internal/detectverify/orchestrate.go internal/detectverify/orchestrate_test.go
git commit -m "feat(detectverify): add per-run verification orchestration (VerifyRun)"
git push
```

---

### Task 6: `detection_connectors` table migration

**Files:**
- Modify: `orchestrator/internal/db/postgres.go`

**Interfaces:**
- Produces: table `detection_connectors` with columns `id, name, provider, enabled, auto_verify, tenant_id, client_id, client_secret, workspace_id, verify_delay_seconds, created_at, updated_at` — consumed by Task 7's handlers.

- [ ] **Step 1: Add the table to the `stmts` slice in `EnsureSchema`**

In `orchestrator/internal/db/postgres.go`, find this block (it currently ends the `stmts` slice, immediately before the closing `}` at what is currently line 813):

```go
		// verification_evidence_blob holds bytes only when storage_type='database'.
		// Kept in its own table so the metadata row stays light and a move to
		// external storage just stops writing here.
		`CREATE TABLE IF NOT EXISTS verification_evidence_blob (
			id     text  PRIMARY KEY DEFAULT gen_random_uuid()::text,
			bytes  bytea NOT NULL
		)`,
	}
```

Replace it with (adding the new table before the closing `}`):

```go
		// verification_evidence_blob holds bytes only when storage_type='database'.
		// Kept in its own table so the metadata row stays light and a move to
		// external storage just stops writing here.
		`CREATE TABLE IF NOT EXISTS verification_evidence_blob (
			id     text  PRIMARY KEY DEFAULT gen_random_uuid()::text,
			bytes  bytea NOT NULL
		)`,

		// ── Detection Verification Connectors (SP1 first slice) ────────────────
		// detection_connectors: one row per Sentinel/Defender XDR (and later
		// QRadar/Splunk/Elastic/CrowdStrike/Trellix) API connector. Deliberately
		// separate from siem_configs — Defender XDR is not a SIEM, and this
		// package (internal/detectverify) is independent of internal/siem. See
		// docs/superpowers/specs/2026-07-14-detection-verification-connectors-design.md.
		`CREATE TABLE IF NOT EXISTS detection_connectors (
			id                    text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			name                  text        NOT NULL,
			provider              text        NOT NULL,
			enabled               boolean     NOT NULL DEFAULT true,
			auto_verify           boolean     NOT NULL DEFAULT false,
			tenant_id             text        NOT NULL DEFAULT '',
			client_id             text        NOT NULL DEFAULT '',
			client_secret         text        NOT NULL DEFAULT '',
			workspace_id          text        NOT NULL DEFAULT '',
			verify_delay_seconds  int         NOT NULL DEFAULT 120,
			created_at            timestamptz NOT NULL DEFAULT NOW(),
			updated_at            timestamptz NOT NULL DEFAULT NOW()
		)`,
	}
```

- [ ] **Step 2: Verify the schema applies cleanly**

Run: `cd orchestrator && go build ./...`
Expected: builds cleanly (this is a pure SQL-in-string change; correctness is verified by Task 7's container-backed tests, which will fail at `INSERT`/`SELECT` time if the DDL is wrong).

- [ ] **Step 3: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/db
go build ./...
go vet ./internal/db/...
git add internal/db/postgres.go
git commit -m "feat(db): add detection_connectors table for SP1 API connectors"
git push
```

---

### Task 7: API config CRUD handlers (Admin only)

**Files:**
- Create: `orchestrator/internal/api/detectverify_handlers.go`
- Test: `orchestrator/internal/api/detectverify_config_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `detectVerifyConnector` field to `Handler`)

**Interfaces:**
- Consumes: `detectverify.Config`, `detectverify.Connector`, `detectverify.NewConnector` (Tasks 1–5); existing `Handler` struct, `jsonError`/`respond`/`h.auditLog` helpers, `chi.URLParam` (established patterns from `siem_handlers.go`).
- Produces: `h.ListDetectionConnectors`, `h.CreateDetectionConnector`, `h.UpdateDetectionConnector`, `h.DeleteDetectionConnector`, `h.TestDetectionConnector`, `h.loadDetectionConnector(ctx, id) (*detectverify.Config, error)` — Task 8 reuses `loadDetectionConnector`.

- [ ] **Step 1: Add the connector-builder override field to `Handler`**

In `orchestrator/internal/api/handlers.go`, find:

```go
type Handler struct {
	db               *pgxpool.Pool
	hub              *ws.Hub
	engine           *scenario.Engine
	secret           string
	agentSecret      string // optional shared secret for agent-facing endpoints
	calderaURL       string
```

Add one field right after `engine`:

```go
type Handler struct {
	db               *pgxpool.Pool
	hub              *ws.Hub
	engine           *scenario.Engine
	// detectVerifyConnector builds a detectverify.Connector for a config.
	// nil in production (New leaves it unset; call sites fall back to
	// detectverify.NewConnector) — tests override it to avoid real HTTP calls.
	detectVerifyConnector func(detectverify.Config) (detectverify.Connector, error)
	secret           string
	agentSecret      string // optional shared secret for agent-facing endpoints
	calderaURL       string
```

Add the import in the same file's import block:

```go
	"github.com/audspect/bas/internal/detectverify"
```

- [ ] **Step 2: Write `detectverify_handlers.go`**

```go
// orchestrator/internal/api/detectverify_handlers.go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/detectverify"
)

// ── Detection Connector Config CRUD (Admin only) ───────────────────────────

// ListDetectionConnectors lists all detection verification connector configs.
// GET /api/detectverify/configs
func (h *Handler) ListDetectionConnectors(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, name, provider, enabled, auto_verify, tenant_id, workspace_id,
		        verify_delay_seconds, created_at, updated_at
		   FROM detection_connectors ORDER BY created_at ASC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		ID                 string    `json:"id"`
		Name               string    `json:"name"`
		Provider           string    `json:"provider"`
		Enabled            bool      `json:"enabled"`
		AutoVerify         bool      `json:"autoVerify"`
		TenantID           string    `json:"tenantId"`
		WorkspaceID        string    `json:"workspaceId"`
		VerifyDelaySeconds int       `json:"verifyDelaySeconds"`
		CreatedAt          time.Time `json:"createdAt"`
		UpdatedAt          time.Time `json:"updatedAt"`
	}
	var out []row
	for rows.Next() {
		var rv row
		if err := rows.Scan(&rv.ID, &rv.Name, &rv.Provider, &rv.Enabled, &rv.AutoVerify,
			&rv.TenantID, &rv.WorkspaceID, &rv.VerifyDelaySeconds, &rv.CreatedAt, &rv.UpdatedAt); err != nil {
			continue
		}
		out = append(out, rv)
	}
	if out == nil {
		out = []row{}
	}
	respond(w, out)
}

// CreateDetectionConnector creates a new detection verification connector config.
// POST /api/detectverify/configs
func (h *Handler) CreateDetectionConnector(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name               string `json:"name"`
		Provider           string `json:"provider"`
		Enabled            bool   `json:"enabled"`
		AutoVerify         bool   `json:"autoVerify"`
		TenantID           string `json:"tenantId"`
		ClientID           string `json:"clientId"`
		ClientSecret       string `json:"clientSecret"`
		WorkspaceID        string `json:"workspaceId"`
		VerifyDelaySeconds int    `json:"verifyDelaySeconds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Name == "" || req.Provider == "" {
		jsonError(w, "name and provider are required", http.StatusBadRequest)
		return
	}
	validProviders := map[string]bool{"microsoft_sentinel": true, "microsoft_defender": true}
	if !validProviders[req.Provider] {
		jsonError(w, "provider must be microsoft_sentinel | microsoft_defender", http.StatusBadRequest)
		return
	}
	if req.VerifyDelaySeconds <= 0 {
		req.VerifyDelaySeconds = 120
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO detection_connectors
		 (name, provider, enabled, auto_verify, tenant_id, client_id, client_secret, workspace_id, verify_delay_seconds)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		req.Name, req.Provider, req.Enabled, req.AutoVerify,
		req.TenantID, req.ClientID, req.ClientSecret, req.WorkspaceID, req.VerifyDelaySeconds,
	).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "detectverify.config_created", id, map[string]any{"provider": req.Provider, "name": req.Name}, "ok")
	respond(w, map[string]any{"id": id})
}

// UpdateDetectionConnector updates a detection verification connector config.
// PUT /api/detectverify/configs/{id}
func (h *Handler) UpdateDetectionConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name               string `json:"name"`
		Enabled            bool   `json:"enabled"`
		AutoVerify         bool   `json:"autoVerify"`
		TenantID           string `json:"tenantId"`
		ClientID           string `json:"clientId"`
		ClientSecret       string `json:"clientSecret"`
		WorkspaceID        string `json:"workspaceId"`
		VerifyDelaySeconds int    `json:"verifyDelaySeconds"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	// Preserve masked sensitive values (UI returns "***" for secrets it can't show).
	var existingSecret string
	h.db.QueryRow(r.Context(), `SELECT client_secret FROM detection_connectors WHERE id=$1`, id).Scan(&existingSecret)
	if req.ClientSecret == "***" {
		req.ClientSecret = existingSecret
	}
	if req.VerifyDelaySeconds <= 0 {
		req.VerifyDelaySeconds = 120
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE detection_connectors SET name=$1, enabled=$2, auto_verify=$3, tenant_id=$4,
		        client_id=$5, client_secret=$6, workspace_id=$7, verify_delay_seconds=$8, updated_at=NOW()
		  WHERE id=$9`,
		req.Name, req.Enabled, req.AutoVerify, req.TenantID,
		req.ClientID, req.ClientSecret, req.WorkspaceID, req.VerifyDelaySeconds, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "detectverify.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteDetectionConnector deletes a detection verification connector config.
// DELETE /api/detectverify/configs/{id}
func (h *Handler) DeleteDetectionConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM detection_connectors WHERE id=$1`, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "connector not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "detectverify.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestDetectionConnector tests connectivity for a saved detection connector.
// POST /api/detectverify/configs/{id}/test
func (h *Handler) TestDetectionConnector(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, err := h.loadDetectionConnector(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	conn, err := h.buildDetectConnector(*cfg)
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := conn.TestConnection(r.Context()); err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (h *Handler) loadDetectionConnector(ctx context.Context, id string) (*detectverify.Config, error) {
	var cfg detectverify.Config
	err := h.db.QueryRow(ctx,
		`SELECT id, name, provider, enabled, auto_verify, tenant_id, client_id, client_secret,
		        workspace_id, verify_delay_seconds
		   FROM detection_connectors WHERE id=$1`, id,
	).Scan(&cfg.ID, &cfg.Name, &cfg.Provider, &cfg.Enabled, &cfg.AutoVerify,
		&cfg.TenantID, &cfg.ClientID, &cfg.ClientSecret, &cfg.WorkspaceID, &cfg.VerifyDelaySeconds)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// buildDetectConnector builds a live connector for cfg, honoring a test
// override on h.detectVerifyConnector when set.
func (h *Handler) buildDetectConnector(cfg detectverify.Config) (detectverify.Connector, error) {
	if h.detectVerifyConnector != nil {
		return h.detectVerifyConnector(cfg)
	}
	return detectverify.NewConnector(cfg)
}
```

- [ ] **Step 3: Write `detectverify_config_test.go`**

```go
// orchestrator/internal/api/detectverify_config_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func detectverifyHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func detectverifyConfigReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/detectverify/configs", bytes.NewReader(b))
}

// fakeDetectConnector is a no-network Connector used by handler tests so
// TestDetectionConnector can be exercised without a real Entra/Sentinel/Graph
// endpoint.
type fakeDetectConnector struct{ testErr error }

func (f *fakeDetectConnector) Verify(ctx context.Context, req detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	return detectverify.VerifyResult{}, nil
}
func (f *fakeDetectConnector) TestConnection(ctx context.Context) error { return f.testErr }

func TestListDetectionConnectors_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListDetectionConnectors(rec, httptest.NewRequest(http.MethodGet, "/api/detectverify/configs", nil))
		var empty []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 connectors, got %d", len(empty))
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{
			"name": "Prod Sentinel", "provider": "microsoft_sentinel", "workspaceId": "w1",
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create: status = %d, want 200, body = %s", createRec.Code, createRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListDetectionConnectors(listRec, httptest.NewRequest(http.MethodGet, "/api/detectverify/configs", nil))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Prod Sentinel" || out[0]["provider"] != "microsoft_sentinel" {
			t.Fatalf("out = %+v, want 1 entry named Prod Sentinel/microsoft_sentinel", out)
		}
		if out[0]["verifyDelaySeconds"].(float64) != 120 {
			t.Fatalf("verifyDelaySeconds = %v, want default 120", out[0]["verifyDelaySeconds"])
		}
	})
}

func TestCreateDetectionConnector_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing name", map[string]any{"provider": "microsoft_sentinel"}},
			{"missing provider", map[string]any{"name": "x"}},
			{"invalid provider", map[string]any{"name": "x", "provider": "qradar"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreateDetectionConnector(rec, detectverifyConfigReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

// TestUpdateDetectionConnector_PreservesMaskedSecret pins the "***" sentinel
// contract, same as SIEM configs: resubmitting the masked value must NOT
// overwrite the real stored secret.
func TestUpdateDetectionConnector_PreservesMaskedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{
			"name": "x", "provider": "microsoft_sentinel", "clientSecret": "real-secret",
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{"name": "x-renamed", "clientSecret": "***"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateDetectionConnector(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var name, secret string
		pool.QueryRow(context.Background(),
			`SELECT name, client_secret FROM detection_connectors WHERE id=$1`, created.ID,
		).Scan(&name, &secret)
		if name != "x-renamed" {
			t.Errorf("name = %q, want x-renamed", name)
		}
		if secret != "real-secret" {
			t.Errorf("client_secret = %q, want the original secret preserved", secret)
		}
	})
}

func TestDeleteDetectionConnector_NotFoundAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		notFoundRec := httptest.NewRecorder()
		h.DeleteDetectionConnector(notFoundRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if notFoundRec.Code != http.StatusNotFound {
			t.Fatalf("not found: status = %d, want 404", notFoundRec.Code)
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{"name": "x", "provider": "microsoft_defender"}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteDetectionConnector(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM detection_connectors WHERE id=$1`, created.ID).Scan(&n)
		if n != 0 {
			t.Fatalf("expected the connector to be gone, found %d rows", n)
		}
	})
}

func TestTestDetectionConnector_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TestDetectionConnector(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestTestDetectionConnector_SuccessAndFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		h.detectVerifyConnector = func(cfg detectverify.Config) (detectverify.Connector, error) {
			if cfg.Name == "bad" {
				return &fakeDetectConnector{testErr: errors.New("auth failed")}, nil
			}
			return &fakeDetectConnector{}, nil
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{"name": "good", "provider": "microsoft_sentinel"}))
		var good struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &good)

		rec := httptest.NewRecorder()
		h.TestDetectionConnector(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", good.ID))
		var out struct {
			OK bool `json:"ok"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if !out.OK {
			t.Fatalf("expected ok:true, body = %s", rec.Body.String())
		}

		createRec2 := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec2, detectverifyConfigReq(map[string]any{"name": "bad", "provider": "microsoft_sentinel"}))
		var bad struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec2.Body.Bytes(), &bad)

		rec2 := httptest.NewRecorder()
		h.TestDetectionConnector(rec2, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", bad.ID))
		var out2 struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if out2.OK || out2.Error == "" {
			t.Fatalf("expected ok:false with an error, got %+v", out2)
		}
	})
}
```

- [ ] **Step 4: Run the tests**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListDetectionConnectors|TestCreateDetectionConnector|TestUpdateDetectionConnector|TestDeleteDetectionConnector|TestTestDetectionConnector' -v`
Expected: all PASS. (These are container-backed; ensure Docker is available. If it isn't, `go test ./internal/api/... -short` will skip them cleanly — do not treat a `-short` skip as a pass for this step.)

- [ ] **Step 5: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/api
go build ./...
go vet ./internal/api/...
git add internal/api/detectverify_handlers.go internal/api/detectverify_config_test.go internal/api/handlers.go
git commit -m "feat(api): add detection connector config CRUD (Admin only)"
git push
```

---

### Task 8: Trigger endpoint, auto-verify wiring, routes, and RBAC

**Files:**
- Modify: `orchestrator/internal/api/detectverify_handlers.go` (add trigger + orchestration wiring)
- Modify: `orchestrator/internal/api/handlers.go` (auto-verify call site in `SubmitScenarioResult`)
- Modify: `orchestrator/internal/api/routes.go` (register routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add route entries)
- Test: `orchestrator/internal/api/detectverify_trigger_test.go`

**Interfaces:**
- Consumes: `detectverify.VerifyRun`/`VerifyRunParams` (Task 5), `h.loadDetectionConnector`/`h.buildDetectConnector` (Task 7), `verification.NewStore` (existing), `h.engine` (existing `Handler` field).
- Produces: `h.TriggerDetectionVerification` (HTTP handler), `h.AutoVerifyDetection(runID string)`, `h.runDetectionVerification(ctx, runID)`, `h.runDetectionVerificationForConnector(ctx, runID, connectorID string)`, `h.loadRunForVerification(ctx, runID) (scenarioID, host, ip string, results []models.SimulationResult, err error)`.

- [ ] **Step 1: Append orchestration wiring to `detectverify_handlers.go`**

Add to the end of `orchestrator/internal/api/detectverify_handlers.go` (and add `"fmt"`, `"log"` to the import block):

```go
// ── Correlation / Trigger ───────────────────────────────────────────────────

// TriggerDetectionVerification manually runs API detection verification for a
// completed run against every enabled connector.
// POST /api/detectverify/run/{runId}
func (h *Handler) TriggerDetectionVerification(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		h.runDetectionVerification(ctx, runID)
	}()
	h.auditLog(r, "detectverify.triggered", runID, nil, "ok")
	respond(w, map[string]any{"status": "verifying", "runId": runID,
		"message": "Detection verification started — results will appear in the run report shortly"})
}

// AutoVerifyDetection is called from SubmitScenarioResult when a run
// completes. Fires one independent, delayed verification pass per enabled
// connector with auto_verify=true — mirrors AutoCorrelateSIEM's per-config
// dispatch exactly. Each goroutine sleeps its own verify_delay_seconds before
// querying, to absorb SIEM/XDR ingestion lag.
func (h *Handler) AutoVerifyDetection(runID string) {
	rows, err := h.db.Query(context.Background(),
		`SELECT id, verify_delay_seconds FROM detection_connectors
		  WHERE enabled=true AND auto_verify=true ORDER BY created_at ASC`)
	if err != nil || rows == nil {
		return
	}
	type target struct {
		id    string
		delay int
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.delay); err != nil {
			continue
		}
		targets = append(targets, t)
	}
	rows.Close()

	for _, t := range targets {
		t := t
		go func() {
			if t.delay > 0 {
				time.Sleep(time.Duration(t.delay) * time.Second)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			h.runDetectionVerificationForConnector(ctx, runID, t.id)
		}()
	}
}

// loadRunForVerification loads the scenario ID, host name/IP, and stored
// results for a run — the same data AutoCorrelateSIEM's call site already
// reads for SIEM correlation, plus the scenario ID VerifyRun needs to resolve
// expectations.
func (h *Handler) loadRunForVerification(ctx context.Context, runID string) (scenarioID, agentHost, agentIP string, results []models.SimulationResult, err error) {
	var resultsRaw []byte
	err = h.db.QueryRow(ctx,
		`SELECT sr.scenario_id, COALESCE(a.hostname,''), COALESCE(a.ip_address,''), sr.results
		   FROM scenario_runs sr
		   LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.id = $1`, runID,
	).Scan(&scenarioID, &agentHost, &agentIP, &resultsRaw)
	if err != nil {
		return "", "", "", nil, err
	}
	_ = json.Unmarshal(resultsRaw, &results)
	return scenarioID, agentHost, agentIP, results, nil
}

// runDetectionVerification checks a run against every enabled connector.
// Used by the manual trigger endpoint.
func (h *Handler) runDetectionVerification(ctx context.Context, runID string) {
	scenarioID, host, ip, results, err := h.loadRunForVerification(ctx, runID)
	if err != nil {
		log.Printf("[detectverify] load run %s: %v", runID, err)
		return
	}
	connectors, err := h.enabledDetectionConnectors(ctx)
	if err != nil || len(connectors) == 0 {
		return
	}
	summary := detectverify.VerifyRun(ctx, detectverify.VerifyRunParams{
		RunID: runID, ScenarioID: scenarioID, HostName: host, HostIP: ip,
		Results: results, Scenarios: h.engine, Store: verification.NewStore(h.db), Connectors: connectors,
	})
	log.Printf("[detectverify] run %s: checked=%d attested=%d errors=%d",
		runID, summary.Checked, summary.Attested, summary.Errors)
}

// runDetectionVerificationForConnector checks a run against exactly one
// connector. Used by the auto-verify path so each connector gets its own
// independently-timed delay.
func (h *Handler) runDetectionVerificationForConnector(ctx context.Context, runID, connectorID string) {
	scenarioID, host, ip, results, err := h.loadRunForVerification(ctx, runID)
	if err != nil {
		log.Printf("[detectverify] load run %s: %v", runID, err)
		return
	}
	cfg, err := h.loadDetectionConnector(ctx, connectorID)
	if err != nil {
		return
	}
	conn, err := h.buildDetectConnector(*cfg)
	if err != nil {
		log.Printf("[detectverify] build connector %s: %v", connectorID, err)
		return
	}
	summary := detectverify.VerifyRun(ctx, detectverify.VerifyRunParams{
		RunID: runID, ScenarioID: scenarioID, HostName: host, HostIP: ip,
		Results: results, Scenarios: h.engine, Store: verification.NewStore(h.db),
		Connectors: map[string]detectverify.Connector{cfg.Provider: conn},
	})
	log.Printf("[detectverify] run %s connector %s: checked=%d attested=%d errors=%d",
		runID, connectorID, summary.Checked, summary.Attested, summary.Errors)
}

// enabledDetectionConnectors builds a live Connector for every enabled
// detection_connectors row, keyed by provider.
func (h *Handler) enabledDetectionConnectors(ctx context.Context) (map[string]detectverify.Connector, error) {
	rows, err := h.db.Query(ctx, `SELECT id FROM detection_connectors WHERE enabled=true ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	rows.Close()

	out := map[string]detectverify.Connector{}
	for _, id := range ids {
		cfg, err := h.loadDetectionConnector(ctx, id)
		if err != nil {
			continue
		}
		conn, err := h.buildDetectConnector(*cfg)
		if err != nil {
			log.Printf("[detectverify] build connector %s: %v", id, err)
			continue
		}
		out[cfg.Provider] = conn
	}
	return out, nil
}
```

Update the import block at the top of `orchestrator/internal/api/detectverify_handlers.go` to:

```go
import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/verification"
)
```

- [ ] **Step 2: Wire the auto-verify call site in `SubmitScenarioResult`**

In `orchestrator/internal/api/handlers.go`, find (this is the existing `AutoCorrelateSIEM` dispatch, currently around line 1795-1814):

```go
		{
			runID := raw.RunID
			agentID := raw.AgentID
			sr := simResults
			go func() {
				var agentIP string
				var runStart time.Time
				h.db.QueryRow(context.Background(),
					`SELECT COALESCE(a.ip_address,''), sr.started_at
					   FROM scenario_runs sr
					   LEFT JOIN agents a ON a.agent_id = sr.agent_id
					  WHERE sr.id = $1`, runID,
				).Scan(&agentIP, &runStart)
				runEnd := time.Now()
				h.AutoCorrelateSIEM(runID, agentID, agentIP, runStart, runEnd, sr)
			}()
		}
```

Replace it with (adding the `AutoVerifyDetection` call after `AutoCorrelateSIEM`):

```go
		{
			runID := raw.RunID
			agentID := raw.AgentID
			sr := simResults
			go func() {
				var agentIP string
				var runStart time.Time
				h.db.QueryRow(context.Background(),
					`SELECT COALESCE(a.ip_address,''), sr.started_at
					   FROM scenario_runs sr
					   LEFT JOIN agents a ON a.agent_id = sr.agent_id
					  WHERE sr.id = $1`, runID,
				).Scan(&agentIP, &runStart)
				runEnd := time.Now()
				h.AutoCorrelateSIEM(runID, agentID, agentIP, runStart, runEnd, sr)
				h.AutoVerifyDetection(runID)
			}()
		}
```

- [ ] **Step 3: Register routes in `routes.go`**

In `orchestrator/internal/api/routes.go`, find the SIEM Correlation trigger line (Analyst+Admin block, currently around line 186-188):

```go
			// SIEM Correlation — trigger and results (Analyst+)
			r.Post("/api/siem/correlate/{runId}", h.TriggerSIEMCorrelation)
			r.Get("/api/siem/correlations/{runId}", h.GetSIEMCorrelations)
```

Add right after it:

```go
			// SIEM Correlation — trigger and results (Analyst+)
			r.Post("/api/siem/correlate/{runId}", h.TriggerSIEMCorrelation)
			r.Get("/api/siem/correlations/{runId}", h.GetSIEMCorrelations)
			// Detection Verification — manual trigger (Analyst+)
			r.Post("/api/detectverify/run/{runId}", h.TriggerDetectionVerification)
```

Find the SIEM Correlation connector-management block (Admin-only block, currently around line 325-330):

```go
			// SIEM Correlation — connector management (Admin only)
			r.Get("/api/siem/configs", h.ListSIEMConfigs)
			r.Post("/api/siem/configs", h.CreateSIEMConfig)
			r.Put("/api/siem/configs/{id}", h.UpdateSIEMConfig)
			r.Delete("/api/siem/configs/{id}", h.DeleteSIEMConfig)
			r.Post("/api/siem/configs/{id}/test", h.TestSIEMConfig)
```

Add right after it:

```go
			// SIEM Correlation — connector management (Admin only)
			r.Get("/api/siem/configs", h.ListSIEMConfigs)
			r.Post("/api/siem/configs", h.CreateSIEMConfig)
			r.Put("/api/siem/configs/{id}", h.UpdateSIEMConfig)
			r.Delete("/api/siem/configs/{id}", h.DeleteSIEMConfig)
			r.Post("/api/siem/configs/{id}/test", h.TestSIEMConfig)

			// Detection Verification — connector management (Admin only)
			r.Get("/api/detectverify/configs", h.ListDetectionConnectors)
			r.Post("/api/detectverify/configs", h.CreateDetectionConnector)
			r.Put("/api/detectverify/configs/{id}", h.UpdateDetectionConnector)
			r.Delete("/api/detectverify/configs/{id}", h.DeleteDetectionConnector)
			r.Post("/api/detectverify/configs/{id}/test", h.TestDetectionConnector)
```

- [ ] **Step 4: Add RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodPost, "/api/siem/correlate/{runId}", tierAnalystAdmin, ""},
```

Add right after it:

```go
	{http.MethodPost, "/api/detectverify/run/{runId}", tierAnalystAdmin, ""},
```

Find:

```go
	{http.MethodGet, "/api/siem/configs", tierAdminOnly, ""},
	{http.MethodPost, "/api/siem/configs", tierAdminOnly, ""},
	{http.MethodPut, "/api/siem/configs/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/siem/configs/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/siem/configs/{id}/test", tierAdminOnly, ""},
```

Add right after it:

```go
	{http.MethodGet, "/api/detectverify/configs", tierAdminOnly, ""},
	{http.MethodPost, "/api/detectverify/configs", tierAdminOnly, ""},
	{http.MethodPut, "/api/detectverify/configs/{id}", tierAdminOnly, ""},
	{http.MethodDelete, "/api/detectverify/configs/{id}", tierAdminOnly, ""},
	{http.MethodPost, "/api/detectverify/configs/{id}/test", tierAdminOnly, ""},
```

- [ ] **Step 5: Write `detectverify_trigger_test.go`**

```go
// orchestrator/internal/api/detectverify_trigger_test.go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedRunForVerification inserts a minimal scenario_runs + agents row pair so
// loadRunForVerification/runDetectionVerification have something to load.
func seedRunForVerification(t *testing.T, pool *pgxpool.Pool, runID, scenarioID, agentID, hostname string, results []models.SimulationResult) {
	t.Helper()
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, ip_address) VALUES ($1,$2,'10.0.0.9')
		 ON CONFLICT (agent_id) DO NOTHING`, agentID, hostname)
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, status, started_at, results)
		 VALUES ($1,$2,$3,'completed',NOW(),$4)`, runID, scenarioID, agentID, resultsJSON)
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
}

// TestTriggerDetectionVerification_EndToEnd seeds a scenario with one
// api-verified expectation, a completed run, and a fake Detected connector,
// then drives the whole path — manual trigger -> DB load -> VerifyRun ->
// Attest -> verification_history row — via runDetectionVerification directly
// (the HTTP handler only dispatches this in a goroutine; the dispatch logic
// itself is exercised in orchestrate_test.go).
func TestTriggerDetectionVerification_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		h.detectVerifyConnector = func(cfg detectverify.Config) (detectverify.Connector, error) {
			return &fakeDetectConnector{}, nil
		}

		sc := &scenario.Scenario{
			ID: "sc-trigger-1",
			Steps: []scenario.Step{
				{
					Name: "step1", TechniqueID: "T1059.001",
					ExpectedDetections: []scenario.ExpectedDetection{
						{ID: "exp-1", Provider: "microsoft_sentinel", Verification: scenario.VerificationAPI, Confidence: scenario.ConfidenceRequired},
					},
				},
			},
		}
		if err := h.engine.Save(sc); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{
			"name": "trig", "provider": "microsoft_sentinel", "enabled": true,
		}))

		runStart := time.Now()
		results := []models.SimulationResult{
			{Technique: models.AttackTechnique{ID: "T1059.001"}, Result: models.ResultFail, ExecutedAt: runStart, DurationMs: 1000},
		}
		seedRunForVerification(t, pool, "run-trigger-1", "sc-trigger-1", "agent-trigger-1", "HOST1", results)

		rec := httptest.NewRecorder()
		h.TriggerDetectionVerification(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "runId", "run-trigger-1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("trigger: status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		deadline := time.Now().Add(5 * time.Second)
		var n int
		for time.Now().Before(deadline) {
			pool.QueryRow(context.Background(),
				`SELECT COUNT(*) FROM verification_history WHERE run_id='run-trigger-1' AND expectation_id='exp-1'`).Scan(&n)
			if n > 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if n != 1 {
			t.Fatalf("verification_history rows for run-trigger-1/exp-1 = %d, want 1", n)
		}
		var result, source string
		pool.QueryRow(context.Background(),
			`SELECT result, verification_source FROM verification_history WHERE run_id='run-trigger-1' AND expectation_id='exp-1' AND active`,
		).Scan(&result, &source)
		if result != "Detected" || source != "api" {
			t.Fatalf("result=%q source=%q, want Detected/api", result, source)
		}
	})
}

// TestAutoVerifyDetection_OnlyDispatchesAutoVerifyConnectors pins the filter:
// AutoVerifyDetection only fires for connectors with enabled=true AND
// auto_verify=true — mirrors TestAutoCorrelateSIEM_OnlyDispatchesEnabledAutoCorrelateConfigs.
func TestAutoVerifyDetection_OnlyDispatchesAutoVerifyConnectors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		h.detectVerifyConnector = func(cfg detectverify.Config) (detectverify.Connector, error) {
			return &fakeDetectConnector{}, nil
		}

		sc := &scenario.Scenario{
			ID: "sc-auto-1",
			Steps: []scenario.Step{
				{
					Name: "step1", TechniqueID: "T1059.001",
					ExpectedDetections: []scenario.ExpectedDetection{
						{ID: "exp-auto-1", Provider: "microsoft_sentinel", Verification: scenario.VerificationAPI, Confidence: scenario.ConfidenceRequired},
					},
				},
			},
		}
		if err := h.engine.Save(sc); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}

		mustCreateConnector := func(name string, enabled, autoVerify bool) {
			rec := httptest.NewRecorder()
			h.CreateDetectionConnector(rec, detectverifyConfigReq(map[string]any{
				"name": name, "provider": "microsoft_sentinel", "enabled": enabled, "autoVerify": autoVerify,
				"verifyDelaySeconds": 1,
			}))
			if rec.Code != http.StatusOK {
				t.Fatalf("create %s: status = %d", name, rec.Code)
			}
		}
		mustCreateConnector("auto-on", true, true)   // should fire
		mustCreateConnector("auto-off", true, false) // manual only — skipped
		mustCreateConnector("disabled", false, true) // disabled — skipped

		results := []models.SimulationResult{
			{Technique: models.AttackTechnique{ID: "T1059.001"}, Result: models.ResultFail, ExecutedAt: time.Now(), DurationMs: 1000},
		}
		seedRunForVerification(t, pool, "run-auto-1", "sc-auto-1", "agent-auto-1", "HOST1", results)

		h.AutoVerifyDetection("run-auto-1")

		deadline := time.Now().Add(8 * time.Second)
		var n int
		for time.Now().Before(deadline) {
			pool.QueryRow(context.Background(),
				`SELECT COUNT(*) FROM verification_history WHERE run_id='run-auto-1'`).Scan(&n)
			if n > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if n != 1 {
			t.Fatalf("verification_history rows for run-auto-1 = %d, want exactly 1 (only auto-on should fire)", n)
		}
	})
}
```

Add `"encoding/json"` to the test file's import block (used by `seedRunForVerification` above):

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/jackc/pgx/v5/pgxpool"
)
```

- [ ] **Step 6: Run the RBAC drift test and the new tests**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRBACMatrix_NoDrift|TestTriggerDetectionVerification_EndToEnd|TestAutoVerifyDetection_OnlyDispatchesAutoVerifyConnectors' -v`
Expected: all PASS. `TestRBACMatrix_NoDrift` confirms the new routes are both registered in `routes.go` and present in the hand-maintained `routeMatrix` table.

- [ ] **Step 7: Format, build, vet, commit**

```bash
cd orchestrator
gofmt -l internal/api
go build ./...
go vet ./internal/api/...
git add internal/api/detectverify_handlers.go internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/detectverify_trigger_test.go
git commit -m "feat(api): add detection verification trigger, auto-verify wiring, and routes"
git push
```

---

### Task 9: Full validation and final push

**Files:** none (validation only).

- [ ] **Step 1: Format check across the whole module**

Run: `cd orchestrator && gofmt -l .`
Expected: no output (nothing unformatted).

- [ ] **Step 2: Build**

Run: `cd orchestrator && go build ./...`
Expected: exits 0.

- [ ] **Step 3: Vet**

Run: `cd orchestrator && go vet ./...`
Expected: exits 0, no output.

- [ ] **Step 4: Staticcheck**

Run: `cd orchestrator && staticcheck ./internal/detectverify/... ./internal/api/... ./internal/db/...`
Expected: exits 0, no findings (or only pre-existing findings unrelated to this change — do not fix unrelated findings per the project's minimal-changes convention).

- [ ] **Step 5: Full test suite**

Run: `cd orchestrator && go test ./... 2>&1 | tee /tmp/detectverify-full-test.log; tail -20 /tmp/detectverify-full-test.log`
Expected: every package reports `ok`; no `FAIL` lines. (Per project convention, verify pass/fail from the log content itself, not the exit code of `tail`.)

- [ ] **Step 6: Scoped stress run on the new tests**

Run:
```bash
cd orchestrator
go test ./internal/detectverify/... -count=10 -run 'TestMatchAlerts|TestContainsTechnique|TestEntraTokenSource|TestSentinel|TestDefenderXDR|TestNewConnector|TestVerifyRun' -v 2>&1 | tee /tmp/detectverify-stress.log
grep -c '^--- FAIL' /tmp/detectverify-stress.log
tail -5 /tmp/detectverify-stress.log
```
Expected: `grep -c` prints `0`; log ends with `ok`.

Run:
```bash
cd orchestrator
go test ./internal/api/... -count=10 -run 'TestListDetectionConnectors|TestCreateDetectionConnector|TestUpdateDetectionConnector|TestDeleteDetectionConnector|TestTestDetectionConnector|TestTriggerDetectionVerification_EndToEnd|TestAutoVerifyDetection_OnlyDispatchesAutoVerifyConnectors' -v 2>&1 | tee /tmp/detectverify-api-stress.log
grep -c '^--- FAIL' /tmp/detectverify-api-stress.log
tail -5 /tmp/detectverify-api-stress.log
```
Expected: `grep -c` prints `0`; log ends with `ok`. (Do not run `-count=10` over the whole `internal/api` package — it will hit `go test`'s 10-minute per-package timeout and produce a false FAIL; scope with `-run` as shown.)

- [ ] **Step 7: Confirm everything is pushed**

Run: `cd orchestrator && git status && git log --oneline -10`
Expected: working tree clean, and the 8 feature commits from Tasks 1–8 are visible and already pushed (each task pushed individually — this is a final confirmation, not a new push).

---

## Self-Review

**Spec coverage:**
- Architecture (new `internal/detectverify` package, `internal/siem` untouched) → Tasks 1–5.
- Data model (`detection_connectors` table) → Task 6.
- Data flow (trigger → resolve → connector → Attest → evidence) → Task 5 (`VerifyRun`) + Task 8 (DB wiring).
- Matching logic (host+window+technique, high/medium confidence) → Task 1 (`match.go`).
- Verdict gating (Detected→Approved, NotDetected→NeedsReview) → Task 5, pinned by `TestVerifyRun_DetectedVerdict_...` / `TestVerifyRun_NotDetectedVerdict_...`.
- Trigger model (on-demand endpoint; auto with per-connector delay) → Task 8 (`TriggerDetectionVerification`, `AutoVerifyDetection`).
- Error handling (connector error → no attestation) → Task 5, pinned by `TestVerifyRun_ConnectorError_NoAttestationWritten`.
- Testing plan (httptest-mocked connectors, container-backed orchestration/CRUD) → Tasks 1–8 each carry their own tests as specified.
- Out of scope items (other vendors, `RuleName` pinning, `internal/siem` changes) → correctly not touched anywhere in this plan.

**Placeholder scan:** no TBD/TODO; every step has complete, runnable code and exact commands.

**Type consistency:** `VerifyRequest`/`VerifyResult`/`MatchedAlert`/`Connector`/`Config` (Task 1) are used identically in Tasks 3, 4, 5, 7, 8. `VerifyRunParams`/`VerifyRunSummary`/`ScenarioResolver`/`Store` (Task 5) match their construction in Task 8's `runDetectionVerification`/`runDetectionVerificationForConnector`. `h.detectVerifyConnector`/`h.buildDetectConnector`/`h.loadDetectionConnector` (Task 7) are reused unchanged in Task 8.
