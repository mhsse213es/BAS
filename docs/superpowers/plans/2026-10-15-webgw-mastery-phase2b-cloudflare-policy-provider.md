# Web Gateway BAS Mastery Phase 2b (Cloudflare Gateway Policy-Correctness Provider) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `CloudflareGatewayPolicyProvider`, a real implementation of Phase 3's existing `PolicyConfigEvidenceProvider` interface that calls Cloudflare's actual, documented Gateway rules API -- proving the real HTTP request/response contract is correctly implemented, without requiring the live account access that remains blocked (`docs/webgw-mastery-qa-log.md` item #1).

**Architecture:** One new leaf file in `internal/webgwefficacy`, `cloudflare.go`, continuing the package's zero-dependency discipline. It reuses Phase 3's `PolicyConfigEvidenceProvider` interface rather than inventing a new one -- this adapter proves live **policy-configuration correctness** (is the real Cloudflare rule's `action` what we declared it should be), not per-request attack-resistance evidence, which the spec amendment confirms is unavailable on the free tier without an additional paid purchase. Construction is credential-gated: one constructor takes an explicit `*http.Client`/base URL for testability (an `httptest` server standing in for Cloudflare), the other reads real credentials from the environment and errors cleanly when they're absent. A scenario test proves the real documented response shape flows correctly through the existing, unmodified `VerifyPolicyBaselineExpectation` pipeline.

**Tech Stack:** Go standard library only (`net/http`, `net/http/httptest`, `encoding/json`, `crypto/sha256`, `encoding/hex`, `fmt`, `os`, `strings`, `time`) -- no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` §2.3 (the 8 locked conditions for the Cloudflare adapter) and §3 Phase 2's "Amendment, 2026-10-15 (Phase 2b, scoped to what doesn't require account access)", committed directly beneath Phase 2a's own amendment. Executors should read both; the amendment also records the exact Cloudflare API research (sources in `docs/webgw-mastery-qa-log.md` item #2) this plan's request/response shapes are built from.

## Global Constraints

- `internal/webgwefficacy`'s production code still imports zero other `github.com/audspect/bas/...` package -- unchanged since Phase 1. Verify with `go list -deps ./internal/webgwefficacy/...` after Task 1; exactly one `github.com/audspect/bas/...` entry (itself).
- `CloudflareGatewayPolicyProvider` implements the *existing* `PolicyConfigEvidenceProvider` interface from `drift.go` (`PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error)`) -- no new interface is introduced, and this is deliberately not a `GatewayEvidenceProvider` (per-request evidence remains out of scope, confirmed blocked by cost per the spec amendment).
- A mocked (`httptest`) response never counts as proof of real enforcement in any report -- per condition #7 (§2.3), the live adapter is exercised only in the one integration test explicitly labeled and gated as such (Task 1, Step covering `TestCloudflareGatewayPolicyProvider_RealAPI_SkipsWithoutCredentials`), which must skip, never fail, when `CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_API_TOKEN` are unset.
- `Source` on every `PolicyConfigEvidence` this provider returns is `SourceLive` (`types.go`) -- this package's first real producer of that value anywhere else it has only ever been a documented-but-unused constant.
- A returned error from `PolicyConfigEvidenceFor` means collection genuinely failed (HTTP transport error, or Cloudflare's own envelope reporting `success: false`) -- distinct from a successful call that legitimately found nothing (HTTP 404, or evidence whose timestamp falls outside the requested window), which returns `(nil, nil)`, matching `FixturePolicyConfigProvider`'s own "nothing in this window is not an error" semantics (`drift.go:47-59`).

## Review Focus

1. **An HTTP transport error** (the server is unreachable, connection refused, or times out). `PolicyConfigEvidenceFor` must return a genuine error -- never silently return `(nil, nil)` as if "nothing found," which would let a network outage masquerade as "this rule has no configuration evidence" instead of "collection failed." Pinned in Task 1.
2. **An HTTP 404 response.** Must return `(nil, nil)`, not an error -- a rule that genuinely does not exist (anymore) is a legitimate negative result, not a collection failure, and forcing it through the error path would make every renamed or deleted rule look like an outage. Pinned in Task 1.
3. **A 2xx response whose envelope says `"success": false`.** Must return a descriptive error citing Cloudflare's own first error message -- Cloudflare's API can report application-level failure inside an HTTP-successful response, and treating HTTP 200 alone as success would silently swallow a real API-level rejection. Pinned in Task 1.
4. **Evidence whose timestamp falls outside the requested `TimeWindow`.** Must return `(nil, nil)`, never a record force-fit into a window it doesn't belong to -- a live snapshot taken "now" is not valid evidence for an audit window that doesn't cover now, and misreporting it as in-window would fabricate corroboration that was never actually collected. Pinned in Task 1.
5. **`NewCloudflareGatewayPolicyProviderFromEnv` called with only one of the two required env vars set** (e.g. a token present but no account ID). Must still return an error -- silently proceeding with an empty account ID would build a malformed URL and could send a real HTTP request with garbage credentials to Cloudflare's live API by accident. Pinned in Task 1.

---

### Task 1: CloudflareGatewayPolicyProvider

**Files:**
- Create: `orchestrator/internal/webgwefficacy/cloudflare.go`
- Test: `orchestrator/internal/webgwefficacy/cloudflare_test.go`

**Interfaces:**
- Consumes: `PolicyConfigEvidence{PolicyRuleID, ObservedConfigHash, StillActive, Timestamp, Source}`, `PolicyConfigEvidenceProvider` interface, `inWindow(t time.Time, window TimeWindow) bool` (all `drift.go`/`providers.go`, Phase 3, unmodified); `TimeWindow{Start, End time.Time}`, `SourceLive EvidenceSource` (`types.go`, Phase 1, unmodified).
- Produces: `CloudflareGatewayPolicyProvider` (implements `PolicyConfigEvidenceProvider`), `NewCloudflareGatewayPolicyProvider(httpClient *http.Client, baseURL, accountID, apiToken string) *CloudflareGatewayPolicyProvider`, `NewCloudflareGatewayPolicyProviderFromEnv() (*CloudflareGatewayPolicyProvider, error)`, and the unexported `cloudflareGatewayRule{ID, Name, Action string, Filters []string, Traffic string, Enabled bool}` and `configHashFor(rule cloudflareGatewayRule) string` -- Task 2's scenario test calls `NewCloudflareGatewayPolicyProvider`, `configHashFor`, and constructs a `cloudflareGatewayRule` literal directly; its exact field names are final for this plan.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func cloudflareTestServer(t *testing.T, status int, body map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if body != nil {
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Fatalf("encode test response: %v", err)
			}
		}
	}))
}

func TestCloudflareGatewayPolicyProvider_SuccessfulRuleRead_ReturnsLiveEvidence(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{
		"success": true,
		"errors":  []any{},
		"result": map[string]any{
			"id":      "block-malware-category",
			"name":    "Block malware category",
			"action":  "block",
			"filters": []string{"http"},
			"traffic": `http.request.uri.category == "malware"`,
			"enabled": true,
		},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	records, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].PolicyRuleID != "block-malware-category" {
		t.Errorf("PolicyRuleID = %q, want %q", records[0].PolicyRuleID, "block-malware-category")
	}
	if !records[0].StillActive {
		t.Error("StillActive = false, want true -- the rule's enabled field was true")
	}
	if records[0].Source != SourceLive {
		t.Errorf("Source = %q, want %q -- this is the package's real live provider", records[0].Source, SourceLive)
	}
	if records[0].ObservedConfigHash == "" {
		t.Error("ObservedConfigHash is empty, want a real hash of the rule's configuration")
	}
}

func TestCloudflareGatewayPolicyProvider_RuleNotFound_ReturnsEmptyNotError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusNotFound, map[string]any{
		"success": false,
		"errors":  []any{map[string]any{"code": 1003, "message": "Not Found"}},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	records, err := provider.PolicyConfigEvidenceFor("deleted-rule", window)
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v, want nil -- a 404 is a legitimate negative result, not a collection failure", err)
	}
	if records != nil {
		t.Errorf("records = %v, want nil", records)
	}
}

func TestCloudflareGatewayPolicyProvider_SuccessFalseEnvelope_ReturnsDescriptiveError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{
		"success": false,
		"errors":  []any{map[string]any{"code": 9109, "message": "Invalid access token"}},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "bad-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	_, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err == nil {
		t.Fatal("PolicyConfigEvidenceFor: want an error for a success:false envelope, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid access token") {
		t.Errorf("error = %q, want it to contain Cloudflare's own error message", err.Error())
	}
}

func TestCloudflareGatewayPolicyProvider_TransportError_ReturnsError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{"success": true, "result": map[string]any{}})
	server.Close() // closed before use -- every request now fails at the transport level

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	_, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err == nil {
		t.Fatal("PolicyConfigEvidenceFor: want an error when the server is unreachable, got nil -- a network outage must never look like \"nothing found\"")
	}
}

func TestCloudflareGatewayPolicyProvider_EvidenceOutsideWindow_ReturnsEmptyNotError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{
		"success": true,
		"errors":  []any{},
		"result": map[string]any{
			"id":      "block-malware-category",
			"action":  "block",
			"filters": []string{"http"},
			"traffic": `http.request.uri.category == "malware"`,
			"enabled": true,
		},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	past := time.Now().Add(-24 * time.Hour)
	window := TimeWindow{Start: past.Add(-time.Minute), End: past.Add(time.Minute)} // a window that does not cover "now"

	records, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v", err)
	}
	if records != nil {
		t.Errorf("records = %v, want nil -- a live snapshot taken now is not valid evidence for a window that doesn't cover now", records)
	}
}

func TestNewCloudflareGatewayPolicyProviderFromEnv_MissingAccountID_Errors(t *testing.T) {
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "some-token")

	_, err := NewCloudflareGatewayPolicyProviderFromEnv()
	if err == nil {
		t.Fatal("NewCloudflareGatewayPolicyProviderFromEnv: want an error when CLOUDFLARE_ACCOUNT_ID is unset, got nil")
	}
}

func TestNewCloudflareGatewayPolicyProviderFromEnv_MissingAPIToken_Errors(t *testing.T) {
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "some-account")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")

	_, err := NewCloudflareGatewayPolicyProviderFromEnv()
	if err == nil {
		t.Fatal("NewCloudflareGatewayPolicyProviderFromEnv: want an error when CLOUDFLARE_API_TOKEN is unset, got nil")
	}
}

func TestCloudflareGatewayPolicyProvider_RealAPI_SkipsWithoutCredentials(t *testing.T) {
	provider, err := NewCloudflareGatewayPolicyProviderFromEnv()
	if err != nil {
		t.Skipf("skipping real Cloudflare API integration test: %v (set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN to run it for real)", err)
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	ruleID := os.Getenv("CLOUDFLARE_TEST_GATEWAY_RULE_ID")
	if ruleID == "" {
		t.Skip("CLOUDFLARE_ACCOUNT_ID/CLOUDFLARE_API_TOKEN are set but CLOUDFLARE_TEST_GATEWAY_RULE_ID is not -- skipping the real call")
	}

	if _, err := provider.PolicyConfigEvidenceFor(ruleID, window); err != nil {
		t.Fatalf("real Cloudflare Gateway rules API call failed: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run "TestCloudflareGatewayPolicyProvider|TestNewCloudflareGatewayPolicyProviderFromEnv" -v`
Expected: FAIL -- `undefined: NewCloudflareGatewayPolicyProvider` (and related symbols).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// CloudflareGatewayPolicyProvider implements PolicyConfigEvidenceProvider
// (drift.go) against Cloudflare's real, documented Zero Trust Gateway
// rules API -- https://developers.cloudflare.com/api/operations/zero-trust-gateway-rules-create-zero-trust-gateway-rule.
// It is deliberately not a GatewayEvidenceProvider: per the architecture
// spec's Phase 2b amendment, per-request attack-resistance evidence is
// confirmed unavailable on the free tier (Logpush for Zero Trust Gateway
// logs is Enterprise-only; Log Explorer has no free tier or trial at any
// plan level). This provider proves live POLICY-CONFIGURATION
// correctness only -- whether a rule's real, currently-configured action
// matches what was declared -- which the free-tier gateway/rules API
// does support.
type CloudflareGatewayPolicyProvider struct {
	httpClient *http.Client
	baseURL    string
	accountID  string
	apiToken   string
}

// NewCloudflareGatewayPolicyProvider takes an explicit HTTP client and
// base URL so tests can inject an httptest server in place of
// Cloudflare's real API host.
func NewCloudflareGatewayPolicyProvider(httpClient *http.Client, baseURL, accountID, apiToken string) *CloudflareGatewayPolicyProvider {
	return &CloudflareGatewayPolicyProvider{
		httpClient: httpClient,
		baseURL:    baseURL,
		accountID:  accountID,
		apiToken:   apiToken,
	}
}

// NewCloudflareGatewayPolicyProviderFromEnv reads real Cloudflare
// credentials from the environment. It errors cleanly when either is
// unset rather than silently constructing a provider that would send a
// malformed request to Cloudflare's live API.
func NewCloudflareGatewayPolicyProviderFromEnv() (*CloudflareGatewayPolicyProvider, error) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if accountID == "" {
		return nil, fmt.Errorf("CLOUDFLARE_ACCOUNT_ID is not set")
	}
	if apiToken == "" {
		return nil, fmt.Errorf("CLOUDFLARE_API_TOKEN is not set")
	}
	return NewCloudflareGatewayPolicyProvider(http.DefaultClient, "https://api.cloudflare.com/client/v4", accountID, apiToken), nil
}

// cloudflareAPIError mirrors one entry of Cloudflare's documented
// envelope error array.
type cloudflareAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cloudflareGatewayRule mirrors the fields of Cloudflare's documented
// GatewayRule result schema this provider actually uses.
type cloudflareGatewayRule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Action  string   `json:"action"`
	Filters []string `json:"filters"`
	Traffic string   `json:"traffic"`
	Enabled bool     `json:"enabled"`
}

// cloudflareGatewayRuleEnvelope mirrors Cloudflare's own documented API
// v4 response envelope (success/errors/result) for a single Gateway
// rule.
type cloudflareGatewayRuleEnvelope struct {
	Success bool                  `json:"success"`
	Errors  []cloudflareAPIError  `json:"errors"`
	Result  cloudflareGatewayRule `json:"result"`
}

// configHashFor computes a deterministic hash over the fields of a
// Cloudflare Gateway rule that constitute its enforced behavior --
// action, filters, and the traffic-matching expression. Name,
// description, and ID are deliberately excluded: they don't change what
// the rule does.
func configHashFor(rule cloudflareGatewayRule) string {
	canonical := fmt.Sprintf("action=%s|filters=%s|traffic=%s", rule.Action, strings.Join(rule.Filters, ","), rule.Traffic)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// PolicyConfigEvidenceFor calls Cloudflare's real gateway/rules API for
// the given rule ID. An HTTP transport error or a 2xx response whose
// envelope reports success:false both return a genuine error --
// collection failed. An HTTP 404, or evidence whose timestamp falls
// outside window, both return (nil, nil) -- a legitimate "nothing here",
// never an error, matching FixturePolicyConfigProvider's own semantics.
func (p *CloudflareGatewayPolicyProvider) PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error) {
	url := fmt.Sprintf("%s/accounts/%s/gateway/rules/%s", p.baseURL, p.accountID, policyRuleID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build Cloudflare Gateway rule request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call Cloudflare Gateway rules API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	var envelope cloudflareGatewayRuleEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode Cloudflare Gateway rule response: %w", err)
	}
	if !envelope.Success {
		reason := "unknown error"
		if len(envelope.Errors) > 0 {
			reason = envelope.Errors[0].Message
		}
		return nil, fmt.Errorf("Cloudflare Gateway rules API returned an error: %s", reason)
	}

	now := time.Now()
	if !inWindow(now, window) {
		return nil, nil
	}

	return []PolicyConfigEvidence{
		{
			PolicyRuleID:       policyRuleID,
			ObservedConfigHash: configHashFor(envelope.Result),
			StillActive:        envelope.Result.Enabled,
			Timestamp:          now,
			Source:             SourceLive,
		},
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test in the package including Task 1's new ones. `TestCloudflareGatewayPolicyProvider_RealAPI_SkipsWithoutCredentials` reports `SKIP`, not `PASS` or `FAIL` -- confirm the output actually shows `--- SKIP`, since a silent pass here would hide a broken skip condition.

- [ ] **Step 5: Verify the zero-import-dependency constraint still holds**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/cloudflare.go internal/webgwefficacy/cloudflare_test.go
git commit -m "feat(webgwefficacy): add CloudflareGatewayPolicyProvider against Cloudflare's real, documented rules API

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Policy-correctness scenario, proven through the real response shape

**Files:**
- Modify: `orchestrator/internal/webgwefficacy/scenarios_test.go`

**Interfaces:**
- Consumes: `NewCloudflareGatewayPolicyProvider`, `configHashFor`, `cloudflareGatewayRule` (Task 1, `cloudflare.go`); `PolicyBaselineExpectation`, `VerifyPolicyBaselineExpectation` (Phase 3, `drift.go`, unmodified).
- Produces: nothing new -- this task adds no production code. It proves Cloudflare's real, documented response shape flows correctly through the existing, unmodified `VerifyPolicyBaselineExpectation` pipeline, the same "run the real thing through the real pipeline" proof Task 4 of the Phase 5 plan already established for mutation testing.

- [ ] **Step 1: Write the scenario test**

Append to `orchestrator/internal/webgwefficacy/scenarios_test.go`:

```go
// TestPolicyCorrectnessScenario_CloudflareRealResponseShape_FlowsThroughExistingPipeline
// proves Phase 2b's narrowed exit criterion end-to-end: a Cloudflare
// Gateway rule's real, documented response shape -- built from this
// package's own CloudflareGatewayPolicyProvider against an httptest
// server standing in for Cloudflare's live API -- flows correctly
// through Phase 3's existing, unmodified VerifyPolicyBaselineExpectation
// pipeline and resolves to a genuine Pass. Per the spec's Phase 2b
// amendment, per-request attack-resistance evidence remains unavailable
// on the free tier (Logpush is Enterprise-only; Log Explorer has no free
// tier), so this is a policy-CONFIGURATION-correctness proof, not a
// per-request one -- the scope this phase actually ships.
func TestPolicyCorrectnessScenario_CloudflareRealResponseShape_FlowsThroughExistingPipeline(t *testing.T) {
	rule := cloudflareGatewayRule{
		ID:      "block-malware-category",
		Name:    "Block malware category",
		Action:  "block",
		Filters: []string{"http"},
		Traffic: `http.request.uri.category == "malware"`,
		Enabled: true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"errors":  []any{},
			"result": map[string]any{
				"id":      rule.ID,
				"name":    rule.Name,
				"action":  rule.Action,
				"filters": rule.Filters,
				"traffic": rule.Traffic,
				"enabled": rule.Enabled,
			},
		})
	}))
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	exp := PolicyBaselineExpectation{
		PolicyRuleID:       rule.ID,
		ExpectedConfigHash: configHashFor(rule),
		ControlProduct:     "cloudflare-gateway",
	}

	result := VerifyPolicyBaselineExpectation(exp, provider, window, now)

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- Cloudflare's real documented response shape must flow correctly through the existing policy-baseline pipeline", result.Verdict, VerdictPass)
	}
}
```

- [ ] **Step 2: Add the `net/http`, `net/http/httptest`, and `encoding/json` imports to scenarios_test.go**

In `orchestrator/internal/webgwefficacy/scenarios_test.go`, update the import block:

```go
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)
```

- [ ] **Step 3: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestPolicyCorrectnessScenario -v`
Expected: PASS directly -- every piece this test calls already exists from Task 1 and Phase 3's own unmodified `VerifyPolicyBaselineExpectation`; there is no new implementation to watch fail against. Confirm the compiler has no errors and the test genuinely ran (not skipped) before proceeding.

- [ ] **Step 4: Run the full package suite**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Task 1 and Task 2 plus Phase 1 through Phase 5's full existing suite.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/scenarios_test.go
git commit -m "test(webgwefficacy): prove Cloudflare's real response shape through the existing policy-baseline pipeline

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-15-webgw-mastery-phase2b-cloudflare-policy-provider.md`.

**Native** — I implement both tasks myself in this session, then one fresh reviewer checks the whole branch at the end, matching Phase 3 and Phase 5's own execution method (both tasks here are deterministic, in-memory against `httptest`, and zero-dependency -- the same risk profile that already ran natively on this initiative).
