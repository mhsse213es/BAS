# IOC Threat Intelligence Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pluggable `ioc.Provider` interface with a working LevelBLUE OTX implementation, exercisable end to end via a manual `GET /api/threatintel/lookup` endpoint — independently useful with no dependency on IOC extraction (a later, separate sub-project) existing yet.

**Architecture:** New `internal/ioc` package, modeled directly on `internal/detectverify/connector.go`'s proven shape (`Provider interface` + `Config` + `NewProvider` factory, no DB I/O in the package). Config flows in via one env var (`OTX_API_KEY`), through `config.Config`, into a `Handler.iocProvider` field set via a new `WithIOCProvider` builder method (mirroring `WithCaldera`), gated behind a new `ioc:lookup` RBAC permission.

**Tech Stack:** Go, `net/http` (outbound OTX client), existing `internal/auth` RBAC framework.

## Global Constraints

- Package name `internal/ioc`, permission `ioc:lookup` — deliberately NOT `internal/threatintel`/`threatintel:lookup`, to avoid colliding with the existing, different CVE↔ATT&CK Relationship Store's `threatintel:curate`/`threatintel:review` permissions.
- OTX API: base URL `https://otx.alienvault.com/api/v1`, auth via `X-OTX-API-KEY` header, path pattern `/indicators/{type}/{value}/general` (types: `IPv4`, `domain`, `url`, `file`, `cve`).
- Confidence buckets: 0 pulses → `unknown`, 1-2 → `low`, 3+ → `high`.
- No DB I/O in `internal/ioc` — config in, result out, matching `internal/detectverify`'s discipline.
- No caching, no multi-provider config table, no IPv6, no OTX sections beyond `general`, no retry/backoff — all explicitly deferred (see spec's Non-goals).

---

### Task 1: `internal/ioc` package — interface, types, and OTX client

**Files:**
- Create: `orchestrator/internal/ioc/provider.go`
- Create: `orchestrator/internal/ioc/otx.go`
- Create: `orchestrator/internal/ioc/otx_test.go`

**Interfaces:**
- Produces: `ioc.Provider` interface (`LookupIP`/`LookupDomain`/`LookupURL`/`LookupHash`/`LookupCVE`, each `func(context.Context, string) (*Result, error)`), `ioc.Result` struct, `ioc.Config` struct, `ioc.NewProvider(cfg Config) (Provider, error)` — all consumed by Task 4's handler wiring.

- [ ] **Step 1: Write `provider.go`**

```go
package ioc

import (
	"context"
	"encoding/json"
	"fmt"
)

// Provider is one threat-intelligence source's lookup client. Implementations
// do no database I/O -- callers own persistence, mirroring internal/detectverify.
type Provider interface {
	LookupIP(ctx context.Context, ip string) (*Result, error)
	LookupDomain(ctx context.Context, domain string) (*Result, error)
	LookupURL(ctx context.Context, url string) (*Result, error)
	LookupHash(ctx context.Context, hash string) (*Result, error)
	LookupCVE(ctx context.Context, cveID string) (*Result, error)
}

// Result is one indicator's enrichment, normalized across providers.
type Result struct {
	Indicator       string          `json:"indicator"`
	Type            string          `json:"type"` // ip | domain | url | hash | cve
	Provider        string          `json:"provider"`
	PulseCount      int             `json:"pulseCount"`
	PulseNames      []string        `json:"pulseNames,omitempty"`
	MalwareFamilies []string        `json:"malwareFamilies,omitempty"`
	AdversaryNames  []string        `json:"adversaryNames,omitempty"`
	Industries      []string        `json:"industries,omitempty"`
	Confidence      string          `json:"confidence"` // unknown | low | high
	RawResponse     json.RawMessage `json:"raw,omitempty"`
}

// Confidence buckets, derived from pulse count -- the number of independent
// OTX community reports that reference this indicator.
const (
	ConfidenceUnknown = "unknown" // 0 pulses
	ConfidenceLow     = "low"     // 1-2 pulses
	ConfidenceHigh    = "high"    // 3+ pulses
)

// Config holds one provider's connection settings.
type Config struct {
	Provider string // "otx" (only implementation for now)
	APIKey   string
}

// NewProvider builds the Provider for cfg.Provider.
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Provider {
	case "otx":
		return newOTXProvider(cfg), nil
	default:
		return nil, fmt.Errorf("ioc: provider %q not supported", cfg.Provider)
	}
}
```

- [ ] **Step 2: Write `otx.go`**

```go
package ioc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const otxBaseURL = "https://otx.alienvault.com/api/v1"

type otxProvider struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string // overridden by tests; otxBaseURL in production
}

func newOTXProvider(cfg Config) *otxProvider {
	return &otxProvider{
		apiKey:     cfg.APIKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    otxBaseURL,
	}
}

func (p *otxProvider) LookupIP(ctx context.Context, ip string) (*Result, error) {
	return p.lookup(ctx, "IPv4", ip, "ip")
}
func (p *otxProvider) LookupDomain(ctx context.Context, domain string) (*Result, error) {
	return p.lookup(ctx, "domain", domain, "domain")
}
func (p *otxProvider) LookupURL(ctx context.Context, u string) (*Result, error) {
	return p.lookup(ctx, "url", u, "url")
}
func (p *otxProvider) LookupHash(ctx context.Context, hash string) (*Result, error) {
	return p.lookup(ctx, "file", hash, "hash")
}
func (p *otxProvider) LookupCVE(ctx context.Context, cveID string) (*Result, error) {
	return p.lookup(ctx, "cve", cveID, "cve")
}

// otxGeneralResponse mirrors the fields of OTX's /indicators/{type}/{value}/general
// response actually used by this provider -- not a full schema, just what's consumed.
type otxGeneralResponse struct {
	Indicator string `json:"indicator"`
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"pulses"`
		Related struct {
			Alienvault struct {
				Adversary       []string `json:"adversary"`
				MalwareFamilies []string `json:"malware_families"`
				Industries      []string `json:"industries"`
			} `json:"alienvault"`
		} `json:"related"`
	} `json:"pulse_info"`
}

func (p *otxProvider) lookup(ctx context.Context, otxType, value, resultType string) (*Result, error) {
	reqURL := fmt.Sprintf("%s/indicators/%s/%s/general", p.baseURL, otxType, url.PathEscape(value))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ioc/otx: build request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ioc/otx: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &Result{Indicator: value, Type: resultType, Provider: "otx", Confidence: ConfidenceUnknown}, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioc/otx: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ioc/otx: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var raw otxGeneralResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ioc/otx: parse response: %w", err)
	}

	pulseNames := make([]string, 0, len(raw.PulseInfo.Pulses))
	for _, pulse := range raw.PulseInfo.Pulses {
		pulseNames = append(pulseNames, pulse.Name)
	}

	confidence := ConfidenceUnknown
	switch {
	case raw.PulseInfo.Count >= 3:
		confidence = ConfidenceHigh
	case raw.PulseInfo.Count >= 1:
		confidence = ConfidenceLow
	}

	return &Result{
		Indicator:       value,
		Type:            resultType,
		Provider:        "otx",
		PulseCount:      raw.PulseInfo.Count,
		PulseNames:      pulseNames,
		MalwareFamilies: raw.PulseInfo.Related.Alienvault.MalwareFamilies,
		AdversaryNames:  raw.PulseInfo.Related.Alienvault.Adversary,
		Industries:      raw.PulseInfo.Related.Alienvault.Industries,
		Confidence:      confidence,
		RawResponse:     json.RawMessage(body),
	}, nil
}
```

- [ ] **Step 3: Write `otx_test.go`**

```go
package ioc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testProvider(t *testing.T, handler http.HandlerFunc) *otxProvider {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &otxProvider{
		apiKey:     "test-key",
		httpClient: http.DefaultClient,
		baseURL:    server.URL,
	}
}

func TestOTXLookup_ZeroPulses(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-OTX-API-KEY"); got != "test-key" {
			t.Errorf("X-OTX-API-KEY header = %q, want test-key", got)
		}
		w.Write([]byte(`{"indicator":"1.2.3.4","pulse_info":{"count":0,"pulses":[],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]}}}}`))
	})

	got, err := p.LookupIP(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if got.PulseCount != 0 {
		t.Errorf("PulseCount = %d, want 0", got.PulseCount)
	}
	if got.Confidence != ConfidenceUnknown {
		t.Errorf("Confidence = %q, want %q", got.Confidence, ConfidenceUnknown)
	}
	if got.Indicator != "1.2.3.4" || got.Type != "ip" || got.Provider != "otx" {
		t.Errorf("Indicator/Type/Provider = %q/%q/%q, want 1.2.3.4/ip/otx", got.Indicator, got.Type, got.Provider)
	}
}

func TestOTXLookup_ThreePulses_HighConfidence(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"indicator":"evil.example.com","pulse_info":{"count":3,"pulses":[{"name":"Emotet Campaign","tags":["emotet"]},{"name":"TA542 Infrastructure","tags":["ta542"]},{"name":"Banking Trojan IOCs","tags":["banking"]}],"related":{"alienvault":{"adversary":["TA542"],"malware_families":["Emotet"],"industries":["Financial Services"]}}}}`))
	})

	got, err := p.LookupDomain(context.Background(), "evil.example.com")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if got.PulseCount != 3 {
		t.Errorf("PulseCount = %d, want 3", got.PulseCount)
	}
	if got.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", got.Confidence, ConfidenceHigh)
	}
	wantPulses := []string{"Emotet Campaign", "TA542 Infrastructure", "Banking Trojan IOCs"}
	if len(got.PulseNames) != len(wantPulses) {
		t.Fatalf("PulseNames = %v, want %v", got.PulseNames, wantPulses)
	}
	for i, name := range wantPulses {
		if got.PulseNames[i] != name {
			t.Errorf("PulseNames[%d] = %q, want %q", i, got.PulseNames[i], name)
		}
	}
	if len(got.MalwareFamilies) != 1 || got.MalwareFamilies[0] != "Emotet" {
		t.Errorf("MalwareFamilies = %v, want [Emotet]", got.MalwareFamilies)
	}
	if len(got.AdversaryNames) != 1 || got.AdversaryNames[0] != "TA542" {
		t.Errorf("AdversaryNames = %v, want [TA542]", got.AdversaryNames)
	}
	if len(got.Industries) != 1 || got.Industries[0] != "Financial Services" {
		t.Errorf("Industries = %v, want [Financial Services]", got.Industries)
	}
}

func TestOTXLookup_OnePulse_LowConfidence(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"indicator":"maybe-bad.example","pulse_info":{"count":1,"pulses":[{"name":"Low Confidence Report","tags":[]}],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]}}}}`))
	})

	got, err := p.LookupDomain(context.Background(), "maybe-bad.example")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if got.Confidence != ConfidenceLow {
		t.Errorf("Confidence = %q, want %q", got.Confidence, ConfidenceLow)
	}
}

func TestOTXLookup_404_NotAnError(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	got, err := p.LookupHash(context.Background(), "deadbeef")
	if err != nil {
		t.Fatalf("LookupHash returned an error for a 404, want a zero-pulse Result: %v", err)
	}
	if got.Confidence != ConfidenceUnknown || got.PulseCount != 0 {
		t.Errorf("got %+v, want zero-pulse unknown-confidence result", got)
	}
}

func TestOTXLookup_UnexpectedStatus_ReturnsError(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})

	_, err := p.LookupCVE(context.Background(), "CVE-2024-0001")
	if err == nil {
		t.Fatal("LookupCVE with a 500 response returned no error, want one")
	}
}

func TestNewProvider_OTX(t *testing.T) {
	p, err := NewProvider(Config{Provider: "otx", APIKey: "k"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("NewProvider returned nil provider with no error")
	}
}

func TestNewProvider_UnknownProvider(t *testing.T) {
	_, err := NewProvider(Config{Provider: "not-a-real-provider"})
	if err == nil {
		t.Fatal("NewProvider with an unknown provider name returned no error")
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd orchestrator && go test ./internal/ioc/... -v
```

Expected: all 7 tests PASS (`TestOTXLookup_ZeroPulses`, `TestOTXLookup_ThreePulses_HighConfidence`, `TestOTXLookup_OnePulse_LowConfidence`, `TestOTXLookup_404_NotAnError`, `TestOTXLookup_UnexpectedStatus_ReturnsError`, `TestNewProvider_OTX`, `TestNewProvider_UnknownProvider`).

- [ ] **Step 5: `go vet`**

```bash
go vet ./internal/ioc/...
```

Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/ioc/
git commit -m "$(cat <<'EOF'
feat(ioc): add pluggable Provider interface + OTX implementation

Modeled on internal/detectverify's proven Connector shape (interface +
Config + NewProvider factory, no DB I/O in the package). LookupIP/
LookupDomain/LookupURL/LookupHash/LookupCVE all hit OTX's
/indicators/{type}/{value}/general endpoint; confidence derives from
pulse count (0=unknown, 1-2=low, 3+=high). A 404 from OTX (unknown
indicator) returns a zero-pulse Result, not a Go error.
EOF
)"
```

---

### Task 2: Config wiring — `OTX_API_KEY`

**Files:**
- Modify: `orchestrator/config/config.go`

**Interfaces:**
- Produces: `config.Config.OTXAPIKey string` — read by Task 4's `main.go` wiring.

- [ ] **Step 1: Add the field**

Current (`orchestrator/config/config.go`):

```go
	CalderaURL        string `json:"caldera_url,omitempty"`
	CalderaAPIKey     string `json:"caldera_api_key,omitempty"`
```

Becomes:

```go
	CalderaURL        string `json:"caldera_url,omitempty"`
	CalderaAPIKey     string `json:"caldera_api_key,omitempty"`
	OTXAPIKey         string `json:"otx_api_key,omitempty"`
```

- [ ] **Step 2: Read the env var**

Current (`orchestrator/config/config.go`, right after the `CALDERA_API_KEY` env read):

```go
	if v := os.Getenv("CALDERA_API_KEY"); v != "" {
		cfg.CalderaAPIKey = v
	}
```

Becomes:

```go
	if v := os.Getenv("CALDERA_API_KEY"); v != "" {
		cfg.CalderaAPIKey = v
	}
	if v := os.Getenv("OTX_API_KEY"); v != "" {
		cfg.OTXAPIKey = v
	}
```

- [ ] **Step 3: Build**

```bash
cd orchestrator && go build ./config/... && echo "BUILD_OK"
```

Expected: `BUILD_OK`.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/config/config.go
git commit -m "feat(ioc): wire OTX_API_KEY env var into config.Config"
```

---

### Task 3: RBAC — `ioc:lookup` permission

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go`
- Modify: `orchestrator/internal/auth/permissions_test.go`

**Interfaces:**
- Produces: `auth.CanLookupIOC Permission` — consumed by Task 4's route registration.

- [ ] **Step 1: Add the permission constant**

Current (`orchestrator/internal/auth/permissions.go`):

```go
	// SIEM correlation + detection verification — Analyst+Admin can trigger.
	CanCorrelateSIEM            Permission = "siem:correlate"
	CanViewSIEMCorrelations     Permission = "siem:correlations:view"
	CanRunDetectionVerification Permission = "detectverify:run"
```

Becomes:

```go
	// SIEM correlation + detection verification — Analyst+Admin can trigger.
	CanCorrelateSIEM            Permission = "siem:correlate"
	CanViewSIEMCorrelations     Permission = "siem:correlations:view"
	CanRunDetectionVerification Permission = "detectverify:run"
	CanLookupIOC                Permission = "ioc:lookup"
```

- [ ] **Step 2: Grant it to Admin**

Current (`orchestrator/internal/auth/permissions.go`, inside the `RoleAdmin` map):

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,
		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true,

		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
```

Becomes:

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,
		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,

		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
```

(This is the first occurrence of that exact block, inside `RoleAdmin`. The second, near-identical block a few lines below is inside `RoleAnalyst` — handled in the next step.)

- [ ] **Step 3: Grant it to Analyst**

Current (`orchestrator/internal/auth/permissions.go`, inside the `RoleAnalyst` map — this is the second, and last, occurrence of this exact line group):

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,
		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true,
	},
	RoleViewer: {},
```

Becomes:

```go
		CanRunDetectionVerification: true, CanCreateCampaign: true, CanStopCampaign: true,
		CanSetFindingStatus: true, CanPushToITSM: true, CanBulkPushToITSM: true,
		CanCreateScenario: true, CanUploadScenario: true, CanCloneScenario: true,
		CanUpdateScenario: true, CanDeleteScenario: true, CanGenerateVariants: true,
		CanRunVariants: true, CanViewVariantRun: true, CanViewVariantCoverage: true,
		CanViewVariantStats: true, CanListPayloadFamilies: true, CanViewPayloadFamily: true,
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
	},
	RoleViewer: {},
```

- [ ] **Step 4: Add it to `Permissions()`'s ordered list**

Current (`orchestrator/internal/auth/permissions.go`, inside `Permissions()`):

```go
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanSetFindingStatus,
		CanPushToITSM, CanBulkPushToITSM, CanCreateScenario, CanUploadScenario, CanCloneScenario,
		CanUpdateScenario, CanDeleteScenario, CanGenerateVariants, CanRunVariants, CanViewVariantRun,
		CanViewVariantCoverage, CanViewVariantStats, CanListPayloadFamilies, CanViewPayloadFamily,
		CanLaunchExerciseExecution, CanAbortExerciseExecution, CanApproveExerciseStep,
		CanInjectExerciseEvidence,
```

Becomes:

```go
		CanRunDetectionVerification, CanCreateCampaign, CanStopCampaign, CanSetFindingStatus,
		CanPushToITSM, CanBulkPushToITSM, CanCreateScenario, CanUploadScenario, CanCloneScenario,
		CanUpdateScenario, CanDeleteScenario, CanGenerateVariants, CanRunVariants, CanViewVariantRun,
		CanViewVariantCoverage, CanViewVariantStats, CanListPayloadFamilies, CanViewPayloadFamily,
		CanLaunchExerciseExecution, CanAbortExerciseExecution, CanApproveExerciseStep,
		CanInjectExerciseEvidence, CanLookupIOC,
```

- [ ] **Step 5: Build to confirm it compiles**

```bash
cd orchestrator && go build ./internal/auth/... && echo "BUILD_OK"
```

Expected: `BUILD_OK`.

- [ ] **Step 6: Update `TestHasPermission_MatrixIsComplete`'s `tested` map**

`CanLookupIOC` is now granted to Admin (Step 2), so `Permissions(RoleAdmin)` includes it — this test asserts every permission Admin holds has a row here, and that the counts match exactly.

Current (`orchestrator/internal/auth/permissions_test.go`, inside `TestHasPermission_MatrixIsComplete`'s `tested` map):

```go
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true,

		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
```

Becomes:

```go
		CanLaunchExerciseExecution: true, CanAbortExerciseExecution: true,
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,

		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
```

- [ ] **Step 7: Update `TestPermissions_Ordering`'s `want` slice**

Current (`orchestrator/internal/auth/permissions_test.go`, inside `TestPermissions_Ordering`):

```go
		CanLaunchExerciseExecution, CanAbortExerciseExecution, CanApproveExerciseStep,
		CanInjectExerciseEvidence,

		CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
```

Becomes:

```go
		CanLaunchExerciseExecution, CanAbortExerciseExecution, CanApproveExerciseStep,
		CanInjectExerciseEvidence, CanLookupIOC,

		CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
```

`TestPermissionGrants_MatchMigrationInventory`'s `groupA`/`groupB` lists are deliberately **not** touched — that test pins the exact historical inventory of the 2026-07-18 Phase 7 migration (34+51 permissions); `CanLookupIOC` is a new permission outside that migration and doesn't belong in either group.

- [ ] **Step 8: Run the full `internal/auth` test suite**

```bash
go test ./internal/auth/... -v 2>&1 | tail -40
```

Expected: all tests PASS, including `TestHasPermission_MatrixIsComplete`, `TestPermissions_Ordering`, and `TestPermissionGrants_MatchMigrationInventory` (the last one unaffected since its expected counts, 34 and 51, don't change).

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/auth/permissions.go orchestrator/internal/auth/permissions_test.go
git commit -m "$(cat <<'EOF'
feat(ioc): add ioc:lookup RBAC permission for Analyst+Admin

Granted alongside CanRunDetectionVerification/CanCorrelateSIEM --
looking up threat intel is an analyst action, not admin-only.
TestPermissionGrants_MatchMigrationInventory's groupA/groupB lists are
untouched: that test pins the exact 2026-07-18 Phase 7 migration
inventory, and this permission is new and outside that migration.
EOF
)"
```

---

### Task 4: Handler wiring, route, and live verification

**Files:**
- Modify: `orchestrator/internal/api/handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `ioc.Provider`, `ioc.NewProvider` (Task 1), `cfg.OTXAPIKey` (Task 2), `auth.CanLookupIOC` (Task 3).
- Produces: `Handler.iocProvider ioc.Provider` field, `Handler.WithIOCProvider(provider ioc.Provider) *Handler`, `Handler.LookupIOC(w http.ResponseWriter, r *http.Request)` — the route registered in this task is the end-user-visible deliverable.

- [ ] **Step 1: Add the `iocProvider` field to `Handler`**

Current (`orchestrator/internal/api/handlers.go`):

```go
	secret                string
	agentSecret           string // optional shared secret for agent-facing endpoints
	calderaURL            string
	calderaKey            string
```

Becomes:

```go
	secret                string
	agentSecret           string // optional shared secret for agent-facing endpoints
	calderaURL            string
	calderaKey            string
	iocProvider           ioc.Provider // nil when OTX_API_KEY is unset
```

Add `"github.com/audspect/bas/internal/ioc"` to `handlers.go`'s import block (alongside the other `internal/...` imports already there).

- [ ] **Step 2: Add the `WithIOCProvider` builder method**

Current (`orchestrator/internal/api/handlers.go`):

```go
func (h *Handler) WithCaldera(url, key string) *Handler {
	h.calderaURL = url
	h.calderaKey = key
	return h
}
```

Becomes:

```go
func (h *Handler) WithCaldera(url, key string) *Handler {
	h.calderaURL = url
	h.calderaKey = key
	return h
}

// WithIOCProvider attaches the threat-intel lookup provider (nil when
// OTX_API_KEY is unset -- LookupIOC degrades to a clear 503, same pattern
// as GetCalderaAdversaries when CALDERA_URL is empty).
func (h *Handler) WithIOCProvider(provider ioc.Provider) *Handler {
	h.iocProvider = provider
	return h
}
```

- [ ] **Step 3: Add the `LookupIOC` handler**

Add near `GetCalderaAdversaries` in `orchestrator/internal/api/handlers.go` (same file, for proximity to a similar external-lookup handler):

```go
// GET /api/threatintel/lookup?type={ip|domain|url|hash|cve}&value={value}
func (h *Handler) LookupIOC(w http.ResponseWriter, r *http.Request) {
	if h.iocProvider == nil {
		jsonError(w, "threat intel not configured — set OTX_API_KEY and restart", http.StatusServiceUnavailable)
		return
	}
	iocType := r.URL.Query().Get("type")
	value := r.URL.Query().Get("value")
	if value == "" {
		jsonError(w, "value is required", http.StatusBadRequest)
		return
	}

	var (
		result *ioc.Result
		err    error
	)
	switch iocType {
	case "ip":
		result, err = h.iocProvider.LookupIP(r.Context(), value)
	case "domain":
		result, err = h.iocProvider.LookupDomain(r.Context(), value)
	case "url":
		result, err = h.iocProvider.LookupURL(r.Context(), value)
	case "hash":
		result, err = h.iocProvider.LookupHash(r.Context(), value)
	case "cve":
		result, err = h.iocProvider.LookupCVE(r.Context(), value)
	default:
		jsonError(w, "type must be one of: ip, domain, url, hash, cve", http.StatusBadRequest)
		return
	}
	if err != nil {
		jsonError(w, "lookup failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	respond(w, result)
}
```

- [ ] **Step 4: Register the route**

Current (`orchestrator/internal/api/routes.go`):

```go
		r.With(auth.RequirePermission(auth.CanRunDetectionVerification)).Post("/api/detectverify/run/{runId}", h.TriggerDetectionVerification)
```

Becomes:

```go
		r.With(auth.RequirePermission(auth.CanRunDetectionVerification)).Post("/api/detectverify/run/{runId}", h.TriggerDetectionVerification)
		r.With(auth.RequirePermission(auth.CanLookupIOC)).Get("/api/threatintel/lookup", h.LookupIOC)
```

- [ ] **Step 5: Wire it up in `main.go`**

Current (`orchestrator/cmd/server/main.go`):

```go
	handler := api.New(pool, hub, engine, cfg.JWTSecret).
		WithCaldera(cfg.CalderaURL, cfg.CalderaAPIKey).
```

Becomes:

```go
	var iocProvider ioc.Provider
	if cfg.OTXAPIKey != "" {
		var err error
		iocProvider, err = ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: cfg.OTXAPIKey})
		if err != nil {
			log.Printf("[!] ioc provider init warning: %v", err)
		} else {
			log.Println("[+] IOC threat-intel provider ready (OTX)")
		}
	}

	handler := api.New(pool, hub, engine, cfg.JWTSecret).
		WithCaldera(cfg.CalderaURL, cfg.CalderaAPIKey).
```

And add `.WithIOCProvider(iocProvider)` to the end of the existing builder chain:

Current:

```go
		WithVerificationStore(verificationStore).
		WithRelationshipStore(relationshipStore).
		WithRuleLibrary(rulesEngine)
```

Becomes:

```go
		WithVerificationStore(verificationStore).
		WithRelationshipStore(relationshipStore).
		WithRuleLibrary(rulesEngine).
		WithIOCProvider(iocProvider)
```

Add `"github.com/audspect/bas/internal/ioc"` to `main.go`'s import block.

- [ ] **Step 6: Build and vet the whole orchestrator**

```bash
cd orchestrator
go build ./... && echo "BUILD_OK"
go vet ./... && echo "VET_OK"
```

Expected: `BUILD_OK`, `VET_OK`.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/cmd/server/main.go
git commit -m "$(cat <<'EOF'
feat(ioc): wire the OTX-backed lookup endpoint into the server

GET /api/threatintel/lookup?type=&value=, gated by ioc:lookup. Handler
degrades to a clear 503 when OTX_API_KEY is unset -- same pattern as
GetCalderaAdversaries when CALDERA_URL is empty, no crash either way.
EOF
)"
```

- [ ] **Step 8: Live-verify without an API key (degrade path)**

```bash
docker rm -f bas-ioc-smoke-pg >/dev/null 2>&1
docker run -d --name bas-ioc-smoke-pg -e POSTGRES_PASSWORD=devpass -e POSTGRES_DB=bas -p 55434:5432 postgres:16-alpine >/dev/null
for i in $(seq 1 20); do docker exec bas-ioc-smoke-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
cd orchestrator
(DATABASE_URL="postgres://postgres:devpass@localhost:55434/bas?sslmode=disable" JWT_SECRET="dev-smoke-secret-01234567890123456789012345678901" BAS_LICENSE_PATH="../audspect-dev.lic" HTTP_PORT=9093 nohup go run ./cmd/server > /tmp/bas-ioc-smoke.log 2>&1 &)
for i in $(seq 1 30); do grep -q "listening on" /tmp/bas-ioc-smoke.log 2>/dev/null && break; sleep 1; done
TOKEN=$(curl -s -X POST http://localhost:9093/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"ChangeMe!2024"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:9093/api/threatintel/lookup?type=ip&value=8.8.8.8" -w "\nHTTP %{http_code}\n"
```

Expected: `HTTP 503` with a body like `{"error":"threat intel not configured — set OTX_API_KEY and restart"}` (no `OTX_API_KEY` was set in this launch command — confirms the degrade path from Step 3 works exactly as designed, matching the Caldera precedent it was modeled on).

- [ ] **Step 9: Live-verify with a real API key (if available)**

If a LevelBLUE OTX API key is available (obtained from `otx.alienvault.com`), restart the same server with `OTX_API_KEY=<real key>` added to the env block in Step 8, and re-run the same `curl` command. Expected: `HTTP 200` with real `pulseCount`/`confidence`/etc. fields for `8.8.8.8` (a well-known, heavily-pulsed indicator). If no key is available, this step is skipped and Step 8's degrade-path verification plus Task 1's unit tests are the evidence this sub-project works — note this explicitly when reporting completion.

- [ ] **Step 10: Clean up the smoke-test environment**

```bash
powershell -Command "Get-CimInstance Win32_Process -Filter \"Name='go.exe' OR Name='server.exe'\" | Where-Object { \$_.CommandLine -like '*cmd/server*' -or \$_.Name -eq 'server.exe' } | Select-Object ProcessId,Name"
```

Stop the returned process IDs (`Stop-Process -Id <id1>,<id2> -Force`), then:

```bash
docker rm -f bas-ioc-smoke-pg
```

- [ ] **Step 11: Push**

```bash
git push
```
