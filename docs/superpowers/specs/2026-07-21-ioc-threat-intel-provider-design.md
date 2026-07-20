# IOC Threat Intelligence Provider (Sub-project A) — Design

## Context

This is the first of three linked sub-projects toward automatically enriching BAS run results with external threat intelligence (LevelBLUE OTX, and later MISP/VirusTotal/etc.):

- **A (this spec):** a pluggable `Provider` interface + LevelBLUE OTX implementation, independently usable via a manual lookup endpoint.
- **B (later):** extract candidate IOCs (IPs, domains, URLs, hashes) from BAS run results and call into A.
- **C (later):** correlate B's output and surface it in scenario/campaign reports.

No IOC extraction exists anywhere in this codebase today (confirmed via search) — this spec covers only the lookup capability itself, not extraction or report wiring.

The shape of A is modeled directly on `internal/detectverify/connector.go` — a proven pattern in this codebase for "one interface, multiple vendor implementations, config-in/result-out, no DB I/O in the package itself": `Connector interface` + `Config` struct + `NewConnector(cfg) (Connector, error)` factory switching on a provider-name string. `Provider`/`NewProvider` here follow that exact shape.

**Naming note:** `internal/auth/permissions.go` already has a `"threatintel:"` permission prefix (`CanCurateThreatIntel`, `CanReviewThreatIntel`) belonging to the *existing, different* CVE↔ATT&CK Relationship Store (`internal/relationships` — internally-curated technique-CVE mappings, unrelated to external OTX lookups). To avoid the new capability reading as part of that feature, this plan uses `internal/ioc` and `ioc:lookup` instead of `threatintel`.

## OTX API grounding

Verified against `https://otx.alienvault.com`'s public API docs and a live sample response:

- Base URL: `https://otx.alienvault.com/api/v1`
- Auth: API key via `X-OTX-API-KEY` header
- Path pattern: `/indicators/{type}/{value}/general` where `{type}` ∈ `IPv4`, `domain`, `url`, `file`, `cve`
- `general` response includes `pulse_info.count`, `pulse_info.pulses[]` (each with `name`, `tags`), and `pulse_info.related.alienvault` (`adversary[]`, `malware_families[]`, `industries[]`)
- 404 means "indicator not known to OTX" — not an error condition, just a zero-pulse result

## Goal

A `Provider` interface any future threat-intel source can implement, a working OTX implementation, and a manual lookup API endpoint to exercise it end to end — usable standalone, with no dependency on IOC extraction (sub-project B) existing yet.

## Architecture

### 1. `internal/ioc` package — interface and types

New file `internal/ioc/provider.go`:

```go
package ioc

import "context"

// Provider is one threat-intelligence source's lookup client. Implementations
// do no database I/O — callers own persistence, mirroring internal/detectverify.
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

(`json` and `fmt` imports added as needed — `Result.RawResponse` uses `encoding/json.RawMessage`.)

### 2. `internal/ioc/otx.go` — OTX implementation

```go
package ioc

type otxProvider struct {
	apiKey     string
	httpClient *http.Client
}

func newOTXProvider(cfg Config) *otxProvider {
	return &otxProvider{
		apiKey:     cfg.APIKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

const otxBaseURL = "https://otx.alienvault.com/api/v1"

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
	reqURL := fmt.Sprintf("%s/indicators/%s/%s/general", otxBaseURL, otxType, url.PathEscape(value))
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

`otx.go` needs `context`, `encoding/json`, `fmt`, `io`, `net/http`, `net/url`, and `time` in its import block.

IPv6 lookups, and OTX's other sections (`reputation`, `geo`, `malware`, `passive_dns`, `whois`, `analysis`) are explicitly out of scope (see Non-goals) — `general` alone covers everything `Result` needs.

### 3. Config wiring — `config/config.go`

New field + env var, mirroring `CalderaURL`/`CALDERA_URL` exactly:

```go
OTXAPIKey string `json:"otx_api_key,omitempty"`
```

```go
if v := os.Getenv("OTX_API_KEY"); v != "" {
	cfg.OTXAPIKey = v
}
```

### 4. Server wiring — `cmd/server/main.go` + `internal/api/handlers.go`

`main.go` builds the provider once at startup (nil when `OTXAPIKey` is empty — the handler degrades gracefully, same pattern as `h.calderaURL == ""` in `GetCalderaAdversaries`):

```go
var iocProvider ioc.Provider
if cfg.OTXAPIKey != "" {
	iocProvider, _ = ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: cfg.OTXAPIKey})
}
```

`Handler` struct gains an `iocProvider ioc.Provider` field (mirrors `calderaURL`/`calderaKey`), passed in via the existing handler-construction path.

### 5. Manual lookup endpoint

`GET /api/threatintel/lookup?type={ip|domain|url|hash|cve}&value={value}`, gated by a new permission:

```go
CanLookupIOC Permission = "ioc:lookup"
```

added to `internal/auth/permissions.go` alongside the existing permission block, and to the same Analyst+Admin role tiers as `CanRunDetectionVerification`/`CanCorrelateSIEM` (viewing/looking up threat intel is an analyst action, not an admin-only one).

Route registration (`routes.go`), matching the existing per-action-permission pattern:

```go
r.With(auth.RequirePermission(auth.CanLookupIOC)).Get("/api/threatintel/lookup", h.LookupIOC)
```

Handler dispatches `type` to the matching `Provider` method:

```go
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

## Non-goals

- **No IOC extraction from run results** — sub-project B, not this spec.
- **No report/UI surfacing** — sub-project C, not this spec.
- **No caching or persistence of lookup results.** The `internal/ioc` package does no DB I/O, matching `internal/detectverify`'s discipline exactly. Caching becomes relevant once B generates real query volume — deferred until then, not designed blind now.
- **No DB-backed multi-provider config table.** Single `OTX_API_KEY` env var, one active provider. A `threat_intel_connectors`-style table (mirroring `detection_connectors`) is a natural future addition when a second provider (MISP, VirusTotal, etc.) actually gets built — not before.
- **No IPv6 support**, and no OTX sections beyond `general` (`reputation`, `geo`, `malware`, `passive_dns`, `whois`, `analysis`, `http_scans`) — `general` alone covers every field `Result` needs; the others are available on the same client if a future need arises, but nothing here builds toward them speculatively.
- **No retry/backoff logic** for OTX request failures — a single 30s-timeout attempt, matching every existing `detectverify` connector's simplicity.
- **No rate-limit handling.** OTX's public docs don't specify a rate limit; if one is hit in practice, `lookup()`'s existing "unexpected status code" error path surfaces it as a normal `502` to the caller — no special-casing until it's shown to be needed.

## Testing

- **Unit tests** for `otxProvider.lookup()`'s parsing logic, using `httptest.NewServer` to serve canned OTX-shaped JSON fixtures (a zero-pulse response, a 3-pulse response with malware families/adversary names, a 404) — asserting `Result` fields and confidence-bucket boundaries (0/1/2/3 pulses) exactly, and that a real HTTP-level 404 never surfaces as a Go `error`.
- **Unit test** for `NewProvider`: `"otx"` returns a non-nil provider and no error; an unknown provider string returns a clear error.
- **Live verification**: with a real `OTX_API_KEY` (the user's own, obtained from `otx.alienvault.com`), hit `GET /api/threatintel/lookup?type=domain&value=<a domain known to have OTX pulses>` against the dev server and confirm real pulse/malware-family/adversary data comes back, plus a lookup for an unremarkable domain returning `confidence: "unknown"`, `pulseCount: 0`.
