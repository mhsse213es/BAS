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
	// Name identifies which provider produced a Result -- used to key the
	// enrichment cache (internal/db/ioc_enrichment.go) so different providers'
	// results for the same indicator never collide.
	Name() string
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
	Tags            []string        `json:"tags,omitempty"`
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
