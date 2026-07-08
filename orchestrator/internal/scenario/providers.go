package scenario

import (
	"strings"
	"sync"
)

// Provider Registry — the single place that knows about security vendors.
//
// Expected detections reference a provider by key (e.g. "microsoft_defender").
// The registry resolves that key to a display name, product category, default
// validation-matrix domain, and default verifier. Engine and report code look
// providers up here instead of hardcoding `if provider == "defender"`, so adding
// a vendor is one RegisterProvider call and nothing else changes.

// Provider describes one security product/control source.
type Provider struct {
	Key           string // registry key used in YAML, e.g. "microsoft_defender"
	DisplayName   string // human label, e.g. "Microsoft Defender"
	Category      string // product class: EDR|SIEM|DLP|AV|IDP|CASB|RULESET
	DefaultDomain string // validation-matrix domain when the expectation omits Type
	Verifier      string // default verification model when the expectation omits it
}

var (
	providerMu       sync.RWMutex
	providerRegistry = map[string]Provider{}
)

// RegisterProvider adds or replaces a provider in the registry. Keys are
// lowercased so lookups are case-insensitive.
func RegisterProvider(p Provider) {
	providerMu.Lock()
	defer providerMu.Unlock()
	providerRegistry[strings.ToLower(p.Key)] = p
}

// LookupProvider resolves a provider key. Returns ok=false for unknown keys so
// the loader can reject expectations that name a provider we don't understand.
func LookupProvider(key string) (Provider, bool) {
	providerMu.RLock()
	defer providerMu.RUnlock()
	p, ok := providerRegistry[strings.ToLower(strings.TrimSpace(key))]
	return p, ok
}

// KnownProviders returns the registered provider keys (for validation/UX).
func KnownProviders() []string {
	providerMu.RLock()
	defer providerMu.RUnlock()
	keys := make([]string, 0, len(providerRegistry))
	for k := range providerRegistry {
		keys = append(keys, k)
	}
	return keys
}

// Built-in seed table. On-host EDR/AV products default to automatic verification
// (the agent can observe their event-log detections); off-host SIEM/ruleset
// sources default to manual until an API connector exists (SP3).
func init() {
	for _, p := range []Provider{
		// ── Endpoint EDR / AV (on-host, auto-verifiable) ──────────────────────
		{Key: "microsoft_defender", DisplayName: "Microsoft Defender", Category: "EDR", DefaultDomain: DomainEndpoint, Verifier: VerificationAutomatic},
		{Key: "crowdstrike", DisplayName: "CrowdStrike Falcon", Category: "EDR", DefaultDomain: DomainEndpoint, Verifier: VerificationAutomatic},
		{Key: "sentinelone", DisplayName: "SentinelOne", Category: "EDR", DefaultDomain: DomainEndpoint, Verifier: VerificationAutomatic},
		{Key: "trellix", DisplayName: "Trellix", Category: "EDR", DefaultDomain: DomainEndpoint, Verifier: VerificationAutomatic},
		{Key: "sophos", DisplayName: "Sophos Intercept X", Category: "EDR", DefaultDomain: DomainEndpoint, Verifier: VerificationAutomatic},
		{Key: "carbon_black", DisplayName: "VMware Carbon Black", Category: "EDR", DefaultDomain: DomainEndpoint, Verifier: VerificationAutomatic},
		{Key: "cortex_xdr", DisplayName: "Palo Alto Cortex XDR", Category: "EDR", DefaultDomain: DomainEndpoint, Verifier: VerificationAutomatic},

		// ── DLP ───────────────────────────────────────────────────────────────
		{Key: "trellix_dlp", DisplayName: "Trellix DLP", Category: "DLP", DefaultDomain: DomainDLP, Verifier: VerificationManual},
		{Key: "microsoft_purview", DisplayName: "Microsoft Purview DLP", Category: "DLP", DefaultDomain: DomainDLP, Verifier: VerificationManual},

		// ── Identity ──────────────────────────────────────────────────────────
		{Key: "microsoft_defender_identity", DisplayName: "Microsoft Defender for Identity", Category: "IDP", DefaultDomain: DomainIdentity, Verifier: VerificationManual},
		{Key: "entra_id_protection", DisplayName: "Entra ID Protection", Category: "IDP", DefaultDomain: DomainIdentity, Verifier: VerificationManual},

		// ── SIEM / analytics (off-host, manual until connectors) ──────────────
		{Key: "microsoft_sentinel", DisplayName: "Microsoft Sentinel", Category: "SIEM", DefaultDomain: DomainSIEM, Verifier: VerificationManual},
		{Key: "splunk", DisplayName: "Splunk Enterprise Security", Category: "SIEM", DefaultDomain: DomainSIEM, Verifier: VerificationManual},
		{Key: "qradar", DisplayName: "IBM QRadar", Category: "SIEM", DefaultDomain: DomainSIEM, Verifier: VerificationManual},
		{Key: "elastic", DisplayName: "Elastic Security", Category: "SIEM", DefaultDomain: DomainSIEM, Verifier: VerificationManual},

		// ── Detection-content ruleset (not a live product; documentation) ─────
		{Key: "sigma", DisplayName: "Sigma Rule", Category: "RULESET", DefaultDomain: DomainSIEM, Verifier: VerificationManual},
	} {
		RegisterProvider(p)
	}
}

// ResolveDomain returns the domain for an expectation: its explicit Type, else
// the provider's DefaultDomain, else "endpoint".
func ResolveDomain(exp ExpectedDetection) string {
	if exp.Type != "" {
		return exp.Type
	}
	if p, ok := LookupProvider(exp.Provider); ok && p.DefaultDomain != "" {
		return p.DefaultDomain
	}
	return DomainEndpoint
}

// ResolveVerification returns the verification model for an expectation: its
// explicit Verification, else the provider's default, else manual (safe: never
// auto-scores something we can't actually verify).
func ResolveVerification(exp ExpectedDetection) string {
	if exp.Verification != "" {
		return exp.Verification
	}
	if p, ok := LookupProvider(exp.Provider); ok && p.Verifier != "" {
		return p.Verifier
	}
	return VerificationManual
}
