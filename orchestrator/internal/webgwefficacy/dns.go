package webgwefficacy

import (
	"fmt"
	"time"
)

// DNSQueryExpectation is a declared "this domain's resolution should
// be blocked/allowed by the gateway's own DNS policy" claim -- domain
// 07's own axis, structurally distinct from HTTPExpectation's
// allow/block policy action: a DNS resolution has no URL and no TLS
// to inspect, the same reasoning that gave TLS inspection its own
// TLSInspectionExpectation rather than overloading HTTPExpectation.
type DNSQueryExpectation struct {
	QueryDomain    string                `json:"queryDomain"`
	ThreatCategory string                `json:"threatCategory,omitempty"`
	ExpectedAction ExpectedGatewayAction `json:"expectedAction"`
	ControlProduct string                `json:"controlProduct"`
	Note           string                `json:"note,omitempty"`
}

// DNSResolutionEvidence is one normalized record of how the gateway's
// own DNS policy actually resolved a specific domain. Action is a
// plain string (e.g. "block"/"allow") compared case-sensitively
// against DNSQueryExpectation.ExpectedAction -- matching
// VerifyHTTPExpectation's own established discipline that an
// action-case mismatch is a real mismatch, never silently normalized
// away.
type DNSResolutionEvidence struct {
	QueryDomain    string         `json:"queryDomain"`
	Action         string         `json:"action"`
	ThreatCategory string         `json:"threatCategory,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
	Source         EvidenceSource `json:"source"`
}

// DNSResolutionEvidenceProvider supplies DNS-resolution-policy
// evidence for a queried domain and time window. A returned error
// means collection failed -- distinct from a successful search that
// found nothing.
type DNSResolutionEvidenceProvider interface {
	DNSResolutionEvidenceFor(queryDomain string, window TimeWindow) ([]DNSResolutionEvidence, error)
}

// FixtureDNSResolutionProvider wraps an in-memory slice of hand-built
// DNSResolutionEvidence values -- no real DNS resolver log is queried
// in this phase.
type FixtureDNSResolutionProvider struct {
	events []DNSResolutionEvidence
}

func NewFixtureDNSResolutionProvider(events []DNSResolutionEvidence) *FixtureDNSResolutionProvider {
	return &FixtureDNSResolutionProvider{events: events}
}

func (p *FixtureDNSResolutionProvider) DNSResolutionEvidenceFor(queryDomain string, window TimeWindow) ([]DNSResolutionEvidence, error) {
	var out []DNSResolutionEvidence
	for _, e := range p.events {
		if e.QueryDomain != queryDomain {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyDNSQueryExpectation checks one declared DNS-query expectation
// against evidence. No evidence in the window is Inconclusive, never
// an assumed Pass or Fail -- the same discipline every other
// Verify... function in this package already follows.
func VerifyDNSQueryExpectation(
	exp DNSQueryExpectation,
	provider DNSResolutionEvidenceProvider,
	window TimeWindow,
) VerdictDetail {
	records, err := provider.DNSResolutionEvidenceFor(exp.QueryDomain, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("DNS resolution evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no DNS resolution evidence found for this domain in the window",
		}
	}
	latest := latestByTimestamp(records, func(e DNSResolutionEvidence) time.Time { return e.Timestamp })
	if latest.Action == string(exp.ExpectedAction) {
		return VerdictDetail{Verdict: VerdictPass}
	}
	return VerdictDetail{Verdict: VerdictFail, Reason: fmt.Sprintf("observed DNS resolution action %q did not match expected %q", latest.Action, exp.ExpectedAction)}
}
