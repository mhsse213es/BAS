package webgwefficacy

import (
	"fmt"
	"time"
)

// TLSInspectionExpectation is a declared "should this HTTPS request
// have been TLS-inspected" claim -- orthogonal to HTTPExpectation's
// allow/block policy action. A request can be allowed and inspected,
// allowed and bypassed, or blocked either way; this type exists
// because policy action and inspection depth are independent claims
// that must never be inferred from one another.
type TLSInspectionExpectation struct {
	RequestURL        string `json:"requestUrl"`
	ExpectedInspected bool   `json:"expectedInspected"`
	ControlProduct    string `json:"controlProduct"`
	Note              string `json:"note,omitempty"`
}

// TLSInspectionEvidence is one normalized record of whether a
// specific request was actually decrypted and re-inspected by the
// gateway, however it was obtained.
type TLSInspectionEvidence struct {
	RequestURL   string         `json:"requestUrl"`
	WasInspected bool           `json:"wasInspected"`
	CertIssuer   string         `json:"certIssuer,omitempty"`
	Timestamp    time.Time      `json:"timestamp"`
	Source       EvidenceSource `json:"source"`
}

// TLSInspectionEvidenceProvider supplies TLS-inspection evidence for
// a request URL and time window. A returned error means collection
// failed -- distinct from a successful search that found nothing.
type TLSInspectionEvidenceProvider interface {
	TLSInspectionEvidenceFor(requestURL string, window TimeWindow) ([]TLSInspectionEvidence, error)
}

// FixtureTLSInspectionProvider wraps an in-memory slice of hand-built
// TLSInspectionEvidence values -- no real certificate-chain
// inspection happens in this phase.
type FixtureTLSInspectionProvider struct {
	events []TLSInspectionEvidence
}

func NewFixtureTLSInspectionProvider(events []TLSInspectionEvidence) *FixtureTLSInspectionProvider {
	return &FixtureTLSInspectionProvider{events: events}
}

func (p *FixtureTLSInspectionProvider) TLSInspectionEvidenceFor(requestURL string, window TimeWindow) ([]TLSInspectionEvidence, error) {
	var out []TLSInspectionEvidence
	for _, e := range p.events {
		if e.RequestURL != requestURL {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyTLSInspectionExpectation checks one declared TLS-inspection
// expectation against evidence. Never infers successful inspection
// merely because a request succeeded -- the evidence must say so
// explicitly, or the result is Inconclusive.
func VerifyTLSInspectionExpectation(
	exp TLSInspectionExpectation,
	provider TLSInspectionEvidenceProvider,
	window TimeWindow,
) VerdictDetail {
	records, err := provider.TLSInspectionEvidenceFor(exp.RequestURL, window)
	if err != nil {
		return VerdictDetail{Verdict: VerdictInconclusive, Reason: fmt.Sprintf("TLS inspection evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return VerdictDetail{
			Verdict: VerdictInconclusive,
			Reason:  "no TLS inspection evidence found for this request in the window; absence of evidence is not proof of inspection or bypass",
		}
	}
	latest := latestByTimestamp(records, func(e TLSInspectionEvidence) time.Time { return e.Timestamp })
	if latest.WasInspected == exp.ExpectedInspected {
		return VerdictDetail{Verdict: VerdictPass}
	}
	return VerdictDetail{Verdict: VerdictFail, Reason: "observed inspection state did not match expectation"}
}
