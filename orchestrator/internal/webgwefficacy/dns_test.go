package webgwefficacy

import (
	"errors"
	"testing"
	"time"
)

type erroringDNSProvider struct{ err error }

func (p erroringDNSProvider) DNSResolutionEvidenceFor(queryDomain string, window TimeWindow) ([]DNSResolutionEvidence, error) {
	return nil, p.err
}

func TestFixtureDNSResolutionProvider_FiltersByDomainAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: "c2-beacon.example", Action: "block", Timestamp: now, Source: SourceFixture},
		{QueryDomain: "other.example", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.DNSResolutionEvidenceFor("c2-beacon.example", TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("DNSResolutionEvidenceFor: %v", err)
	}
	if len(got) != 1 || got[0].Action != "block" {
		t.Fatalf("got %+v, want exactly one blocked record for the matching domain", got)
	}
}

func TestFixtureDNSResolutionProvider_OutsideWindowExcluded(t *testing.T) {
	now := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: "c2-beacon.example", Action: "block", Timestamp: now, Source: SourceFixture},
	})
	got, err := provider.DNSResolutionEvidenceFor("c2-beacon.example", TimeWindow{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("DNSResolutionEvidenceFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty -- outside the requested window", got)
	}
}

func TestVerifyDNSQueryExpectation_ActionMatchesExpectation_Pass(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ThreatCategory: "c2-dns", ExpectedAction: ExpectedBlock, ControlProduct: "cloudflare-gateway"}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "block", ThreatCategory: "c2-dns", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictPass)
	}
}

func TestVerifyDNSQueryExpectation_ActionMismatch_Fail(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ThreatCategory: "c2-dns", ExpectedAction: ExpectedBlock, ControlProduct: "cloudflare-gateway"}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "allow", ThreatCategory: "c2-dns", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- expected block but evidence shows the query was allowed through", result.Verdict, VerdictFail)
	}
}

func TestVerifyDNSQueryExpectation_ActionCaseMismatch_TreatedAsMismatchNotNormalized(t *testing.T) {
	now := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "Block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Verdict != VerdictFail {
		t.Errorf("Verdict = %q, want %q -- \"Block\" must not be silently normalized to match \"block\"", result.Verdict, VerdictFail)
	}
}

func TestVerifyDNSQueryExpectation_NoEvidence_Inconclusive(t *testing.T) {
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := NewFixtureDNSResolutionProvider(nil)
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- absence of evidence is not proof the gateway's DNS policy ran", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDNSQueryExpectation_ProviderError_Inconclusive(t *testing.T) {
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := erroringDNSProvider{err: errors.New("DNS log store unreachable")}
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{})

	if result.Verdict != VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q", result.Verdict, VerdictInconclusive)
	}
}

func TestVerifyDNSQueryExpectation_MultipleRecords_MostRecentWins(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	exp := DNSQueryExpectation{QueryDomain: "c2-beacon.example", ExpectedAction: ExpectedBlock}
	provider := NewFixtureDNSResolutionProvider([]DNSResolutionEvidence{
		{QueryDomain: exp.QueryDomain, Action: "allow", Timestamp: older, Source: SourceFixture},
		{QueryDomain: exp.QueryDomain, Action: "block", Timestamp: newer, Source: SourceFixture},
	})
	result := VerifyDNSQueryExpectation(exp, provider, TimeWindow{Start: older.Add(-time.Minute), End: newer.Add(time.Minute)})

	if result.Verdict != VerdictPass {
		t.Errorf("Verdict = %q, want %q -- the most recent record (blocked) must win over the stale earlier one (allowed)", result.Verdict, VerdictPass)
	}
}
