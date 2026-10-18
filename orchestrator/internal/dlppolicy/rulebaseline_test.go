package dlppolicy

import (
	"testing"
	"time"
)

func TestFixtureDLPPolicyRuleProvider_FiltersByRuleScopeAndWindow(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	events := []DLPPolicyRuleEvidence{
		{RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-finance", Timestamp: base, Source: SourceFixture},                      // match
		{RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-hr", Timestamp: base, Source: SourceFixture},                           // wrong scope
		{RuleID: "lab-dlp-rule-other", ScopeID: "lab-ou-finance", Timestamp: base, Source: SourceFixture},                          // wrong rule
		{RuleID: "lab-dlp-rule-pci-scope", ScopeID: "lab-ou-finance", Timestamp: base.Add(-48 * time.Hour), Source: SourceFixture}, // out of window
	}
	p := NewFixtureDLPPolicyRuleProvider(events)
	window := TimeWindow{Start: base.Add(-time.Hour), End: base.Add(time.Hour)}

	got, err := p.DLPPolicyRuleEvidenceFor("lab-dlp-rule-pci-scope", "lab-ou-finance", window)
	if err != nil {
		t.Fatalf("DLPPolicyRuleEvidenceFor: %v", err)
	}
	if len(got) != 1 || !got[0].Timestamp.Equal(base) {
		t.Fatalf("got %+v, want exactly the one matching record at %v", got, base)
	}
}

func TestFixtureDLPPolicyRuleProvider_WindowBoundaryInclusive(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	events := []DLPPolicyRuleEvidence{{RuleID: "r1", ScopeID: "s1", Timestamp: base, Source: SourceFixture}}
	p := NewFixtureDLPPolicyRuleProvider(events)

	got, err := p.DLPPolicyRuleEvidenceFor("r1", "s1", TimeWindow{Start: base, End: base})
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, err %v -- a record exactly at Start==End must still match (inclusive both ends)", got, err)
	}
}
