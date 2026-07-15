package exposure

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/relationships"
)

type fakeRelLookup struct {
	byTech map[string][]relationships.Relationship
}

func (f *fakeRelLookup) ForTechnique(_ context.Context, techID string) ([]relationships.Relationship, error) {
	return f.byTech[techID], nil
}

type fakeEnricher struct{ meta map[string]CVEMeta }

func (f *fakeEnricher) Enrich(_ context.Context, ids []string) (map[string]CVEMeta, error) {
	out := map[string]CVEMeta{}
	for _, id := range ids {
		if m, ok := f.meta[id]; ok {
			out[id] = m
		}
	}
	return out, nil
}

func TestCVESeverity_KEVAddsFlatBonusEvenWithoutCVSS(t *testing.T) {
	noKEV := cveSeverity(0, false, 0)
	withKEV := cveSeverity(0, true, 0)
	if noKEV != 0 {
		t.Fatalf("no CVSS/KEV/EPSS should be 0, got %v", noKEV)
	}
	if withKEV != 25 {
		t.Fatalf("KEV-only severity = %v, want 25", withKEV)
	}
}

func TestCVESeverity_MaxInputsCapAt100(t *testing.T) {
	if got := cveSeverity(10, true, 1); got != 100 {
		t.Fatalf("max severity = %v, want 100", got)
	}
}

func TestVulnerabilitiesForTechniques_FiltersInactiveAndLowConfidence(t *testing.T) {
	rels := &fakeRelLookup{byTech: map[string][]relationships.Relationship{
		"T1190": {
			{CVEID: "CVE-2024-0001", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceHigh},
			{CVEID: "CVE-2024-0002", Status: relationships.StatusDeprecated, EffectiveConfidence: relationships.ConfidenceHigh},
			{CVEID: "CVE-2024-0003", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceLow},
		},
	}}
	enricher := &fakeEnricher{meta: map[string]CVEMeta{
		"CVE-2024-0001": {CVSS: 9.8, KEV: true, EPSSScore: 0.9},
	}}

	out, err := vulnerabilitiesForTechniques(context.Background(), []string{"T1190"}, rels, enricher)
	if err != nil {
		t.Fatalf("vulnerabilitiesForTechniques: %v", err)
	}
	got := out["T1190"]
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 CVE (deprecated + low-confidence filtered out), got %+v", got)
	}
	if got[0].CVEID != "CVE-2024-0001" || got[0].Severity <= 0 {
		t.Fatalf("unexpected CVE entry: %+v", got[0])
	}
}

func TestVulnerabilitiesForTechniques_NilDependenciesReturnEmpty(t *testing.T) {
	out, err := vulnerabilitiesForTechniques(context.Background(), []string{"T1190"}, nil, nil)
	if err != nil {
		t.Fatalf("vulnerabilitiesForTechniques: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty map with nil deps, got %+v", out)
	}
}
