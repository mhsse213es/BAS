package connector

import (
	"strings"
	"testing"
)

func TestBuildYAML_TagsSectorAndRegionRelevance(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"government"}, []string{"south-asia"})
	actor := ThreatActor{
		Name:       "APT36",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "abc123")
	if !strings.Contains(yaml, "sector-relevant") {
		t.Error("expected sector-relevant tag when actor sector matches configured sector")
	}
	if !strings.Contains(yaml, "region-relevant") {
		t.Error("expected region-relevant tag when actor region matches configured region")
	}
}

func TestBuildYAML_NoTagsWhenNoOverlap(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"financial-services"}, []string{"emea"})
	actor := ThreatActor{
		Name:       "SomeOtherActor",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "def456")
	if strings.Contains(yaml, "sector-relevant") {
		t.Error("did not expect sector-relevant tag when no sector overlap")
	}
	if strings.Contains(yaml, "region-relevant") {
		t.Error("did not expect region-relevant tag when no region overlap")
	}
}

func TestBuildYAML_NoTagsWhenNotConfigured(t *testing.T) {
	g := NewGenerator(t.TempDir(), nil, nil)
	actor := ThreatActor{
		Name:       "APT36",
		Sectors:    []string{"government"},
		Regions:    []string{"south-asia"},
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1566.001"}},
	}
	yaml := g.buildYAML(actor, "ghi789")
	if strings.Contains(yaml, "sector-relevant") || strings.Contains(yaml, "region-relevant") {
		t.Error("did not expect relevance tags when deployment sector/region is unconfigured")
	}
}
