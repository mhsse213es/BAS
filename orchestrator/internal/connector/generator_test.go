package connector

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestBuildYAML_TagsSectorAndRegionRelevance(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"government"}, []string{"south-asia"}, nil)
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
	g := NewGenerator(t.TempDir(), []string{"financial-services"}, []string{"emea"}, nil)
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
	g := NewGenerator(t.TempDir(), nil, nil, nil)
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

func TestBuildYAML_NoDetectionProfilesWhenNoneConfigured(t *testing.T) {
	g := NewGenerator(t.TempDir(), nil, nil, nil)
	actor := ThreatActor{
		Name:       "APT29",
		Techniques: []TechniqueRef{{ID: "T1003.002"}},
	}
	yaml := g.buildYAML(actor, "jkl012")
	if strings.Contains(yaml, "detection_profiles:") {
		t.Error("did not expect detection_profiles: block when no profiles are configured -- must match pre-inheritance behavior exactly")
	}
}

func TestBuildYAML_AttachesMatchingDetectionProfile(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft": {Profile: "windows_sam_theft", TechniqueIDs: []string{"T1003.002"}},
	}
	g := NewGenerator(t.TempDir(), nil, nil, profiles)
	actor := ThreatActor{
		Name:       "APT29",
		Techniques: []TechniqueRef{{ID: "T1003.002"}},
	}
	yaml := g.buildYAML(actor, "mno345")
	if !strings.Contains(yaml, "detection_profiles:") {
		t.Fatal("expected a detection_profiles: block")
	}
	if !strings.Contains(yaml, "- windows_sam_theft") {
		t.Errorf("expected windows_sam_theft in detection_profiles:, got:\n%s", yaml)
	}
}

func TestBuildYAML_UnmatchedTechniqueGetsNoDetectionProfiles(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft": {Profile: "windows_sam_theft", TechniqueIDs: []string{"T1003.002"}},
	}
	g := NewGenerator(t.TempDir(), nil, nil, profiles)
	actor := ThreatActor{
		Name:       "SomeActor",
		Techniques: []TechniqueRef{{ID: "T9999"}}, // no profile declares this
	}
	yaml := g.buildYAML(actor, "pqr678")
	if strings.Contains(yaml, "detection_profiles:") {
		t.Errorf("did not expect detection_profiles: block for an unmatched technique, got:\n%s", yaml)
	}
}
