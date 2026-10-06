package connector

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/contentregistry"
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

func TestDedupedTechniqueIDs_DedupesAndUppercases(t *testing.T) {
	got := dedupedTechniqueIDs([]TechniqueRef{{ID: "t1059.001"}, {ID: "T1566.001"}, {ID: "T1059.001"}})
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 deduped entries", got)
	}
	want := map[string]bool{"T1059.001": true, "T1566.001": true}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected id %q in %v", id, got)
		}
	}
}

func TestDedupedTechniqueIDs_EmptyInput(t *testing.T) {
	if got := dedupedTechniqueIDs(nil); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestGenerator_UnchangedInputsSameBytes(t *testing.T) { // Review Focus 3
	g := NewGenerator(t.TempDir(), nil, nil, nil)
	a := ThreatActor{Name: "RansomHub", Source: "misp", SourceID: "evt-1", Confidence: "high",
		LastSeen:   time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1059.001"}}}
	id := intelContentID(a.Name)
	first := g.buildYAML(a, id)
	time.Sleep(1100 * time.Millisecond)         // a wall-clock timestamp in the YAML would now differ
	a.LastSeen = a.LastSeen.Add(24 * time.Hour) // last-seen churn alone must not change bytes
	if second := g.buildYAML(a, id); first != second {
		t.Fatalf("YAML must be deterministic for unchanged techniques/confidence:\n%s\n---\n%s", first, second)
	}
}

func TestIntelContentID_StablePerActor(t *testing.T) {
	if intelContentID("RansomHub") != intelContentID(" ransomhub ") {
		t.Fatal("content id must depend on the normalized actor name only")
	}
	if intelContentID("RansomHub") == intelContentID("Akira") {
		t.Fatal("different actors must not collide")
	}
}

type recRegistrar struct {
	got []contentregistry.GeneratedCandidate
}

func (r *recRegistrar) RegisterGenerated(_ context.Context, c contentregistry.GeneratedCandidate) (string, bool, error) {
	r.got = append(r.got, c)
	return "v", true, nil
}

func TestGenerator_WriteRegistersAndRewritesWorkingCopy(t *testing.T) { // A2 generator half
	dir := t.TempDir()
	rec := &recRegistrar{}
	g := NewGenerator(dir, nil, nil, nil).WithRegistrar(rec)
	a := ThreatActor{Name: "Akira", Source: "opencti", SourceID: "x", Confidence: "medium",
		Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083"}}}
	r1, err := g.Write([]ThreatActor{a})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Changed != 1 {
		t.Fatalf("first write must report a changed working copy: %+v", r1)
	}
	r2, err := g.Write([]ThreatActor{a}) // second sync: still registers; registry dedups
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed != 0 {
		t.Fatalf("unchanged working copy must not report Changed: %+v", r2)
	}
	if len(rec.got) != 2 || rec.got[0].GenerationKey != rec.got[1].GenerationKey ||
		string(rec.got[0].Artifact) != string(rec.got[1].Artifact) {
		t.Fatalf("same inputs must yield same key and bytes: %+v", rec.got)
	}
	if rec.got[0].ContentID != intelContentID("Akira") || rec.got[0].Sources[0].Role != "primary" {
		t.Fatalf("candidate: %+v", rec.got[0])
	}
	if _, err := os.Stat(filepath.Join(dir, "intel", intelContentID("Akira")+".yaml")); err != nil {
		t.Fatalf("working copy: %v", err)
	}
}

type failRegistrar struct{}

func (failRegistrar) RegisterGenerated(context.Context, contentregistry.GeneratedCandidate) (string, bool, error) {
	return "", false, errors.New("boom")
}

func TestGenerator_RegistrationFailureWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerator(dir, nil, nil, nil).WithRegistrar(failRegistrar{})
	a := ThreatActor{Name: "Akira", Source: "opencti", SourceID: "x", Confidence: "medium",
		Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083"}}}
	res, err := g.Write([]ThreatActor{a})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 || res.Changed != 0 || res.Created != 0 {
		t.Fatalf("result: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "intel", intelContentID("Akira")+".yaml")); !os.IsNotExist(err) {
		t.Fatalf("file must not exist after a failed registration: %v", err)
	}
}

func TestDeriveMITREPhases_DeterministicRegardlessOfOrder(t *testing.T) {
	techs := []TechniqueRef{
		{ID: "T1082"}, {ID: "T1059"}, {ID: "T9001", Tactic: "zeta-unknown"},
		{ID: "T9002", Tactic: "alpha-unknown"}, {ID: "T1486"},
	}
	want := strings.Join(deriveMITREPhases(techs), ",")
	for i := 0; i < 20; i++ {
		shuffled := append([]TechniqueRef(nil), techs...)
		rand.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if got := strings.Join(deriveMITREPhases(shuffled), ","); got != want {
			t.Fatalf("order-dependent phases: %s vs %s", got, want)
		}
	}
}
