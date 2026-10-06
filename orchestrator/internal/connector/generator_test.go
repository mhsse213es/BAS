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
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatidentity"
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
	id := threatidentity.ContentID(a.ThreatID)
	first := g.buildYAML(a, id)
	time.Sleep(1100 * time.Millisecond)         // a wall-clock timestamp in the YAML would now differ
	a.LastSeen = a.LastSeen.Add(24 * time.Hour) // last-seen churn alone must not change bytes
	if second := g.buildYAML(a, id); first != second {
		t.Fatalf("YAML must be deterministic for unchanged techniques/confidence:\n%s\n---\n%s", first, second)
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
	a := ThreatActor{Name: "Akira", ThreatID: "thr-akira", Source: "opencti", SourceID: "x", Confidence: "medium",
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
	if rec.got[0].ContentID != threatidentity.ContentID("thr-akira") || rec.got[0].Sources[0].Role != "primary" {
		t.Fatalf("candidate: %+v", rec.got[0])
	}
	if _, err := os.Stat(filepath.Join(dir, "intel", threatidentity.ContentID("thr-akira")+".yaml")); err != nil {
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
	a := ThreatActor{Name: "Akira", ThreatID: "thr-akira", Source: "opencti", SourceID: "x", Confidence: "medium",
		Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083"}}}
	res, err := g.Write([]ThreatActor{a})
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 || res.Changed != 0 || res.Created != 0 {
		t.Fatalf("result: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "intel", threatidentity.ContentID("thr-akira")+".yaml")); !os.IsNotExist(err) {
		t.Fatalf("file must not exist after a failed registration: %v", err)
	}
}

// Final-review I3: actor fields come from external intel (MISP/OpenCTI/OTX).
// A quote, newline, anchor or leading "- " must never change the YAML's
// structure -- in particular it must not be able to inject steps.
func TestBuildYAML_ExternalFieldsCannotInjectStructure(t *testing.T) {
	hostile := []struct{ in, want string }{
		{`Evil" Actor`, `Evil" Actor`},
		{"Line1\nsteps:\n- command: evil", "Line1steps:- command: evil"},
		{"Line1\r\nsteps:\r\n  - name: x\r\n    command: evil", "Line1steps:  - name: x    command: evil"},
		{"&a *a", "&a *a"},
		{"- leading", "- leading"},
		{"nul\x00byte\x1b[31m", "nulbyte[31m"},
	}
	g := NewGenerator(t.TempDir(), []string{"x"}, nil, nil)
	for _, h := range hostile {
		a := ThreatActor{Name: h.in, Source: "misp\nsteps: [x]", SourceID: "id\"\nsteps:\n- command: evil",
			Confidence: "high\nlocal_check: true", Description: "d\"\n- command: evil",
			Sectors:    []string{"x", "fin\nsteps:\n- command: evil", "&b *b"},
			Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083\nsteps: [x]"}}}
		out := g.buildYAML(a, threatidentity.ContentID(a.ThreatID))
		if out != g.buildYAML(a, threatidentity.ContentID(a.ThreatID)) {
			t.Fatalf("%q: output not deterministic", h.in)
		}
		var top map[string]any
		if err := yaml.Unmarshal([]byte(out), &top); err != nil {
			t.Fatalf("%q: unparseable: %v\n%s", h.in, err, out)
		}
		wantKeys := map[string]bool{"id": true, "name": true, "description": true, "author": true, "tags": true,
			"mitre_phases": true, "intel_source": true, "intel_source_id": true, "intel_actor": true,
			"intel_confidence": true, "art_techniques": true}
		for k := range top {
			if !wantKeys[k] {
				t.Fatalf("%q: injected top-level key %q\n%s", h.in, k, out)
			}
		}
		if len(top) != len(wantKeys) {
			t.Fatalf("%q: keys = %v", h.in, top)
		}
		var sc scenario.Scenario
		if err := yaml.Unmarshal([]byte(out), &sc); err != nil {
			t.Fatal(err)
		}
		if len(sc.Steps) != 0 || sc.LocalCheck {
			t.Fatalf("%q: structure changed: steps=%d local_check=%v", h.in, len(sc.Steps), sc.LocalCheck)
		}
		if sc.IntelActor != h.want || sc.Name != h.want+" — Active Campaign (Intel)" {
			t.Fatalf("%q: actor = %q, name = %q; want literal %q", h.in, sc.IntelActor, sc.Name, h.want)
		}
		if len(sc.ARTTechniques) != 2 || sc.ARTTechniques[0] != "T1082" {
			t.Fatalf("%q: art_techniques = %q", h.in, sc.ARTTechniques)
		}
		for _, s := range append(append([]string{sc.IntelSource, sc.IntelSourceID, sc.IntelConfidence, sc.Description}, sc.Tags...), sc.ARTTechniques...) {
			if strings.ContainsAny(s, "\r\n\x00") {
				t.Fatalf("%q: control character survived in %q", h.in, s)
			}
		}
	}
}

// Re-review M-b: values are cleaned first, then deduped and sorted, so the
// provider's ordering and values that collapse after cleaning cannot change
// the bytes.
func TestBuildYAML_CleanThenDedupeSort(t *testing.T) {
	g := NewGenerator(t.TempDir(), []string{"finance"}, nil, nil)
	a := ThreatActor{Name: "Akira", Source: "misp", Confidence: "high",
		Sectors:    []string{"retail", "finance", "finance\n", "fin\u200bance"},
		Techniques: []TechniqueRef{{ID: "T1083"}, {ID: "t1082"}, {ID: "T1082\x00"}, {ID: "T1059", Tactic: "execution\r"}}}
	b := ThreatActor{Name: "Akira", Source: "misp", Confidence: "high",
		Sectors:    []string{"finance", "retail"},
		Techniques: []TechniqueRef{{ID: "T1059", Tactic: "execution"}, {ID: "T1082"}, {ID: "T1083"}}}
	ya, yb := g.buildYAML(a, "intel-x"), g.buildYAML(b, "intel-x")
	if ya != yb {
		t.Fatalf("reordered / collapsing inputs must give identical bytes:\n%s\n---\n%s", ya, yb)
	}
}

// Re-review M-b2: format characters (bidi controls, ZWSP, BOM) and line/
// paragraph separators are stripped too.
func TestSanitizeIntelText_DropsFormatAndSeparatorChars(t *testing.T) {
	got, _ := sanitizeIntelText("A\u202eB\u200bC\ufeffD\u2028E\u2029F\u2066G", 100)
	if got != "ABCDEFG" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildYAML_TruncatesOnRuneBoundary(t *testing.T) {
	g := NewGenerator(t.TempDir(), nil, nil, nil)
	a := ThreatActor{Name: strings.Repeat("é", 500), Source: "otx", Description: strings.Repeat("日", 300),
		Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083"}}}
	out := g.buildYAML(a, threatidentity.ContentID(a.ThreatID))
	if !utf8.ValidString(out) {
		t.Fatal("output must be valid UTF-8")
	}
	var sc scenario.Scenario
	if err := yaml.Unmarshal([]byte(out), &sc); err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(sc.IntelActor); n != maxIntelNameRunes || strings.Trim(sc.IntelActor, "é") != "" {
		t.Fatalf("actor name: %d runes", n)
	}
	if !strings.Contains(sc.Description, strings.Repeat("日", maxIntelDescriptionRunes)+"...") ||
		strings.Contains(sc.Description, strings.Repeat("日", maxIntelDescriptionRunes+1)) {
		t.Fatalf("description not cut at %d runes: %q", maxIntelDescriptionRunes, sc.Description)
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

func TestGenerator_ContentIDFollowsThreatNotName(t *testing.T) { // acceptance 10
	dir := t.TempDir()
	rec := &recRegistrar{}
	g := NewGenerator(dir, nil, nil, nil).WithRegistrar(rec)
	techs := []TechniqueRef{{ID: "T1059.001"}, {ID: "T1082"}}
	a := ThreatActor{Name: "APT29", ThreatID: "thr-fixed", Source: "misp", Techniques: techs}
	b := ThreatActor{Name: "Midnight Blizzard", ThreatID: "thr-fixed", Source: "misp", Techniques: techs}
	if _, err := g.Write([]ThreatActor{a}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Write([]ThreatActor{b}); err != nil {
		t.Fatal(err)
	}
	if rec.got[0].ContentID != rec.got[1].ContentID || rec.got[0].ContentID != threatidentity.ContentID("thr-fixed") {
		t.Fatalf("ids %q %q", rec.got[0].ContentID, rec.got[1].ContentID)
	}
	if rec.got[0].ThreatID != "thr-fixed" {
		t.Fatalf("threat not passed: %+v", rec.got[0])
	}
}

func TestGenerator_SkipsUnresolvedActor(t *testing.T) { // acceptance 12 (no content for unresolved)
	dir := t.TempDir()
	rec := &recRegistrar{}
	g := NewGenerator(dir, nil, nil, nil).WithRegistrar(rec)
	res, err := g.Write([]ThreatActor{{Name: "Panda", Source: "misp",
		Techniques: []TechniqueRef{{ID: "T1059.001"}, {ID: "T1082"}}}})
	if err != nil || res.Skipped != 1 || len(rec.got) != 0 {
		t.Fatalf("res=%+v got=%d err=%v", res, len(rec.got), err)
	}
}
