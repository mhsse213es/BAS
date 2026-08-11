package attackdata

import (
	"slices"
	"testing"
)

// The embedded ATT&CK dataset must load and carry authoritative enrichment for a
// well-known technique.
func TestLookupAuthoritative(t *testing.T) {
	e := Lookup("T1003.001")
	if e == nil {
		t.Fatal("T1003.001 not found in embedded dataset")
	}
	if len(e.Groups) == 0 || len(e.Software) == 0 || len(e.Mitigations) == 0 {
		t.Errorf("T1003.001 missing authoritative data: groups=%d software=%d mitig=%d",
			len(e.Groups), len(e.Software), len(e.Mitigations))
	}
	if e.URL == "" {
		t.Error("T1003.001 missing ATT&CK URL")
	}
}

// The curated overlay must merge onto authoritative data and be flagged Curated.
func TestLookupCuratedOverlayMerges(t *testing.T) {
	e := Lookup("T1003.001")
	if e == nil || !e.Curated {
		t.Fatalf("T1003.001 should carry curated overlay (Curated=%v)", e != nil && e.Curated)
	}
	if len(e.CWE) == 0 {
		t.Error("expected curated CWE on T1003.001")
	}
	// Authoritative data must survive the merge.
	if len(e.Groups) == 0 {
		t.Error("authoritative groups lost after overlay merge")
	}
}

// A sub-technique with no record of its own falls back to its parent.
func TestLookupSubtechniqueFallback(t *testing.T) {
	if e := Lookup("T1003.099"); e == nil || e.TechniqueID != "T1003" {
		t.Errorf("T1003.099 should fall back to parent T1003, got %v", e)
	}
}

func TestLookupUnknown(t *testing.T) {
	if e := Lookup("T9999"); e != nil {
		t.Errorf("T9999 should be nil, got %+v", e)
	}
}

// Documentation keys in the overlay must not become enrichment records.
func TestOverlayIgnoresUnderscoreKeys(t *testing.T) {
	if e := Lookup("_README"); e != nil {
		t.Errorf("_README should be ignored, got %+v", e)
	}
}

// AvgCVSS averages only the analyst-supplied scores and never invents one.
func TestAvgCVSS(t *testing.T) {
	e := &Enrichment{CVEs: []string{"CVE-2024-30088 (CVSS 7.8)", "CVE-2023-21768 (CVSS 8.8)"}}
	if avg, n := e.AvgCVSS(); n != 2 || avg < 8.29 || avg > 8.31 {
		t.Errorf("AvgCVSS = %.3f (n=%d), want ~8.30 (n=2)", avg, n)
	}
	// A CVE with no recorded score must not be counted (no fabrication).
	mixed := &Enrichment{CVEs: []string{"CVE-2024-30088 (CVSS 7.8)", "CVE-2020-0001"}}
	if avg, n := mixed.AvgCVSS(); n != 1 || avg != 7.8 {
		t.Errorf("AvgCVSS(mixed) = %.3f (n=%d), want 7.8 (n=1)", avg, n)
	}
	// No scores anywhere → (0,0) so the report can omit the line.
	if avg, n := (&Enrichment{CVEs: []string{"CVE-2020-0001"}}).AvgCVSS(); n != 0 || avg != 0 {
		t.Errorf("AvgCVSS(none) = %.3f (n=%d), want 0 (n=0)", avg, n)
	}
}

// DetectionEventIDs maps ATT&CK data sources to Windows telemetry deterministically.
func TestDetectionEventIDs(t *testing.T) {
	e := &Enrichment{DataSources: []string{"Process: Process Creation", "Command: Command Execution"}}
	ids := e.DetectionEventIDs()
	want := map[string]bool{"Sysmon 1": true, "Windows Security 4688": true, "PowerShell 4104": true}
	if len(ids) != len(want) {
		t.Fatalf("DetectionEventIDs = %v, want %d distinct ids", ids, len(want))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected event id %q", id)
		}
		if seen[id] {
			t.Errorf("duplicate event id %q", id)
		}
		seen[id] = true
	}
	// A data source with no mapping yields nothing (never fabricated).
	if ids := (&Enrichment{DataSources: []string{"Cloud Service: Cloud Service Enumeration"}}).DetectionEventIDs(); len(ids) != 0 {
		t.Errorf("unmapped data source should yield no event ids, got %v", ids)
	}
}

// New authoritative fields alone are enough to render a threat-intel block.
func TestHasAuthoritativeFromMetadata(t *testing.T) {
	if !(&Enrichment{DataSources: []string{"Process: Process Creation"}}).HasAuthoritative() {
		t.Error("data sources should count as authoritative")
	}
	if !(&Enrichment{D3FEND: []D3fendCM{{ID: "D3-EAL", Name: "Executable Allowlisting"}}}).HasAuthoritative() {
		t.Error("D3FEND mapping should count as authoritative")
	}
	if (&Enrichment{}).HasAuthoritative() {
		t.Error("empty enrichment must not be authoritative")
	}
}

// GroupTechniqueIndex must load the real bundled STIX data and correctly
// invert it into group→techniques. "Wizard Spider" / T1055.001 is the same
// real group/technique pair internal/api's ti_suggest_pack_test.go already
// relies on for its ransomware-pack test, so this pins the same known-good
// fact at the source.
func TestGroupTechniqueIndex_ContainsKnownGroupAndTechnique(t *testing.T) {
	idx := GroupTechniqueIndex()
	if len(idx) == 0 {
		t.Fatal("GroupTechniqueIndex returned an empty index")
	}
	techs, ok := idx["Wizard Spider"]
	if !ok || len(techs) == 0 {
		t.Fatalf("expected a non-empty technique list for Wizard Spider, got %v (ok=%v)", techs, ok)
	}
	if !slices.Contains(techs, "T1055.001") {
		t.Errorf("expected T1055.001 among Wizard Spider's techniques, got %v", techs)
	}
}

// The index is built once (sync.Once) and cached — repeated calls must
// return the identical data, not silently recompute or drift.
func TestGroupTechniqueIndex_Idempotent(t *testing.T) {
	first := GroupTechniqueIndex()
	second := GroupTechniqueIndex()
	if len(first) != len(second) {
		t.Fatalf("group counts differ across calls: %d vs %d", len(first), len(second))
	}
	for g, techs := range first {
		if len(second[g]) != len(techs) {
			t.Fatalf("technique count for group %q differs across calls: %d vs %d", g, len(techs), len(second[g]))
		}
	}
}

// Every entry must have a non-empty group name and at least one technique —
// the inversion loop only ever creates an entry via append, so a present key
// with zero techniques would indicate a construction bug.
func TestGroupTechniqueIndex_NoEmptyGroupsOrTechniqueLists(t *testing.T) {
	idx := GroupTechniqueIndex()
	for g, techs := range idx {
		if g == "" {
			t.Error("found an empty group name key")
		}
		if len(techs) == 0 {
			t.Errorf("group %q has an empty technique list", g)
		}
	}
}

// The synonym dictionary must merge into Lookup() results the same way the
// curated overlay does.
func TestLookupAliasesMerge(t *testing.T) {
	e := Lookup("T1055")
	if e == nil {
		t.Fatal("T1055 not found in embedded dataset")
	}
	if !slices.Contains(e.Aliases, "dll injection") {
		t.Errorf("T1055 should carry alias %q, got %v", "dll injection", e.Aliases)
	}
	// Authoritative data must survive the merge.
	if e.Name == "" {
		t.Error("authoritative name lost after alias merge")
	}
}

func TestLookupNoAliases(t *testing.T) {
	// T1078 (Valid Accounts) has no entry in technique_synonyms.json.
	e := Lookup("T1078")
	if e == nil {
		t.Fatal("T1078 not found in embedded dataset")
	}
	if len(e.Aliases) != 0 {
		t.Errorf("T1078 should have no aliases, got %v", e.Aliases)
	}
}

func TestBuildGroupCanonicalTokenIndex_ResolvesNameAndAliases(t *testing.T) {
	idx := buildGroupCanonicalTokenIndex([]Group{
		{ID: "G0016", Name: "APT29", Aliases: []string{"Cozy Bear", "The Dukes"}},
	})
	for _, tok := range []string{"apt29", "cozybear", "thedukes"} {
		if idx[tok] != "G0016" {
			t.Errorf("idx[%q] = %q, want G0016", tok, idx[tok])
		}
	}
}

// A token MITRE's own data lists under two different groups must resolve
// to nothing -- picking either arbitrarily would risk a false merge.
func TestBuildGroupCanonicalTokenIndex_AmbiguousTokenExcluded(t *testing.T) {
	idx := buildGroupCanonicalTokenIndex([]Group{
		{ID: "G0001", Name: "Group One", Aliases: []string{"Shared"}},
		{ID: "G0002", Name: "Group Two", Aliases: []string{"Shared"}},
	})
	if _, ok := idx["shared"]; ok {
		t.Errorf("ambiguous token %q should be excluded, got %q", "shared", idx["shared"])
	}
	if idx["groupone"] != "G0001" || idx["grouptwo"] != "G0002" {
		t.Errorf("unambiguous tokens should still resolve: %+v", idx)
	}
}

func TestGroupByID_UnknownReturnsNil(t *testing.T) {
	if g := GroupByID("G9999999"); g != nil {
		t.Errorf("GroupByID(unknown) = %+v, want nil", g)
	}
}

// The index is built once (sync.Once) and cached -- repeated calls must
// return consistent data, not silently recompute or drift.
func TestGroupCanonicalTokenIndex_Idempotent(t *testing.T) {
	first := GroupCanonicalTokenIndex()
	second := GroupCanonicalTokenIndex()
	if len(first) != len(second) {
		t.Fatalf("token counts differ across calls: %d vs %d", len(first), len(second))
	}
}

// SubtechniqueCounts must count sub-techniques under their parent and never
// count a technique under itself.
func TestSubtechniqueCounts(t *testing.T) {
	counts := SubtechniqueCounts()
	if counts["T1055"] == 0 {
		t.Error("T1055 (Process Injection) should have a nonzero sub-technique count")
	}
	if _, exists := counts["T1055.001"]; exists {
		t.Error("a sub-technique ID must not itself appear as a parent key")
	}
}
