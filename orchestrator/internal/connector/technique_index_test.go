package connector

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestBuildTechniqueIndex_SingleMatch(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_sam_theft": {Profile: "windows_sam_theft", TechniqueIDs: []string{"T1003.002"}},
	}
	idx := buildTechniqueIndex(profiles)
	if got := idx["T1003.002"]; len(got) != 1 || got[0] != "windows_sam_theft" {
		t.Errorf("idx[T1003.002] = %v, want [windows_sam_theft]", got)
	}
}

func TestBuildTechniqueIndex_MultipleProfilesSameTechnique(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_defender_tampering":           {Profile: "windows_defender_tampering", TechniqueIDs: []string{"T1562.001"}},
		"windows_security_process_termination": {Profile: "windows_security_process_termination", TechniqueIDs: []string{"T1562.001"}},
		"windows_vulnerable_driver_load":        {Profile: "windows_vulnerable_driver_load", TechniqueIDs: []string{"T1562.001"}},
	}
	idx := buildTechniqueIndex(profiles)
	want := []string{"windows_defender_tampering", "windows_security_process_termination", "windows_vulnerable_driver_load"}
	got := idx["T1562.001"]
	if len(got) != len(want) {
		t.Fatalf("idx[T1562.001] = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("idx[T1562.001][%d] = %q, want %q (sorted order)", i, got[i], want[i])
		}
	}
}

func TestBuildTechniqueIndex_ProfileWithNoTechniqueIDsContributesNothing(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_credential_access": {Profile: "windows_credential_access"}, // abstract base, no TechniqueIDs
	}
	idx := buildTechniqueIndex(profiles)
	if len(idx) != 0 {
		t.Errorf("expected empty index for a profile with no TechniqueIDs, got %v", idx)
	}
}

func TestBuildTechniqueIndex_ProfileWithMultipleTechniqueIDs(t *testing.T) {
	profiles := map[string]*scenario.DetectionProfile{
		"windows_dlp_exfiltration": {Profile: "windows_dlp_exfiltration", TechniqueIDs: []string{"T1052", "T1052.001", "T1074.001", "T1115", "T1560.001"}},
	}
	idx := buildTechniqueIndex(profiles)
	for _, tid := range []string{"T1052", "T1052.001", "T1074.001", "T1115", "T1560.001"} {
		if got := idx[tid]; len(got) != 1 || got[0] != "windows_dlp_exfiltration" {
			t.Errorf("idx[%s] = %v, want [windows_dlp_exfiltration]", tid, got)
		}
	}
}

func TestResolveProfile_NoMatch(t *testing.T) {
	idx := map[string][]string{}
	if got := resolveProfile(idx, "T9999"); got != "" {
		t.Errorf("resolveProfile with no matches = %q, want empty string", got)
	}
}

func TestResolveProfile_ExactMatchOnly(t *testing.T) {
	idx := map[string][]string{"T1562.001": {"windows_defender_tampering"}}
	if got := resolveProfile(idx, "T1562"); got != "" {
		t.Errorf("resolveProfile(T1562) = %q, want empty string -- T1562 must not match a T1562.001-only entry", got)
	}
	if got := resolveProfile(idx, "T1562.001"); got != "windows_defender_tampering" {
		t.Errorf("resolveProfile(T1562.001) = %q, want windows_defender_tampering", got)
	}
}

func TestResolveProfile_CaseInsensitive(t *testing.T) {
	idx := map[string][]string{"T1003.002": {"windows_sam_theft"}}
	if got := resolveProfile(idx, "t1003.002"); got != "windows_sam_theft" {
		t.Errorf("resolveProfile(t1003.002) = %q, want windows_sam_theft (case-insensitive match)", got)
	}
}

func TestResolveProfile_MultipleMatchesFirstWins(t *testing.T) {
	idx := map[string][]string{"T1562.001": {"windows_defender_tampering", "windows_security_process_termination", "windows_vulnerable_driver_load"}}
	if got := resolveProfile(idx, "T1562.001"); got != "windows_defender_tampering" {
		t.Errorf("resolveProfile with 3 candidates = %q, want windows_defender_tampering (first by sorted name)", got)
	}
}
