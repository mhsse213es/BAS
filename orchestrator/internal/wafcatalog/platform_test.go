package wafcatalog

import (
	"strings"
	"testing"
)

// Negative: a platform value outside the allowed set must fail catalog validation rather than be stored.
func TestValidateCatalog_RejectsUnknownPlatform(t *testing.T) {
	v := AttackVector{ID: "X-001", Platform: Platform("solaris")}
	if err := ValidateCatalog([]AttackVector{v}); err == nil {
		t.Fatal("ValidateCatalog accepted platform \"solaris\", want an error")
	}
}

// Positive: each allowed platform value (including the unrecorded empty value) passes validation.
func TestValidateCatalog_AcceptsEveryAllowedPlatform(t *testing.T) {
	for i, p := range []Platform{PlatformUnspecified, PlatformAny, PlatformUnix, PlatformWindows} {
		v := AttackVector{ID: "P-" + string(rune('A'+i)), Platform: p}
		if err := ValidateCatalog([]AttackVector{v}); err != nil {
			t.Errorf("platform %q rejected: %v", p, err)
		}
	}
}

// The new command-injection vectors declare the platform their payload is written for.
func TestCommandInjectionDepth_PlatformMetadataMatchesPayload(t *testing.T) {
	want := map[string]Platform{
		"CMDI-009": PlatformWindows,
		"CMDI-010": PlatformUnix,
		"CMDI-011": PlatformUnix,
		"CMDI-012": PlatformUnix,
		"CMDI-013": PlatformWindows,
		"CMDI-014": PlatformUnix,
		"CMDI-015": PlatformAny,
		"CMDI-016": PlatformWindows,
	}
	got := map[string]Platform{}
	for _, v := range depthCatalog(t) {
		got[v.ID] = v.Platform
	}
	for id, p := range want {
		if got[id] != p {
			t.Errorf("%s platform = %q, want %q", id, got[id], p)
		}
	}
}

// Negative: vectors predating the metadata are left unrecorded, not guessed.
func TestOlderVectors_PlatformNotGuessed(t *testing.T) {
	for _, v := range depthCatalog(t) {
		if v.ID == "CMDI-001" || v.ID == "CMDI-002" {
			if v.Platform != PlatformUnspecified {
				t.Errorf("%s platform = %q, want unrecorded (empty)", v.ID, v.Platform)
			}
		}
	}
}

// Negative: a Windows-only payload must not be labelled unix, and the reverse.
func TestCommandInjectionDepth_NoPlatformMislabel(t *testing.T) {
	for _, v := range inFamily(depthCatalog(t), FamilyCommandInjection) {
		p := v.Malicious.Payload
		if v.Platform == PlatformUnix && (containsAny(p, "&& ver", " & ", "ping -n", "w^")) {
			t.Errorf("%s is labelled unix but its payload is Windows-shaped: %q", v.ID, p)
		}
		if v.Platform == PlatformWindows && (containsAny(p, "${IFS}", "`", "i''d")) {
			t.Errorf("%s is labelled windows but its payload is Unix-shaped: %q", v.ID, p)
		}
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
