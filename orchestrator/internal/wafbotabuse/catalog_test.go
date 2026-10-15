package wafbotabuse

import (
	"strings"
	"testing"
)

func TestAudspectWAFBotAbuseCatalog_ReturnsFourVectors(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	if len(vectors) != 4 {
		t.Fatalf("len(vectors) = %d, want 4", len(vectors))
	}
	if err := ValidateBotAbuseCatalog(vectors); err != nil {
		t.Errorf("ValidateBotAbuseCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 4 distinct categories, not
// duplicate one and skip another.
func TestAudspectWAFBotAbuseCatalog_CoversAllFourCategories(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	want := []BotAbuseCategory{
		CategoryBoundedAutomation, CategoryRateLimit, CategoryCredentialAbuse, CategoryDistributedEnforcement,
	}
	seen := make(map[BotAbuseCategory]int)
	for _, v := range vectors {
		seen[v.Category]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("category %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}

// Review (final-review fix): BOTABUSE-004 models a cross-node lockout-state
// bypass where BOTH legs are deliberate attack probes that differ only in
// distribution strategy, not in malicious intent. It must not carry a
// BenignCounterpart: Expectations() wires that leg to wafval.ClaimFalsePositive,
// which asserts the correct outcome is Allowed -- but this leg's own story is
// that the control SHOULD block it (shared lockout state should trigger),
// directly contradicting the claim it would be evaluated against.
func TestAudspectWAFBotAbuseCatalog_DistributedEnforcement_HasNoBenignCounterpart(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.ID != "BOTABUSE-004" {
			continue
		}
		if v.BenignCounterpart != nil {
			t.Fatalf("BOTABUSE-004.BenignCounterpart = %+v, want nil (both legs are attack probes; a BenignCounterpart here contradicts the ClaimFalsePositive semantics Expectations() would wire it to)", v.BenignCounterpart)
		}
		if v.NoBenignCounterpartReason == "" {
			t.Fatal("BOTABUSE-004.NoBenignCounterpartReason must be set when BenignCounterpart is nil")
		}
		return
	}
	t.Fatal("BOTABUSE-004 not found in catalog")
}

// Review (final-review fix): BOTABUSE-003 must model a distinct claim shape
// from wafcatalog's AUTH-001 ("bounded burst of N differing password guesses
// against one username"), not restate it under a different ID. It is pinned
// to a post-threshold CAPTCHA-gate-enforcement story: does a challenge the
// control already issued actually get checked on the next request, rather
// than whether raw attempt volume gets detected at all (AUTH-001's story).
func TestAudspectWAFBotAbuseCatalog_CredentialAbuse_ModelsChallengeGateBypassNotRawBurst(t *testing.T) {
	vectors, err := AudspectWAFBotAbuseCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFBotAbuseCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.ID != "BOTABUSE-003" {
			continue
		}
		combined := v.Malicious.Payload + " " + v.Malicious.Description
		if !strings.Contains(combined, "CAPTCHA-solution") {
			t.Fatalf("BOTABUSE-003's malicious leg = %q, want it to reference a %q to model challenge-gate enforcement distinctly from AUTH-001's raw-burst story", combined, "CAPTCHA-solution")
		}
		return
	}
	t.Fatal("BOTABUSE-003 not found in catalog")
}
