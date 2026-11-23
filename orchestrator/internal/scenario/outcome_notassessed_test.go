package scenario

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// A check that needs an organizational baseline it does not have is NOT_ASSESSED, not a platform problem.
func TestClassifySkipReason_NotAssessed(t *testing.T) {
	if got := classifySkipReason("not assessed; no organizational allowlist configured"); got != models.SkipReasonNotAssessed {
		t.Fatalf("got %q, want %q", got, models.SkipReasonNotAssessed)
	}
}

func TestClassifySkipReason_NotConfiguredAndUnverified(t *testing.T) {
	if got := classifySkipReason("not configured; set BAS_EDR_EVENTS_FILE"); got != models.SkipReasonNotConfigured {
		t.Fatalf("not configured: got %q", got)
	}
	if got := classifySkipReason("unverified; export older than the probe"); got != models.SkipReasonUnverified {
		t.Fatalf("unverified: got %q", got)
	}
}
