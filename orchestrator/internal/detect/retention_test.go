package detect

import (
	"testing"

	"github.com/audspect/bas/internal/auditretention"
)

// Raw detection alerts are security event logs. They must be kept for at least the audit retention minimum,
// or alerts that matched no step are lost before the minimum is reached.
func TestRawDetectionRetentionMeetsAuditMinimum(t *testing.T) {
	if RawRetentionDays < auditretention.MinimumRetentionDays {
		t.Fatalf("raw detections kept %d days, below the %d-day minimum", RawRetentionDays, auditretention.MinimumRetentionDays)
	}
}
