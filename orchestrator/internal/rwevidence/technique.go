package rwevidence

import "github.com/audspect/bas/internal/adprimitive"

// Technique identifies one ransomware technique this package has evidence
// support for. RiskClass is informational only here -- this package
// executes nothing and gates nothing; the existing scenario engine's own
// safety gate (BAS_CONFIRM_VSS_DELETE) is what actually governs execution.
type Technique struct {
	ID        string
	Name      string
	MitreID   string
	RiskClass adprimitive.RiskClass
}

// VSSInhibition is the first technique this package supports: deletion of
// shadow copies / backup catalog entries (T1490, Inhibit System Recovery).
func VSSInhibition() Technique {
	return Technique{
		ID:        "vss-inhibition",
		Name:      "Inhibit System Recovery (VSS/Backup Catalog)",
		MitreID:   "T1490",
		RiskClass: adprimitive.RiskDestructive,
	}
}
