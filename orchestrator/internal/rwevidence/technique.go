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

// DataEncryptedForImpact is the second technique this package supports:
// mass file encryption plus ransom-note deployment (T1486, Data Encrypted
// for Impact) -- the defining ransomware behavior. Recovery does NOT apply
// to this technique directly: T1486 is about whether files get encrypted,
// not about whether recovery mechanisms survive -- that is T1490's domain.
// A caller must record Recovery as NotApplicable for T1486, never silently
// omit it.
func DataEncryptedForImpact() Technique {
	return Technique{
		ID:        "data-encrypted-for-impact",
		Name:      "Data Encrypted for Impact (Mass Encryption + Ransom Note)",
		MitreID:   "T1486",
		RiskClass: adprimitive.RiskDestructive,
	}
}
