package latmove

import "github.com/audspect/bas/internal/adprimitive"

// Technique identifies one lateral-movement technique this vertical validates.
type Technique struct {
	ID        string
	Name      string
	MitreID   string
	RiskClass adprimitive.RiskClass
}

// WMIRemoteProcessCreation is the first (and in this slice, only) technique:
// WMI remote process creation, T1047. RiskClass is non-destructive: the
// attempt writes a benign, self-identifying marker and creates no persistence.
func WMIRemoteProcessCreation() Technique {
	return Technique{
		ID:        "wmi-remote-process-creation",
		Name:      "WMI Remote Process Creation",
		MitreID:   "T1047",
		RiskClass: adprimitive.RiskNonDestructive,
	}
}
