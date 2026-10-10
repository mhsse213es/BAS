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

// RemoteServiceCreation is the second technique in the family: "PsExec-style"
// lateral movement -- copy a binary to the destination's admin share, then
// create and start a Windows service to run it (T1543.003, with T1021.002 as
// the lateral-tool-transfer leg). Unlike WMI's one-shot call, this creates a
// PERSISTENT artifact (the service) that must be torn down even on failure,
// so RiskClass is potentially_destructive, not non_destructive.
func RemoteServiceCreation() Technique {
	return Technique{
		ID:        "remote-service-creation",
		Name:      "Remote Service Creation",
		MitreID:   "T1543.003",
		RiskClass: adprimitive.RiskPotentiallyDestructive,
	}
}
