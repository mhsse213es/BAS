package pathcorrelation

import "github.com/audspect/bas/internal/attackpath"

// TechniqueMapping is one edge-kind -> ATT&CK-technique association. Weight
// (0.0-1.0] is both mapping confidence ("how directly does this edge realize
// this technique") and detection criticality ("how important is it to catch
// this technique") — for a lateral-movement edge the two collapse, since the
// more direct technique is also the one most worth detecting.
type TechniqueMapping struct {
	TechniqueID string  `json:"techniqueId"`
	Weight      float64 `json:"weight"`
	Reason      string  `json:"reason"`
}

// EdgeTechniqueMapper maps a graph edge kind to the ATT&CK technique(s) an
// attacker would use to traverse it. DefaultEdgeTechniqueMapper is the only
// implementation today; the interface exists so a future per-deployment
// override does not require redesigning pathcorrelation.
type EdgeTechniqueMapper interface {
	Techniques(kind attackpath.EdgeKind) []TechniqueMapping
}

// DefaultEdgeTechniqueMapper is the built-in, curated edge -> technique table.
type DefaultEdgeTechniqueMapper struct{}

func (DefaultEdgeTechniqueMapper) Techniques(kind attackpath.EdgeKind) []TechniqueMapping {
	switch kind {
	case attackpath.EdgeSMB:
		return []TechniqueMapping{
			{TechniqueID: "T1021.002", Weight: 1.0, Reason: "SMB/Windows Admin Shares is the direct mechanism of this edge"},
		}
	case attackpath.EdgeWinRM:
		return []TechniqueMapping{
			{TechniqueID: "T1021.006", Weight: 1.0, Reason: "Windows Remote Management is the direct mechanism of this edge"},
		}
	case attackpath.EdgeRDP:
		return []TechniqueMapping{
			{TechniqueID: "T1021.001", Weight: 1.0, Reason: "Remote Desktop Protocol is the direct mechanism of this edge"},
		}
	case attackpath.EdgeAdminTo:
		return []TechniqueMapping{
			{TechniqueID: "T1078", Weight: 1.0, Reason: "Valid Accounts used to hold local admin on the target"},
		}
	case attackpath.EdgeHasSession:
		return []TechniqueMapping{
			{TechniqueID: "T1003", Weight: 0.7, Reason: "OS Credential Dumping is possible from an interactive session"},
			{TechniqueID: "T1552", Weight: 0.5, Reason: "Unsecured Credentials may be exposed via an active session"},
		}
	case attackpath.EdgeMemberOf:
		return []TechniqueMapping{
			{TechniqueID: "T1078", Weight: 0.6, Reason: "Group membership implies valid-account privilege reuse"},
			{TechniqueID: "T1098", Weight: 0.4, Reason: "Account Manipulation is a less direct but possible origin"},
		}
	case attackpath.EdgeCredential:
		return []TechniqueMapping{
			{TechniqueID: "T1550", Weight: 1.0, Reason: "Use Alternate Authentication Material is the direct mechanism"},
			{TechniqueID: "T1555", Weight: 0.5, Reason: "Credentials from Password Stores is a possible but not certain origin"},
		}
	default:
		return nil
	}
}
