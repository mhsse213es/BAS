package pathcorrelation

import "github.com/audspect/bas/internal/attackpath"

// RemediationFor returns a curated, static remediation sentence for an edge kind. Mirrors
// DefaultEdgeTechniqueMapper's exact shape (mapper.go) -- one switch, no dynamic generation.
func RemediationFor(kind attackpath.EdgeKind) string {
	switch kind {
	case attackpath.EdgeSMB:
		return "Restrict SMB connectivity between these hosts (firewall rule or host-based policy)."
	case attackpath.EdgeWinRM:
		return "Restrict WinRM access to only the hosts and accounts that require it."
	case attackpath.EdgeRDP:
		return "Restrict RDP access between these hosts; consider a jump-host-only policy."
	case attackpath.EdgeAdminTo:
		return "Remove unnecessary Local Administrator membership for this account on this host."
	case attackpath.EdgeHasSession:
		return "Reduce interactive session exposure on this host (e.g. avoid privileged logons on shared workstations)."
	case attackpath.EdgeMemberOf:
		return "Review this group membership for least-privilege -- it grants inherited access along this path."
	case attackpath.EdgeCredential:
		return "Rotate or remove the exposed credential material enabling this edge."
	default:
		return ""
	}
}
