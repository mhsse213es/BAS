package adenv

// HasGPOWriteAccess reports whether principal holds edit rights on g. A writer
// can inject policy (an immediate scheduled task, a local-admin membership) that
// applies to every object under the GPO's linked scope.
func HasGPOWriteAccess(g GPO, principal string) bool {
	for _, p := range g.WritePrincipals {
		if p == principal {
			return true
		}
	}
	return false
}

// GPOAffectsScope reports whether g is linked anywhere, i.e. whether editing it
// actually reaches any object. An unlinked GPO is harmless regardless of its ACL.
func GPOAffectsScope(g GPO) bool {
	return len(g.LinkedOUs) > 0
}
