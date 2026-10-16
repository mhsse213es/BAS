package avcatalog

// LabRestrictedVectorIDs names every vector in this catalog that must
// never be included in an ordinary, general-purpose dispatchable
// scenario bundle -- only an explicitly authorized, isolated lab
// endpoint under its own dedicated execution gate may run it. A vector
// can be implemented (has a real, concretely runnable command) without
// being generally dispatchable; this is the single, authoritative place
// that says so, so no caller needs its own copy of this judgment, and no
// future addition to a dispatch allow-list can silently reintroduce one
// of these without the cross-package regression test in
// internal/avscenario catching it.
func LabRestrictedVectorIDs() map[string]string {
	return map[string]string{
		"AV-CONFIG-003": "disables real-time protection via Set-MpPreference; must only run on a dedicated, isolated lab endpoint under its own BAS_CONFIRM_AV_RTP_DISABLE_ATTEMPT execution gate and a real pre-attempt Tamper-Protection/RTP precondition check, never a build/production host or a routine campaign",
	}
}
