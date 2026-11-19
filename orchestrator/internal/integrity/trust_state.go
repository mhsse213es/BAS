package integrity

// NextAgentState is the agent state after a heartbeat or enrolment, from its
// binary's trust. It separates two cases that must not be confused:
//
//   - outdated: the binary is a previous signed release. The agent degrades
//     until it runs a current binary, then returns to active by itself.
//   - quarantined: the binary is unknown (possibly tampered). Only an operator
//     can release it, so no binary check moves a quarantined agent back.
//
// Operator states (quarantined, restricted, retired) are never changed here except
// by the rules below. An outdated agent that now runs an unknown binary escalates to
// quarantined. Callers pass trusted = the current manifest knows the hash, previous =
// the hash is a previous signed release, and revoked = an operator revoked the hash.
// A revoked binary is quarantined even when it is trusted or a previous release.
func NextAgentState(state string, trusted, previous, revoked bool) string {
	switch state {
	case "active", "outdated":
	default:
		return state // quarantined, restricted, retired and anything else stay as they are
	}
	switch {
	case revoked:
		return "quarantined"
	case trusted:
		return "active"
	case previous:
		return "outdated"
	default:
		return "quarantined"
	}
}
