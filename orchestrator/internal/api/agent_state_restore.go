package api

import (
	"fmt"
	"net/http"
)

// restoreRefused reports whether an operator's "set active" must be refused. The heartbeat sets an agent's state from
// its binary, so an agent whose binary the manifest does not recognise is quarantined again on its next heartbeat.
// Accepting the change would make it look restored while it is not, so it is refused with the reason instead. An
// agent is not refused when its binary is trusted, is a previous signed release, or has not reported a hash yet.
func restoreRefused(binaryHash string, binaryTrusted, previousRelease bool) bool {
	return binaryHash != "" && !binaryTrusted && !previousRelease
}

// refuseUntrustedRestore answers 409 and reports true when restoreRefused applies. With no manifest loaded, verification
// is off and nothing is refused. A lookup failure is not refused here: the update itself reports a missing agent.
func (h *Handler) refuseUntrustedRestore(w http.ResponseWriter, r *http.Request, agentID string) bool {
	if h.manifest == nil || !h.manifest.Loaded() {
		return false
	}
	var hash string
	var trusted bool
	if err := h.db.QueryRow(r.Context(),
		`SELECT COALESCE(binary_hash,''), COALESCE(binary_trusted,false) FROM agents WHERE agent_id = $1`,
		agentID).Scan(&hash, &trusted); err != nil {
		return false
	}
	if !restoreRefused(hash, trusted, h.manifest.HashPreviousRelease(hash)) {
		return false
	}
	short := hash
	if len(short) > 12 {
		short = short[:12]
	}
	jsonError(w, fmt.Sprintf("cannot set active: the agent's binary (%s...) is not in the signed release manifest, "+
		"so the server would quarantine it again on its next heartbeat. The agent returns to active by itself once it runs "+
		"a signed release (outdated, if it runs a previous one). Install the signed agent release on this host to restore it.", short),
		http.StatusConflict)
	return true
}
