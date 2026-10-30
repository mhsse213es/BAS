package api

import (
	"context"
	"log"

	"github.com/audspect/bas/internal/integrity"
)

// applyBinaryTrustState moves an agent between active, outdated and quarantined from
// the trust of the binary it reports. The UPDATE is conditional on the state read
// here, so a concurrent operator change is never overwritten.
func (h *Handler) applyBinaryTrustState(ctx context.Context, agentID, binaryHash string, trusted bool) {
	previous := h.manifest.HashPreviousRelease(binaryHash)
	var current string
	if err := h.db.QueryRow(ctx, `SELECT COALESCE(state,'active') FROM agents WHERE agent_id = $1`, agentID).Scan(&current); err != nil {
		return
	}
	next := integrity.NextAgentState(current, trusted, previous)
	if next == current {
		return
	}
	if _, err := h.db.Exec(ctx,
		`UPDATE agents SET state = $3 WHERE agent_id = $1 AND state = $2`,
		agentID, current, next); err != nil {
		log.Printf("[!] agent %s: binary trust state update failed: %v", agentID, err)
		return
	}
	switch next {
	case "quarantined":
		log.Printf("[!] agent %s QUARANTINED — binary hash unrecognised", agentID)
	case "outdated":
		log.Printf("[i] agent %s is outdated — running a previous signed release", agentID)
	case "active":
		log.Printf("[i] agent %s returned to active — running a current signed binary", agentID)
	}
}
