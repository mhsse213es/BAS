package api

import (
	"context"
	"log"
	"time"
)

// retainedSource describes what a threat-intel source left in the console after its config was removed.
// Removing a config keeps this data on purpose: it stops the sync, it does not erase what was already
// ingested. The status card uses this to say "config removed, data kept" rather than a bare "Not configured".
type retainedSource struct {
	Actors        int        `json:"actors"`
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
}

// retainedSources reports, for each of misp, opencti and otx whose connector is currently off, how many
// actors that source still holds and when it last synced successfully. A source with neither is omitted.
// enabled maps connector name to whether it is currently running.
func (h *Handler) retainedSources(ctx context.Context, enabled map[string]bool) map[string]retainedSource {
	out := map[string]retainedSource{}
	if h.db == nil {
		return out
	}
	for _, name := range []string{"misp", "opencti", "otx"} {
		if enabled[name] {
			continue
		}
		var rs retainedSource
		if err := h.db.QueryRow(ctx,
			`SELECT count(DISTINCT actor_name) FROM threat_actor_sources WHERE source = $1`, name).Scan(&rs.Actors); err != nil {
			log.Printf("[threat-intel] retained actors for %s: %v", name, err)
			continue
		}
		var last *time.Time
		if err := h.db.QueryRow(ctx,
			`SELECT max(ss.completed_at) FROM source_syncs ss
			   JOIN source_instances si ON si.id = ss.source_instance_id
			  WHERE si.source_type = $1 AND ss.status = 'succeeded'`, name).Scan(&last); err != nil {
			log.Printf("[threat-intel] retained last sync for %s: %v", name, err)
			continue
		}
		rs.LastSuccessAt = last
		if rs.Actors > 0 || last != nil {
			out[name] = rs
		}
	}
	return out
}
