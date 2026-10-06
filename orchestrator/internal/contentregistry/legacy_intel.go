package contentregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/audspect/bas/internal/threatidentity"
)

// LegacyIntelItem is one piece of Phase-1 name-derived intel content
// (TCF Phase 2 spec §4.4). Reporting only: nothing is deleted or moved.
type LegacyIntelItem struct {
	ContentID    string `json:"contentId"`
	ActorID      string `json:"actorId,omitempty"`
	SupersededBy string `json:"supersededBy,omitempty"`
	HasHistory   bool   `json:"hasHistory"`
	Action       string `json:"action"` // superseded | admin_decision_required | unresolved
}

// legacyIntelID is Phase 1's retired derivation, kept only to map old
// content back to an actor.
func legacyIntelID(name string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return "intel-" + hex.EncodeToString(h[:])[:12]
}

// LegacyIntelContent lists intel content with no threat owner. Content with
// any approval or run history is never handled automatically; an unowned
// DRAFT mapping to exactly one actor with a Threat is reported superseded
// by that threat's content id. Phase 1 has no DRAFT->RETIRED rule, so the
// DRAFT is left as is.
func (r *Registry) LegacyIntelContent(ctx context.Context) ([]LegacyIntelItem, error) {
	type actorThreat struct{ actor, threat string }
	byLegacy := map[string][]actorThreat{}
	rows, err := r.pool.Query(ctx, `SELECT p.id, p.name, COALESCE(t.id, '') FROM threat_actor_profiles p
		LEFT JOIN threats t ON t.subject_type = 'actor' AND t.actor_id = p.id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name, thr string
		if err := rows.Scan(&id, &name, &thr); err != nil {
			rows.Close()
			return nil, err
		}
		k := legacyIntelID(name)
		byLegacy[k] = append(byLegacy[k], actorThreat{id, thr})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = r.pool.Query(ctx, `
		SELECT s.scenario_id,
		       EXISTS (SELECT 1 FROM content_versions v WHERE v.content_id = s.scenario_id
		                AND v.lifecycle NOT IN ('DRAFT','REJECTED'))
		    OR EXISTS (SELECT 1 FROM scenario_runs sr JOIN content_versions v ON v.id = sr.content_version_id
		                WHERE v.content_id = s.scenario_id)
		  FROM scenarios s
		 WHERE EXISTS (SELECT 1 FROM content_versions v WHERE v.content_id = s.scenario_id AND v.intake_source = $1)
		   AND NOT EXISTS (SELECT 1 FROM content_generation_owners o WHERE o.content_id = s.scenario_id)
		 ORDER BY s.scenario_id`, string(SourceIntel))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LegacyIntelItem{}
	for rows.Next() {
		var it LegacyIntelItem
		if err := rows.Scan(&it.ContentID, &it.HasHistory); err != nil {
			return nil, err
		}
		matches := byLegacy[it.ContentID]
		if len(matches) == 1 {
			it.ActorID = matches[0].actor
		}
		switch {
		case it.HasHistory:
			it.Action = "admin_decision_required"
		case len(matches) == 1 && matches[0].threat != "":
			it.Action, it.SupersededBy = "superseded", threatidentity.ContentID(matches[0].threat)
		default:
			it.Action = "unresolved"
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
