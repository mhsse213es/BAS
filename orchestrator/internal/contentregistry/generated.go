package contentregistry

import (
	"context"
	"fmt"
	"time"
)

// SourceRef names one intelligence entity a generated version derives from.
// EntityType: actor|campaign|malware|tool|technique_evidence. Role: primary|supporting.
type SourceRef struct {
	EntityType string
	EntityID   string
	Provider   string
	ExternalID string
	Role       string
}

type GeneratedCandidate struct {
	ContentID     string
	Artifact      []byte
	GenerationKey string
	Generation    map[string]any
	Sources       []SourceRef
}

// RegisterGenerated records a generator candidate as LOCAL/UNTRUSTED/DRAFT
// with point-in-time provenance snapshots (spec 4.5, 5.2). Identical bytes
// are a no-op (created=false).
func (r *Registry) RegisterGenerated(ctx context.Context, c GeneratedCandidate) (string, bool, error) {
	a, err := analyzeArtifact(c.Artifact)
	if err != nil {
		return "", false, err
	}
	if a.contentID != c.ContentID {
		return "", false, fmt.Errorf("artifact id %q does not match %q", a.contentID, c.ContentID)
	}
	snaps, err := r.snapshotSources(ctx, c.Sources)
	if err != nil {
		return "", false, err
	}
	return r.createVersion(ctx, newVersion{contentID: c.ContentID, origin: OriginLocal, source: SourceIntel,
		artifact: c.Artifact, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorGenerator,
		analysis: a, generation: c.Generation, generationKey: c.GenerationKey, sources: snaps,
		exclusiveLocalSource: true})
}

func earliest(ts ...*time.Time) *time.Time {
	var out *time.Time
	for _, t := range ts {
		if t != nil && (out == nil || t.Before(*out)) {
			out = t
		}
	}
	return out
}

// snapshotSources copies what the factory knew at generation time. Actor
// refs expand to every threat_actor_sources row for that actor (the primary
// provider keeps role=primary, the rest become supporting). Missing source
// rows yield empty/NULL snapshot fields -- never invented values.
func (r *Registry) snapshotSources(ctx context.Context, refs []SourceRef) ([]sourceSnapshot, error) {
	var out []sourceSnapshot
	for _, ref := range refs {
		switch ref.EntityType {
		case "actor":
			rows, err := r.pool.Query(ctx,
				`SELECT s.source, s.source_id, s.confidence, s.last_seen, s.updated_at, a.first_observed
				   FROM threat_actor_sources s
				   LEFT JOIN threat_actor_activity a ON a.actor_name = s.actor_name AND a.source = s.source
				  WHERE s.actor_name = $1 ORDER BY s.source`, ref.EntityID)
			if err != nil {
				return nil, err
			}
			found := false
			for rows.Next() {
				var prov, ext, conf string
				var lastSeen, firstObserved *time.Time
				var updated time.Time
				if err := rows.Scan(&prov, &ext, &conf, &lastSeen, &updated, &firstObserved); err != nil {
					rows.Close()
					return nil, err
				}
				found = true
				role := "supporting"
				if prov == ref.Provider {
					role = "primary"
				}
				u := updated
				out = append(out, sourceSnapshot{
					ref:        SourceRef{EntityType: "actor", EntityID: ref.EntityID, Provider: prov, ExternalID: ext, Role: role},
					confidence: conf, firstSeen: earliest(firstObserved, lastSeen), lastSync: &u})
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return nil, err
			}
			if !found {
				out = append(out, sourceSnapshot{ref: ref})
			}
		case "campaign", "malware", "tool":
			var conf string
			var firstSeen, lastSync time.Time
			err := r.pool.QueryRow(ctx,
				`SELECT confidence, first_seen, last_sync FROM intelligence_entity_sources
				  WHERE entity_type = $1 AND entity_id = $2 AND provider = $3`,
				ref.EntityType, ref.EntityID, ref.Provider).Scan(&conf, &firstSeen, &lastSync)
			if err != nil {
				out = append(out, sourceSnapshot{ref: ref})
				continue
			}
			out = append(out, sourceSnapshot{ref: ref, confidence: conf, firstSeen: &firstSeen, lastSync: &lastSync})
		default:
			return nil, fmt.Errorf("provenance snapshot for entity type %q is not supported in Phase 1", ref.EntityType)
		}
	}
	return out, nil
}
