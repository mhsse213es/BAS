package threatidentity

import (
	"context"
	"fmt"
)

type EntityKind string

const (
	EntityCampaign EntityKind = "campaign"
	EntityMalware  EntityKind = "malware"
	EntityTool     EntityKind = "tool"
)

// entityLinkSpec describes one entity kind's actor relation (spec §3.5).
type entityLinkSpec struct{ table, column, candidateKind, source string }

var entityLinkTables = map[EntityKind]entityLinkSpec{
	EntityCampaign: {"campaign_actors", "campaign_id", "campaign_ref", "intelligence_campaigns"},
	EntityMalware:  {"malware_actors", "malware_id", "malware_ref", "intelligence_malware"},
	EntityTool:     {"tool_actors", "tool_id", "tool_ref", "intelligence_tools"},
}

type LinkReport struct{ Linked, Unmatched, Queued int }

func (r *LinkReport) add(o LinkReport) {
	r.Linked += o.Linked
	r.Unmatched += o.Unmatched
	r.Queued += o.Queued
}

// LinkEntityActors maps an entity's legacy actor names to immutable actor
// ids. A name resolving to exactly one actor is linked; an ambiguous name is
// queued once (a decided ref is never re-queued); a name matching nothing is
// counted and left alone -- references never create actors.
func (s *Store) LinkEntityActors(ctx context.Context, kind EntityKind, entityID, provider string, names []string) (LinkReport, error) {
	spec, ok := entityLinkTables[kind]
	if !ok {
		return LinkReport{}, fmt.Errorf("unknown entity kind %q", kind)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LinkReport{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, identityLockKey); err != nil {
		return LinkReport{}, err
	}
	snap, err := loadSnapshot(ctx, tx)
	if err != nil {
		return LinkReport{}, err
	}
	var rep LinkReport
	for _, name := range names {
		in := Incoming{Name: name, Sources: KeysFor(provider, "", name)}
		if len(in.Sources) == 0 {
			continue
		}
		d := Resolve(in, snap)
		switch d.Outcome {
		case OutcomeExisting:
			tag, err := tx.Exec(ctx, `INSERT INTO `+spec.table+` (`+spec.column+`, actor_id, linked_by)
				VALUES ($1, $2, 'resolver') ON CONFLICT DO NOTHING`, entityID, d.ActorID)
			if err != nil {
				return LinkReport{}, err
			}
			rep.Linked += int(tag.RowsAffected())
		case OutcomeAmbiguous:
			id, err := queueCandidate(ctx, tx, spec.candidateKind, in, entityID, d)
			if err != nil {
				return LinkReport{}, err
			}
			if id != "" {
				rep.Queued++
			}
		default:
			rep.Unmatched++
		}
	}
	return rep, tx.Commit(ctx)
}

type BackfillReport struct {
	Threats int
	Links   LinkReport
}

// Backfill runs every boot: every actor profile gets its Threat, and every
// campaign/malware/tool actor_ids array is mapped to actor ids. Idempotent.
func (s *Store) Backfill(ctx context.Context) (BackfillReport, error) {
	var rep BackfillReport
	tag, err := s.pool.Exec(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		SELECT 'thr-' || gen_random_uuid()::text, 'actor', p.id, p.id, p.name FROM threat_actor_profiles p
		ON CONFLICT (subject_type, subject_id) DO NOTHING`)
	if err != nil {
		return rep, err
	}
	rep.Threats = int(tag.RowsAffected())
	for _, kind := range []EntityKind{EntityCampaign, EntityMalware, EntityTool} {
		spec := entityLinkTables[kind]
		rows, err := s.pool.Query(ctx, `SELECT id, source_provider, actor_ids FROM `+spec.source+` WHERE cardinality(actor_ids) > 0`)
		if err != nil {
			return rep, err
		}
		type ent struct {
			id, provider string
			names        []string
		}
		var ents []ent
		for rows.Next() {
			var e ent
			if err := rows.Scan(&e.id, &e.provider, &e.names); err != nil {
				rows.Close()
				return rep, err
			}
			ents = append(ents, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return rep, err
		}
		for _, e := range ents {
			r, err := s.LinkEntityActors(ctx, kind, e.id, e.provider, e.names)
			if err != nil {
				return rep, err
			}
			rep.Links.add(r)
		}
	}
	return rep, nil
}
