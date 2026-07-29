package intelligence

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// nonNil coalesces a nil slice to an empty one. pgx encodes a nil []string
// as SQL NULL rather than an empty array, which would violate this
// package's NOT NULL text[] columns for any caller (like
// connector.MISPClient.extractIntelligence) that never populates a given
// field -- e.g. Aliases, which Phase 1 MISP extraction never sets.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// upsertEntitySource records (or refreshes) one provider's contribution to
// a Campaign/Malware/Tool row. first_seen is intentionally excluded from
// the UPDATE SET clause -- it's set once at first insert (DEFAULT NOW())
// and never recomputed on a repeat sync from the same provider, so it
// stays a true "when did we first observe this from this provider" value.
func upsertEntitySource(ctx context.Context, tx pgx.Tx, entityType, entityID string, src SourceRef) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO intelligence_entity_sources
		   (entity_type, entity_id, provider, external_id, last_sync, confidence)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (entity_type, entity_id, provider) DO UPDATE SET
		   external_id = EXCLUDED.external_id,
		   last_sync   = EXCLUDED.last_sync,
		   confidence  = EXCLUDED.confidence`,
		entityType, entityID, src.Provider, src.ExternalID, src.LastUpdated, src.Confidence)
	return err
}

// loadSources batch-loads every provider contribution for the given entity
// IDs in one query (avoids N+1) -- shared by ListCampaigns/ListMalware/
// ListTools. Ordered oldest-first_seen-first, so index 0 is always the
// first-contributing provider, matching the entity's legacy singular
// Source field.
func loadSources(ctx context.Context, pool *pgxpool.Pool, entityType string, ids []string) (map[string][]SourceRef, error) {
	out := map[string][]SourceRef{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := pool.Query(ctx,
		`SELECT entity_id, provider, external_id, last_sync, confidence
		 FROM intelligence_entity_sources
		 WHERE entity_type = $1 AND entity_id = ANY($2)
		 ORDER BY first_seen ASC`,
		entityType, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var s SourceRef
		if err := rows.Scan(&id, &s.Provider, &s.ExternalID, &s.LastUpdated, &s.Confidence); err != nil {
			return nil, err
		}
		out[id] = append(out[id], s)
	}
	return out, rows.Err()
}

// UpsertCampaign merges actor_ids/technique_ids on conflict (union,
// deduplicated) -- OpenCTI can legitimately attribute the same campaign to
// more than one actor, and Campaign extraction runs per-actor (see
// connector.OpenCTIClient.Fetch), so the same campaign ID can be upserted
// twice within one sync with different ThreatActorIDs. Overwriting would
// silently drop the first actor's attribution. name/description/source_*
// fields still overwrite -- those describe the same real-world campaign, no
// merge needed. Safe for MISP too: its campaigns never collide within a
// sync, so union-of-one-element equals the old overwrite behavior.
func UpsertCampaign(ctx context.Context, pool *pgxpool.Pool, c Campaign) error {
	c.ThreatActorIDs, c.TechniqueIDs = nonNil(c.ThreatActorIDs), nonNil(c.TechniqueIDs)
	_, err := pool.Exec(ctx,
		`INSERT INTO intelligence_campaigns
		   (id, name, description, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, description = EXCLUDED.description,
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.actor_ids || EXCLUDED.actor_ids)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_campaigns.technique_ids || EXCLUDED.technique_ids)),
		   source_provider = EXCLUDED.source_provider, source_external_id = EXCLUDED.source_external_id,
		   source_confidence = EXCLUDED.source_confidence, last_updated = EXCLUDED.last_updated`,
		c.ID, c.Name, c.Description, c.ThreatActorIDs, c.TechniqueIDs,
		c.Source.Provider, c.Source.ExternalID, c.Source.Confidence, c.Source.LastUpdated)
	return err
}

// UpsertMalware merges on conflict -- the same malware family is
// legitimately referenced by many different events, so technique/actor/
// campaign ID lists accumulate (deduplicated union) rather than overwrite.
// Runs in a transaction with the intelligence_entity_sources upsert so the
// parent row and its provenance record commit together.
func UpsertMalware(ctx context.Context, pool *pgxpool.Pool, m Malware) error {
	m.Aliases, m.TechniqueIDs = nonNil(m.Aliases), nonNil(m.TechniqueIDs)
	m.ThreatActorIDs, m.CampaignIDs = nonNil(m.ThreatActorIDs), nonNil(m.CampaignIDs)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO intelligence_malware
		   (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.aliases || EXCLUDED.aliases)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.technique_ids || EXCLUDED.technique_ids)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.actor_ids || EXCLUDED.actor_ids)),
		   campaign_ids  = ARRAY(SELECT DISTINCT UNNEST(intelligence_malware.campaign_ids || EXCLUDED.campaign_ids)),
		   source_confidence = EXCLUDED.source_confidence,
		   last_updated  = GREATEST(intelligence_malware.last_updated, EXCLUDED.last_updated)`,
		m.ID, m.Name, m.Aliases, m.TechniqueIDs, m.ThreatActorIDs, m.CampaignIDs,
		m.Source.Provider, m.Source.ExternalID, m.Source.Confidence, m.Source.LastUpdated)
	if err != nil {
		return err
	}

	if err := upsertEntitySource(ctx, tx, "malware", m.ID, m.Source); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UpsertTool merges on conflict -- the same tool is legitimately referenced
// by many different actors/events, so technique/actor/campaign ID lists
// accumulate (deduplicated union) rather than overwrite. Same reasoning as
// UpsertMalware, including the transaction wrapping.
func UpsertTool(ctx context.Context, pool *pgxpool.Pool, t Tool) error {
	t.Aliases, t.TechniqueIDs = nonNil(t.Aliases), nonNil(t.TechniqueIDs)
	t.ThreatActorIDs, t.CampaignIDs = nonNil(t.ThreatActorIDs), nonNil(t.CampaignIDs)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO intelligence_tools
		   (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (id) DO UPDATE SET
		   aliases       = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.aliases || EXCLUDED.aliases)),
		   technique_ids = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.technique_ids || EXCLUDED.technique_ids)),
		   actor_ids     = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.actor_ids || EXCLUDED.actor_ids)),
		   campaign_ids  = ARRAY(SELECT DISTINCT UNNEST(intelligence_tools.campaign_ids || EXCLUDED.campaign_ids)),
		   source_confidence = EXCLUDED.source_confidence,
		   last_updated  = GREATEST(intelligence_tools.last_updated, EXCLUDED.last_updated)`,
		t.ID, t.Name, t.Aliases, t.TechniqueIDs, t.ThreatActorIDs, t.CampaignIDs,
		t.Source.Provider, t.Source.ExternalID, t.Source.Confidence, t.Source.LastUpdated)
	if err != nil {
		return err
	}

	if err := upsertEntitySource(ctx, tx, "tool", t.ID, t.Source); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListTools returns every tool record, newest-updated first. Always
// non-nil, same convention as ListCampaigns/ListMalware.
func ListTools(ctx context.Context, pool *pgxpool.Pool) ([]Tool, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_tools ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tool{}
	ids := []string{}
	for rows.Next() {
		var t Tool
		if err := rows.Scan(&t.ID, &t.Name, &t.Aliases, &t.TechniqueIDs, &t.ThreatActorIDs, &t.CampaignIDs,
			&t.Source.Provider, &t.Source.ExternalID, &t.Source.Confidence, &t.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, t)
		ids = append(ids, t.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sources, err := loadSources(ctx, pool, "tool", ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Sources = sources[out[i].ID]
	}
	return out, nil
}

// ListCampaigns returns every campaign, newest-updated first. Always
// non-nil (an empty slice, not null) so JSON callers can iterate without a
// guard -- same convention internal/recommend.Recommendations already uses.
func ListCampaigns(ctx context.Context, pool *pgxpool.Pool) ([]Campaign, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, description, actor_ids, technique_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_campaigns ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Campaign{}
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.ThreatActorIDs, &c.TechniqueIDs,
			&c.Source.Provider, &c.Source.ExternalID, &c.Source.Confidence, &c.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListMalware returns every malware record, newest-updated first. Always
// non-nil, same convention as ListCampaigns.
func ListMalware(ctx context.Context, pool *pgxpool.Pool) ([]Malware, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider, source_external_id, source_confidence, last_updated
		 FROM intelligence_malware ORDER BY last_updated DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Malware{}
	ids := []string{}
	for rows.Next() {
		var m Malware
		if err := rows.Scan(&m.ID, &m.Name, &m.Aliases, &m.TechniqueIDs, &m.ThreatActorIDs, &m.CampaignIDs,
			&m.Source.Provider, &m.Source.ExternalID, &m.Source.Confidence, &m.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, m)
		ids = append(ids, m.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sources, err := loadSources(ctx, pool, "malware", ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Sources = sources[out[i].ID]
	}
	return out, nil
}
