package intelligence

import (
	"context"

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
func UpsertMalware(ctx context.Context, pool *pgxpool.Pool, m Malware) error {
	m.Aliases, m.TechniqueIDs = nonNil(m.Aliases), nonNil(m.TechniqueIDs)
	m.ThreatActorIDs, m.CampaignIDs = nonNil(m.ThreatActorIDs), nonNil(m.CampaignIDs)
	_, err := pool.Exec(ctx,
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
	return err
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
	for rows.Next() {
		var m Malware
		if err := rows.Scan(&m.ID, &m.Name, &m.Aliases, &m.TechniqueIDs, &m.ThreatActorIDs, &m.CampaignIDs,
			&m.Source.Provider, &m.Source.ExternalID, &m.Source.Confidence, &m.Source.LastUpdated); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
