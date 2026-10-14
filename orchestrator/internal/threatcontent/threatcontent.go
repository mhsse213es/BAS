// Package threatcontent assembles the live threat-coverage view (TCF
// Phase 10, spec docs/superpowers/specs/2026-10-14-tcf-phase10-live-threat-coverage-design.md):
// for each currently-active threat, which content the factory has produced
// for it, whether that content is actually executable today, and whether
// it has ever been run. It owns no schema of its own -- every table it
// reads (threats, threat_techniques, content_version_threats,
// content_versions, scenario_runs) belongs to an earlier phase.
package threatcontent

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
)

// ThreatExposure is one currently-active threat, with its live techniques and
// the content the factory has produced for it (spec 2026-10-14 §2.1).
type ThreatExposure struct {
	ThreatID    string              `json:"threatId"`
	Title       string              `json:"title"`
	FirstSeenAt *time.Time          `json:"firstSeenAt,omitempty"`
	LastSeenAt  *time.Time          `json:"lastSeenAt,omitempty"`
	Techniques  []TechniqueExposure `json:"techniques"`
	Content     []ContentExposure   `json:"content"`
}

type TechniqueExposure struct {
	TechniqueID          string    `json:"techniqueId"`
	LastSeenAt           time.Time `json:"lastSeenAt"`
	HasExecutableContent bool      `json:"hasExecutableContent"`
}

type ContentExposure struct {
	ContentVersionID string     `json:"contentVersionId"`
	ContentID        string     `json:"contentId"`
	RelationshipKind string     `json:"relationshipKind"`
	Lifecycle        string     `json:"lifecycle"`
	Trust            string     `json:"trust"`
	IsExecutable     bool       `json:"isExecutable"`
	Validation       string     `json:"validation"`
	LastRunAt        *time.Time `json:"lastRunAt,omitempty"`
	RunCount         int        `json:"runCount"`
	techniqueIDs     []string   // not serialized; used to compute TechniqueExposure.HasExecutableContent
}

// ListActiveThreatExposure assembles the live threat-coverage view (spec
// §2.1-§2.2). limit<=0 defaults to 20, capped at 100; offset<0 defaults to 0.
func ListActiveThreatExposure(ctx context.Context, pool *pgxpool.Pool, reg *contentregistry.Registry, limit, offset int) ([]ThreatExposure, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	summaries, err := reg.Summaries(ctx)
	if err != nil {
		return nil, fmt.Errorf("threatcontent: registry summaries: %w", err)
	}

	rows, err := pool.Query(ctx, `SELECT id, title, first_seen_at, last_seen_at FROM threats
		WHERE status = 'active' ORDER BY last_seen_at DESC NULLS LAST LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("threatcontent: list threats: %w", err)
	}
	var out []ThreatExposure
	for rows.Next() {
		var te ThreatExposure
		if err := rows.Scan(&te.ThreatID, &te.Title, &te.FirstSeenAt, &te.LastSeenAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("threatcontent: scan threat: %w", err)
		}
		out = append(out, te)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	for i := range out {
		if err := loadTechniques(ctx, pool, &out[i]); err != nil {
			return nil, err
		}
		if err := loadContent(ctx, pool, summaries, &out[i]); err != nil {
			return nil, err
		}
		computeHasExecutableContent(&out[i])
	}
	return out, nil
}

func loadTechniques(ctx context.Context, pool *pgxpool.Pool, te *ThreatExposure) error {
	rows, err := pool.Query(ctx, `SELECT technique_id, last_seen_at FROM threat_techniques
		WHERE threat_id = $1 AND status = 'active'`, te.ThreatID)
	if err != nil {
		return fmt.Errorf("threatcontent: list techniques for %s: %w", te.ThreatID, err)
	}
	defer rows.Close()
	te.Techniques = []TechniqueExposure{}
	for rows.Next() {
		var t TechniqueExposure
		if err := rows.Scan(&t.TechniqueID, &t.LastSeenAt); err != nil {
			return fmt.Errorf("threatcontent: scan technique: %w", err)
		}
		te.Techniques = append(te.Techniques, t)
	}
	return rows.Err()
}

func loadContent(ctx context.Context, pool *pgxpool.Pool, summaries map[string]contentregistry.Summary, te *ThreatExposure) error {
	rows, err := pool.Query(ctx, `SELECT cv.id, cv.content_id, cvt.relationship_kind, cv.lifecycle, cv.trust_level, cv.version, cv.technique_ids
		FROM content_version_threats cvt JOIN content_versions cv ON cv.id = cvt.content_version_id
		WHERE cvt.threat_id = $1`, te.ThreatID)
	if err != nil {
		return fmt.Errorf("threatcontent: list content for %s: %w", te.ThreatID, err)
	}
	te.Content = []ContentExposure{}
	for rows.Next() {
		var ce ContentExposure
		var version int
		if err := rows.Scan(&ce.ContentVersionID, &ce.ContentID, &ce.RelationshipKind, &ce.Lifecycle, &ce.Trust, &version, &ce.techniqueIDs); err != nil {
			rows.Close()
			return fmt.Errorf("threatcontent: scan content: %w", err)
		}
		ce.Validation = "structural-only"
		if s, ok := summaries[ce.ContentID]; ok {
			// Summaries keys by content_id and names only the single version
			// number the gate actually selected; an older, superseded version of
			// the same content id (still linked via content_version_threats from
			// before a re-intake) must not be marked executable just because it
			// happens to share that version's lifecycle/trust tuple.
			ce.IsExecutable = version == s.ExecutableVersion
		}
		te.Content = append(te.Content, ce)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range te.Content {
		var lastRunAt *time.Time
		var count int
		if err := pool.QueryRow(ctx, `SELECT MAX(started_at), COUNT(*) FROM scenario_runs WHERE content_version_id = $1`,
			te.Content[i].ContentVersionID).Scan(&lastRunAt, &count); err != nil {
			return fmt.Errorf("threatcontent: run aggregate for %s: %w", te.Content[i].ContentVersionID, err)
		}
		te.Content[i].LastRunAt = lastRunAt
		te.Content[i].RunCount = count
	}
	return nil
}

func computeHasExecutableContent(te *ThreatExposure) {
	for i := range te.Techniques {
		for _, c := range te.Content {
			if !c.IsExecutable {
				continue
			}
			for _, tid := range c.techniqueIDs {
				if tid == te.Techniques[i].TechniqueID {
					te.Techniques[i].HasExecutableContent = true
				}
			}
		}
	}
}
