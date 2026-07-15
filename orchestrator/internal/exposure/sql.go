package exposure

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SQLCVEEnricher is the production CVEEnricher: batched join against cves +
// cve_epss. KEV membership is cves.source='cisa-kev' (see Global Constraints
// in the plan for why, not a non-null date_added check).
type SQLCVEEnricher struct{ db *pgxpool.Pool }

func NewSQLCVEEnricher(db *pgxpool.Pool) *SQLCVEEnricher { return &SQLCVEEnricher{db: db} }

func (e *SQLCVEEnricher) Enrich(ctx context.Context, cveIDs []string) (map[string]CVEMeta, error) {
	if len(cveIDs) == 0 {
		return map[string]CVEMeta{}, nil
	}
	// cvss/epss_score are `real` (float32) columns; cast to double precision so
	// pgx scans a value with no float32->float64 round-trip precision artifact
	// (e.g. 9.8 arriving as 9.800000190734863).
	rows, err := e.db.Query(ctx, `
		SELECT c.cve_id, COALESCE(c.cvss,0)::double precision, (c.source = 'cisa-kev'), COALESCE(ep.epss_score,0)::double precision
		FROM cves c
		LEFT JOIN cve_epss ep ON ep.cve_id = c.cve_id
		WHERE c.cve_id = ANY($1)`, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CVEMeta{}
	for rows.Next() {
		var id string
		var m CVEMeta
		if rows.Scan(&id, &m.CVSS, &m.KEV, &m.EPSSScore) != nil {
			continue
		}
		out[id] = m
	}
	return out, rows.Err()
}

// SQLFindingsLookup is the production FindingsLookup: one query, grouped by
// agent in Go (findings has no natural GROUP BY shape for a row-list result).
type SQLFindingsLookup struct{ db *pgxpool.Pool }

func NewSQLFindingsLookup(db *pgxpool.Pool) *SQLFindingsLookup { return &SQLFindingsLookup{db: db} }

func (l *SQLFindingsLookup) AllOpenFindings(ctx context.Context) (map[string][]FindingSummary, error) {
	rows, err := l.db.Query(ctx, `
		SELECT id, agent_id, technique_id, technique_name, tactic, severity, exposure_state
		FROM findings WHERE status='open'
		ORDER BY agent_id, CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]FindingSummary{}
	for rows.Next() {
		var agentID string
		var f FindingSummary
		if rows.Scan(&f.ID, &agentID, &f.TechniqueID, &f.TechniqueName, &f.Tactic, &f.Severity, &f.ExposureState) != nil {
			continue
		}
		out[agentID] = append(out[agentID], f)
	}
	return out, rows.Err()
}
