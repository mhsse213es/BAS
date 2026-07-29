package search

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

// scenariosFrom maps every loaded scenario into a Document. Scenarios are
// file-backed (scenario.Engine), not a Postgres table -- no query needed,
// engine.List() is already in memory.
func scenariosFrom(engine *scenario.Engine) []Document {
	list := engine.List()
	out := make([]Document, 0, len(list))
	for _, s := range list {
		tags := make([]string, 0, len(s.Tags)+len(s.MITREPhases)+len(s.ARTTechniques))
		tags = append(tags, s.Tags...)
		tags = append(tags, s.MITREPhases...)
		tags = append(tags, s.ARTTechniques...)
		out = append(out, Document{
			DocType: "scenario", SourceID: s.ID, Title: s.Name,
			Description: s.Description, Tags: tags,
		})
	}
	return out
}

// runsFrom maps every scenario_runs row into a Document. Title falls back
// to scenario_id when name is empty, matching the existing UI convention
// (e.g. cmd/server/wwwroot/index.html's `r.name || r.scenarioId`).
func runsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, scenario_id, name, status FROM scenario_runs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, scenarioID, name, status string
		if err := rows.Scan(&id, &scenarioID, &name, &status); err != nil {
			return nil, err
		}
		title := name
		if title == "" {
			title = scenarioID
		}
		out = append(out, Document{
			DocType: "run", SourceID: id, Title: title,
			Description: status, Tags: []string{status},
		})
	}
	return out, rows.Err()
}

// findingsFrom maps every findings row into a Document. Title falls back
// to technique_id when technique_name is empty.
func findingsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, technique_id, technique_name, control_class, severity, exposure_state, status FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, techID, techName, controlClass, severity, exposureState, status string
		if err := rows.Scan(&id, &techID, &techName, &controlClass, &severity, &exposureState, &status); err != nil {
			return nil, err
		}
		title := techName
		if title == "" {
			title = techID
		}
		out = append(out, Document{
			DocType: "finding", SourceID: id, Title: title,
			Description: severity + " " + exposureState,
			Tags:        []string{controlClass, severity, status},
		})
	}
	return out, rows.Err()
}
