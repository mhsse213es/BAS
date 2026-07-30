package campaign

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
)

// Rollup is one campaign with its live-computed Summary -- the analytics
// layer's canonical Campaigns result.
type Rollup struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	ScenarioID   string    `json:"scenarioId"`
	ScenarioName string    `json:"scenarioName"`
	Mode         string    `json:"mode"`
	CreatedBy    string    `json:"createdBy"`
	StartedAt    time.Time `json:"startedAt"`
	Summary      Summary   `json:"summary"`
}

// ListWithRollups queries every campaign and its child runs, computing each
// one's live Summary via the existing Aggregate/DeriveStatus. A fresh,
// focused implementation for the fleet-list need -- deliberately not a
// refactor of internal/api/campaign_handlers.go's loadCampaign/loadChildren,
// which also builds the richer per-agent childRunOut breakdown the single-
// campaign detail endpoint needs and this list endpoint does not. See
// design spec Non-Goals.
func ListWithRollups(ctx context.Context, pool *pgxpool.Pool) ([]Rollup, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, name, scenario_id, scenario_name, mode, created_by, skips, started_at, stopped_at
		  FROM campaigns ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	type campRow struct {
		id, name, scenarioID, scenarioName, mode, createdBy string
		skipsRaw                                            []byte
		startedAt                                           time.Time
		stoppedAt                                           *time.Time
	}
	var camps []campRow
	for rows.Next() {
		var c campRow
		if err := rows.Scan(&c.id, &c.name, &c.scenarioID, &c.scenarioName, &c.mode,
			&c.createdBy, &c.skipsRaw, &c.startedAt, &c.stoppedAt); err != nil {
			rows.Close()
			return nil, err
		}
		camps = append(camps, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Rollup, 0, len(camps))
	for _, c := range camps {
		var skips []Skip
		_ = json.Unmarshal(c.skipsRaw, &skips)

		children, err := loadChildRunsForRollup(ctx, pool, c.id)
		if err != nil {
			return nil, err
		}

		s := Aggregate(children, skips)
		s.Status = DeriveStatus(children, len(skips), c.stoppedAt != nil)

		out = append(out, Rollup{
			ID: c.id, Name: c.name, ScenarioID: c.scenarioID, ScenarioName: c.scenarioName,
			Mode: c.mode, CreatedBy: c.createdBy, StartedAt: c.startedAt, Summary: s,
		})
	}
	return out, nil
}

// loadChildRunsForRollup loads just enough per-child-run data to compute a
// Summary (status, results, score, detected techniques) -- the ChildRun
// shape Aggregate/DeriveStatus need, nothing more (unlike
// campaign_handlers.go's loadChildren, which also builds the richer
// childRunOut for the detail view).
func loadChildRunsForRollup(ctx context.Context, pool *pgxpool.Pool, campaignID string) ([]ChildRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT status, results, score, detection_summary
		   FROM scenario_runs WHERE campaign_id = $1 ORDER BY started_at`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ChildRun
	for rows.Next() {
		var status string
		var resultsRaw, scoreRaw, detRaw []byte
		if err := rows.Scan(&status, &resultsRaw, &scoreRaw, &detRaw); err != nil {
			return nil, err
		}
		var results []models.SimulationResult
		_ = json.Unmarshal(resultsRaw, &results)
		var score *models.Score
		if len(scoreRaw) > 0 {
			var sc models.Score
			if json.Unmarshal(scoreRaw, &sc) == nil {
				score = &sc
			}
		}
		det := detectedTechsFromSummary(detRaw, results)
		out = append(out, ChildRun{Status: status, Results: results, Score: score, DetectedTechs: det})
	}
	return out, rows.Err()
}

// detectedTechsFromSummary mirrors campaign_handlers.go's detectedTechs
// helper (internal/api/campaign_handlers.go:157) -- same detection_summary
// shape and same per-step event-classifier supplementary pass, reimplemented
// here since that helper is unexported in a different package. Both read
// the same persisted column; if the schema changes, both call sites need
// updating regardless of which package owns this copy.
//
// The second loop is NOT a fallback gated on detRaw being empty -- it always
// runs, checking every FAILed result's Events via
// reporting.ClassifyDetectionStatus for any technique the sweep data didn't
// already mark detected. Caught during implementation: an earlier draft of
// this function only handled the detRaw branch, silently under-counting
// Detected vs Missed in campaign rollups.
func detectedTechsFromSummary(detRaw []byte, results []models.SimulationResult) map[string]bool {
	out := map[string]bool{}
	if len(detRaw) > 0 {
		var ds struct {
			Techniques []struct {
				TechniqueID string `json:"techniqueId"`
				Verdict     string `json:"verdict"`
			} `json:"techniques"`
		}
		if json.Unmarshal(detRaw, &ds) == nil {
			for _, t := range ds.Techniques {
				if t.Verdict == "detected" {
					out[t.TechniqueID] = true
				}
			}
		}
	}
	for _, res := range results {
		if res.Result == models.ResultFail && !out[res.Technique.ID] {
			if reporting.ClassifyDetectionStatus(res.Events) == "Detected" {
				out[res.Technique.ID] = true
			}
		}
	}
	return out
}
