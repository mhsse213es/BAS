package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ioc"
)

// UpsertRunIOCs replaces the full set of extracted indicators for a run.
// Delete-then-insert (not a merge) mirrors the "agent always submits a
// complete snapshot" idempotency pattern SubmitScenarioResult already uses
// for scenario_runs itself -- a retried submission converges to the same
// row set instead of duplicating or double-merging arrays.
func UpsertRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, scenarioID string, indicators []ioc.RunIndicator) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ioc upsert: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID); err != nil {
		return fmt.Errorf("ioc upsert: delete: %w", err)
	}
	for _, ind := range indicators {
		techniqueIDsJSON, _ := json.Marshal(ind.TechniqueIDs)
		simulationIDsJSON, _ := json.Marshal(ind.SimulationIDs)
		var algo any
		if ind.Algorithm != "" {
			algo = ind.Algorithm
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO run_iocs
			 (run_id, scenario_id, indicator_type, indicator_value, hash_algorithm,
			  confidence, indicator_source, offset_start, offset_end, technique_ids, simulation_ids)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb)`,
			runID, scenarioID, ind.Type, ind.Value, algo,
			ind.Confidence, ind.Source, ind.OffsetStart, ind.OffsetEnd,
			techniqueIDsJSON, simulationIDsJSON,
		)
		if err != nil {
			return fmt.Errorf("ioc upsert: insert %s %s: %w", ind.Type, ind.Value, err)
		}
	}
	return tx.Commit(ctx)
}

// GetRunIOCs returns the extracted indicators for a run, optionally filtered
// by indicator type and/or a substring match against indicator_value.
func GetRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, typeFilter, search string) ([]ioc.RunIndicator, error) {
	query := `SELECT indicator_type, indicator_value, COALESCE(hash_algorithm, ''),
	                  confidence, indicator_source, offset_start, offset_end,
	                  technique_ids, simulation_ids, extracted_at
	           FROM run_iocs WHERE run_id = $1`
	args := []any{runID}
	if typeFilter != "" {
		args = append(args, typeFilter)
		query += fmt.Sprintf(" AND indicator_type = $%d", len(args))
	}
	if search != "" {
		args = append(args, "%"+search+"%")
		query += fmt.Sprintf(" AND indicator_value ILIKE $%d", len(args))
	}
	query += " ORDER BY id ASC"

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ioc get: query: %w", err)
	}
	defer rows.Close()

	out := make([]ioc.RunIndicator, 0)
	for rows.Next() {
		var ind ioc.RunIndicator
		var techniqueIDsJSON, simulationIDsJSON []byte
		var extractedAt time.Time
		if err := rows.Scan(&ind.Type, &ind.Value, &ind.Algorithm,
			&ind.Confidence, &ind.Source, &ind.OffsetStart, &ind.OffsetEnd,
			&techniqueIDsJSON, &simulationIDsJSON, &extractedAt); err != nil {
			return nil, fmt.Errorf("ioc get: scan: %w", err)
		}
		_ = json.Unmarshal(techniqueIDsJSON, &ind.TechniqueIDs)
		_ = json.Unmarshal(simulationIDsJSON, &ind.SimulationIDs)
		ind.ExtractedAt = &extractedAt
		out = append(out, ind)
	}
	return out, rows.Err()
}

// EnrichedRunIndicator is one extracted indicator plus its cached provider
// enrichment. Tier and the enrichment fields are left zero-valued when no
// provider is configured (provider == "" — no lookup was ever attempted) or
// none is cached yet for this specific indicator. Tier mirrors
// reporting.Engine.populateThreatIntel's classification as an independent
// read path (see GetRunIOCs vs GetIOCs' architecture note above for why this
// package tolerates that kind of duplication) so the run drawer and an
// exported report agree on what "malicious" vs "pending" means for the same
// underlying data.
type EnrichedRunIndicator struct {
	ioc.RunIndicator
	Tier            string   `json:"tier,omitempty"` // malicious-associated | suspicious | unknown | pending | "" (no provider)
	PulseCount      int      `json:"pulseCount,omitempty"`
	PulseNames      []string `json:"pulseNames,omitempty"`
	MalwareFamilies []string `json:"malwareFamilies,omitempty"`
	AdversaryNames  []string `json:"adversaryNames,omitempty"`
	Industries      []string `json:"industries,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

// GetRunIOCsEnriched is GetRunIOCs plus a LEFT JOIN against ioc_enrichment
// for the given provider. Pass provider == "" when no threat-intel provider
// is configured (e.g. OTX_API_KEY unset) -- every indicator then comes back
// with Tier == "" rather than attempting to classify against a cache that
// was never populated.
func GetRunIOCsEnriched(ctx context.Context, pool *pgxpool.Pool, runID, provider, typeFilter, search string) ([]EnrichedRunIndicator, error) {
	query := `SELECT ri.indicator_type, ri.indicator_value, COALESCE(ri.hash_algorithm, ''),
	                  ri.confidence, ri.indicator_source, ri.offset_start, ri.offset_end,
	                  ri.technique_ids, ri.simulation_ids, ri.extracted_at,
	                  ie.pulse_count, ie.pulse_names, ie.malware_families, ie.adversary_names,
	                  ie.industries, ie.tags, ie.last_success_at
	           FROM run_iocs ri
	           LEFT JOIN ioc_enrichment ie
	             ON ie.indicator_type = ri.indicator_type
	            AND ie.indicator_value = ri.indicator_value
	            AND ie.provider = $2
	           WHERE ri.run_id = $1`
	args := []any{runID, provider}
	if typeFilter != "" {
		args = append(args, typeFilter)
		query += fmt.Sprintf(" AND ri.indicator_type = $%d", len(args))
	}
	if search != "" {
		args = append(args, "%"+search+"%")
		query += fmt.Sprintf(" AND ri.indicator_value ILIKE $%d", len(args))
	}
	query += " ORDER BY ri.id ASC"

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ioc get enriched: query: %w", err)
	}
	defer rows.Close()

	out := make([]EnrichedRunIndicator, 0)
	for rows.Next() {
		var ind EnrichedRunIndicator
		var techniqueIDsJSON, simulationIDsJSON []byte
		var pulseNamesJSON, malwareJSON, adversaryJSON, industriesJSON, tagsJSON []byte
		var pulseCount *int
		var lastSuccessAt *time.Time
		var extractedAt time.Time
		if err := rows.Scan(&ind.Type, &ind.Value, &ind.Algorithm,
			&ind.Confidence, &ind.Source, &ind.OffsetStart, &ind.OffsetEnd,
			&techniqueIDsJSON, &simulationIDsJSON, &extractedAt,
			&pulseCount, &pulseNamesJSON, &malwareJSON, &adversaryJSON, &industriesJSON, &tagsJSON,
			&lastSuccessAt); err != nil {
			return nil, fmt.Errorf("ioc get enriched: scan: %w", err)
		}
		_ = json.Unmarshal(techniqueIDsJSON, &ind.TechniqueIDs)
		_ = json.Unmarshal(simulationIDsJSON, &ind.SimulationIDs)
		ind.ExtractedAt = &extractedAt

		if provider != "" {
			if pulseCount == nil || lastSuccessAt == nil {
				ind.Tier = "pending"
			} else {
				ind.PulseCount = *pulseCount
				_ = json.Unmarshal(pulseNamesJSON, &ind.PulseNames)
				_ = json.Unmarshal(malwareJSON, &ind.MalwareFamilies)
				_ = json.Unmarshal(adversaryJSON, &ind.AdversaryNames)
				_ = json.Unmarshal(industriesJSON, &ind.Industries)
				_ = json.Unmarshal(tagsJSON, &ind.Tags)
				switch {
				case ind.PulseCount >= 3:
					ind.Tier = "malicious-associated"
				case ind.PulseCount >= 1:
					ind.Tier = "suspicious"
				default:
					ind.Tier = "unknown"
				}
			}
		}
		out = append(out, ind)
	}
	return out, rows.Err()
}
