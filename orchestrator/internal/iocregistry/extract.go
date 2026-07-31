package iocregistry

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// ExtractFromDetectionAlert pulls IOC-shaped values out of res.DetectionAlert
// (if present) into the iocs/ioc_sightings tables. Best-effort by design of
// its caller (SubmitRunDetections) -- a nil DetectionAlert or empty fields
// are not errors, just nothing to extract. techniqueID/detectionVerdict come
// from the same SimulationResult the alert was matched against -- passed
// separately since they live on the result, not the alert.
func ExtractFromDetectionAlert(ctx context.Context, pool *pgxpool.Pool, scenarioID, runID, agentID, techniqueID, detectionVerdict string, res models.SimulationResult) error {
	if res.DetectionAlert == nil {
		return nil
	}
	alert := res.DetectionAlert

	if alert.CommandLine != "" {
		meta := map[string]any{}
		if alert.ThreatName != "" {
			meta["threatName"] = alert.ThreatName
		}
		id, err := upsertIOC(ctx, pool, TypeCommandLine, alert.CommandLine, SourceDetectionAlert, meta)
		if err != nil {
			return err
		}
		if err := recordSighting(ctx, pool, id, scenarioID, runID, agentID, techniqueID, detectionVerdict); err != nil {
			return err
		}
	}

	if alert.ProcessName != "" {
		id, err := upsertIOC(ctx, pool, TypeProcess, alert.ProcessName, SourceDetectionAlert, nil)
		if err != nil {
			return err
		}
		if err := recordSighting(ctx, pool, id, scenarioID, runID, agentID, techniqueID, detectionVerdict); err != nil {
			return err
		}
	}

	return nil
}

// upsertIOC inserts a new iocs row or, if (type, value) already exists,
// bumps last_seen/sighting_count -- the dedup contract. metadata is only
// applied on insert (first observation); it is not merged on repeat
// sightings, since a later observation of the same command line carrying a
// different threatName would otherwise silently overwrite the first.
// Thin wrapper over upsertIOCFull with this package's original defaults --
// unchanged behavior for every Phase 0+A/B/C caller.
func upsertIOC(ctx context.Context, pool *pgxpool.Pool, t Type, value string, source Source, metadata map[string]any) (string, error) {
	return upsertIOCFull(ctx, pool, t, value, source, OriginBuiltIn, StatusObserved, metadata)
}

// upsertIOCFull is the one INSERT INTO iocs statement -- upsertIOC (above),
// RegisterGenerated (generate.go), and ImportManual (import.go) all call this
// instead of each maintaining their own near-identical SQL.
func upsertIOCFull(ctx context.Context, pool *pgxpool.Pool, t Type, value string, source Source, origin Origin, status Status, metadata map[string]any) (string, error) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	var id string
	err = pool.QueryRow(ctx, `
		INSERT INTO iocs (type, value, source, origin, status, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (type, value) DO UPDATE SET
			last_seen = NOW(),
			sighting_count = iocs.sighting_count + 1
		RETURNING id`,
		string(t), value, string(source), string(origin), string(status), metaJSON,
	).Scan(&id)
	return id, err
}

func recordSighting(ctx context.Context, pool *pgxpool.Pool, iocID, scenarioID, runID, agentID, techniqueID, detectionVerdict string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO ioc_sightings (ioc_id, scenario_id, run_id, agent_id, technique_id, detection_verdict)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		iocID, scenarioID, runID, agentID, techniqueID, detectionVerdict)
	return err
}
