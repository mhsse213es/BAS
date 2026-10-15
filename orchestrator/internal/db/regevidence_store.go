package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/regobligation"
)

// EnsureEvidenceSnapshotSchema creates the regulatory_evidence_snapshots
// table and its obligation_id index. Unlike regulatory_obligations'
// created_at, captured_at IS passed explicitly by the caller (never
// DB-defaulted) -- Review Focus #3 requires proving a caller-supplied
// value is server-overwritten, which needs the handler's own
// server-assigned time.Now() to be the value actually persisted and
// visible in the immediate POST response, not a later DB default.
func EnsureEvidenceSnapshotSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS regulatory_evidence_snapshots (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			obligation_id  text        NOT NULL,
			captured_at    timestamptz NOT NULL,
			captured_by    text,
			snapshot_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_regulatory_evidence_snapshots_obligation_id
		ON regulatory_evidence_snapshots (obligation_id)`)
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: ensure index: %w", err)
	}
	return nil
}

// evidenceSnapshotData is the shape persisted in the snapshot_data
// jsonb column -- everything except id/obligation_id/captured_at/
// captured_by, which live in their own columns.
type evidenceSnapshotData struct {
	SchemaVersion       string                       `json:"schemaVersion,omitempty"`
	ControlMappingID    string                       `json:"controlMappingId"`
	ObligationVersion   string                       `json:"obligationVersion,omitempty"`
	CapabilityName      string                       `json:"capabilityName"`
	ImportReferences    map[string]string            `json:"importReferences,omitempty"`
	QueryParameters     map[string]any               `json:"queryParameters,omitempty"`
	CapturedOutcome     string                       `json:"capturedOutcome,omitempty"`
	CapturedConfidence  string                       `json:"capturedConfidence,omitempty"`
	CapturedLimitations string                       `json:"capturedLimitations,omitempty"`
	Status              regobligation.SnapshotStatus `json:"status"`
	IncompleteReason    string                       `json:"incompleteReason,omitempty"`
	Note                string                       `json:"note,omitempty"`
}

// InsertEvidenceSnapshot writes a new regulatory_evidence_snapshots
// row. The caller supplies es.ID and es.CapturedAt already set.
func InsertEvidenceSnapshot(ctx context.Context, pool *pgxpool.Pool, es *regobligation.EvidenceSnapshot) error {
	data, err := json.Marshal(evidenceSnapshotData{
		SchemaVersion: es.SchemaVersion, ControlMappingID: es.ControlMappingID, ObligationVersion: es.ObligationVersion,
		CapabilityName: es.CapabilityName, ImportReferences: es.ImportReferences, QueryParameters: es.QueryParameters,
		CapturedOutcome: es.CapturedOutcome, CapturedConfidence: es.CapturedConfidence, CapturedLimitations: es.CapturedLimitations,
		Status: es.Status, IncompleteReason: es.IncompleteReason, Note: es.Note,
	})
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: marshal snapshot data for %s: %w", es.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO regulatory_evidence_snapshots (id, obligation_id, captured_at, captured_by, snapshot_data)
		 VALUES ($1,$2,$3,$4,$5)`,
		es.ID, es.ObligationID, es.CapturedAt, nullableString(es.CapturedBy), data)
	if err != nil {
		return fmt.Errorf("regulatory_evidence_snapshots: insert %s: %w", es.ID, err)
	}
	return nil
}

func scanEvidenceSnapshot(row pgx.Row) (*regobligation.EvidenceSnapshot, error) {
	es := &regobligation.EvidenceSnapshot{}
	var capturedBy *string
	var data []byte
	if err := row.Scan(&es.ID, &es.ObligationID, &es.CapturedAt, &capturedBy, &data); err != nil {
		return nil, err
	}
	if capturedBy != nil {
		es.CapturedBy = *capturedBy
	}
	var sd evidenceSnapshotData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: unmarshal snapshot data for %s: %w", es.ID, err)
	}
	es.SchemaVersion, es.ControlMappingID, es.ObligationVersion = sd.SchemaVersion, sd.ControlMappingID, sd.ObligationVersion
	es.CapabilityName, es.ImportReferences, es.QueryParameters = sd.CapabilityName, sd.ImportReferences, sd.QueryParameters
	es.CapturedOutcome, es.CapturedConfidence, es.CapturedLimitations = sd.CapturedOutcome, sd.CapturedConfidence, sd.CapturedLimitations
	es.Status, es.IncompleteReason, es.Note = sd.Status, sd.IncompleteReason, sd.Note
	return es, nil
}

// GetEvidenceSnapshot returns one snapshot by id. A missing id returns
// an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetEvidenceSnapshot(ctx context.Context, pool *pgxpool.Pool, id string) (*regobligation.EvidenceSnapshot, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, obligation_id, captured_at, captured_by, snapshot_data FROM regulatory_evidence_snapshots WHERE id = $1`, id)
	es, err := scanEvidenceSnapshot(row)
	if err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: get %s: %w", id, err)
	}
	return es, nil
}

// ListEvidenceSnapshotsByObligation returns every snapshot for one
// obligation, newest first.
func ListEvidenceSnapshotsByObligation(ctx context.Context, pool *pgxpool.Pool, obligationID string) ([]*regobligation.EvidenceSnapshot, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, obligation_id, captured_at, captured_by, snapshot_data
		 FROM regulatory_evidence_snapshots WHERE obligation_id = $1 ORDER BY captured_at DESC`, obligationID)
	if err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: list by obligation %s: %w", obligationID, err)
	}
	defer rows.Close()
	var out []*regobligation.EvidenceSnapshot
	for rows.Next() {
		es, err := scanEvidenceSnapshot(rows)
		if err != nil {
			return nil, fmt.Errorf("regulatory_evidence_snapshots: list scan: %w", err)
		}
		out = append(out, es)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("regulatory_evidence_snapshots: list rows: %w", err)
	}
	return out, nil
}
