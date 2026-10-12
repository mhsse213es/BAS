package ingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/iocregistry"
)

// ProcessEvent records ev's idempotency ledger row and, if it carries an
// IOC payload, registers that indicator via iocregistry -- never forcing
// the caller to match iocs' own column layout. The returned EventResult
// always has a non-error Status/Error pair on validation failure; err is
// reserved for unexpected database failures the caller should surface as a
// 500, not a per-event 4xx.
func ProcessEvent(ctx context.Context, pool *pgxpool.Pool, ev Event) (EventResult, error) {
	if ev.Source == "" {
		return EventResult{ExternalEventID: ev.ExternalEventID, Status: "error", Error: "source is required"}, nil
	}
	if ev.ExternalEventID == "" {
		return EventResult{ExternalEventID: ev.ExternalEventID, Status: "error", Error: "external_event_id is required"}, nil
	}
	if ev.IOC != nil && ev.IOC.Value != "" && !iocregistry.IsKnownType(ev.IOC.Type) {
		return EventResult{ExternalEventID: ev.ExternalEventID, Status: "error", Error: fmt.Sprintf("unknown ioc.type %q", ev.IOC.Type)}, nil
	}

	var ledgerID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO ingested_events (source, external_event_id) VALUES ($1, $2)
		 ON CONFLICT (source, external_event_id) DO NOTHING
		 RETURNING id`,
		ev.Source, ev.ExternalEventID).Scan(&ledgerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ON CONFLICT DO NOTHING produced no row: this
			// (source, external_event_id) was already ingested.
			return EventResult{ExternalEventID: ev.ExternalEventID, Status: "duplicate"}, nil
		}
		return EventResult{}, fmt.Errorf("ingest: record ledger: %w", err)
	}

	var iocID string
	if ev.IOC != nil && ev.IOC.Value != "" {
		metadata := map[string]any{
			"source": ev.Source, "eventType": ev.EventType,
			"severity": ev.Severity, "techniqueId": ev.TechniqueID,
		}
		iocID, err = iocregistry.RegisterFromExternalIngest(ctx, pool, iocregistry.Type(ev.IOC.Type), ev.IOC.Value, metadata)
		if err != nil {
			return EventResult{}, fmt.Errorf("ingest: register ioc: %w", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE ingested_events SET ioc_id = $1 WHERE id = $2`, iocID, ledgerID); err != nil {
			return EventResult{}, fmt.Errorf("ingest: update ledger: %w", err)
		}
	}

	return EventResult{ExternalEventID: ev.ExternalEventID, Status: "created", IOCID: iocID}, nil
}
