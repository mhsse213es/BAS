package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RegisterFromThreatFeed writes one TAXII-sourced indicator into the
// registry as Source=threat_feed, Origin=threat-feed, Status=reported.
// metadata typically carries {"stixId":..., "connectorName":...} for
// traceability. Returns the iocs.id so the caller (internal/taxii) can
// record it in its own idempotency ledger. Thin wrapper over the same
// upsertIOCFull every other producer (ExtractFromDetectionAlert,
// RegisterGenerated, ImportManual) already calls.
func RegisterFromThreatFeed(ctx context.Context, pool *pgxpool.Pool, t Type, value string, metadata map[string]any) (string, error) {
	return upsertIOCFull(ctx, pool, t, value, SourceThreatFeed, OriginThreatFeed, StatusReported, metadata)
}
