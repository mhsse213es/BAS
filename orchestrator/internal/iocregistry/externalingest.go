package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RegisterFromExternalIngest writes one indicator reported through the
// generic inbound ingestion API (internal/ingest) as
// Source=customer_detection, Origin=customer, Status=observed -- an
// automated signal from the customer's own security tooling, not a manual
// upload (see ImportManual, which uses draft status pending review).
// metadata typically carries the original event's non-indicator fields
// (rule title, severity, technique id) for traceability. Returns the
// iocs.id so the caller (internal/ingest) can record it in its own
// idempotency ledger. Thin wrapper over the same upsertIOCFull every other
// producer (ExtractFromDetectionAlert, RegisterGenerated, ImportManual,
// RegisterFromThreatFeed) already calls.
func RegisterFromExternalIngest(ctx context.Context, pool *pgxpool.Pool, t Type, value string, metadata map[string]any) (string, error) {
	return upsertIOCFull(ctx, pool, t, value, SourceCustomerDetection, OriginCustomer, StatusObserved, metadata)
}
