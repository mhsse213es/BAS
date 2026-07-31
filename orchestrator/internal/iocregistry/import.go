package iocregistry

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ImportEntry is one caller-supplied (type, value) pair to register.
type ImportEntry struct {
	Type  Type   `json:"type"`
	Value string `json:"value"`
}

// ImportManual writes each entry as Origin=customer, Status=draft, Source=manual --
// customer-provided IOCs meant to drive future simulations, not observations of anything
// that has happened yet. Best-effort per-entry; returns the count actually written and
// the first error encountered, if any (partial success is reported, not silently lost).
func ImportManual(ctx context.Context, pool *pgxpool.Pool, entries []ImportEntry) (written int, err error) {
	for _, e := range entries {
		if _, ierr := upsertIOCFull(ctx, pool, e.Type, e.Value, SourceManual, OriginCustomer, StatusDraft, nil); ierr != nil {
			if err == nil {
				err = ierr
			}
			continue
		}
		written++
	}
	return written, err
}
