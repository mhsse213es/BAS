package taxii

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/iocregistry"
)

// Normalizer routes each polled STIX object by type. Phase 1 only wires the
// `indicator` branch through to iocregistry -- Phase 2/3 add branches here
// for threat-actor/intrusion-set/campaign/malware/tool without touching
// this shape.
type Normalizer struct {
	pool  *pgxpool.Pool
	store *Store
}

func NewNormalizer(pool *pgxpool.Pool, store *Store) *Normalizer {
	return &Normalizer{pool: pool, store: store}
}

// Ingest processes one page of raw objects for the given connector. Never
// returns an error for per-object problems (malformed/unsupported) -- those
// are counted in the returned PollSummary, never propagated. Only a hard
// infrastructure failure (DB unreachable) returns a non-nil error.
func (n *Normalizer) Ingest(ctx context.Context, connectorID, connectorName string, objects []json.RawMessage) (PollSummary, error) {
	var sum PollSummary
	for _, raw := range objects {
		env, err := ParseObject(raw)
		if err != nil {
			sum.Malformed++
			continue
		}
		if env.Type != "indicator" || env.PatternType != "stix" {
			sum.Skipped++
			continue
		}
		modified, err := time.Parse(time.RFC3339Nano, env.Modified)
		if err != nil {
			sum.Malformed++
			continue
		}
		already, err := n.store.HasIngested(ctx, connectorID, env.ID, modified)
		if err != nil {
			return sum, err
		}
		if already {
			continue // already-seen exact version -- not processed, not skipped, not malformed
		}
		iocType, value, ok := ParsePattern(env.Pattern)
		if !ok {
			sum.Skipped++
			continue
		}
		iocID, err := iocregistry.RegisterFromThreatFeed(ctx, n.pool, iocType, value, map[string]any{
			"stixId": env.ID, "connectorName": connectorName,
		})
		if err != nil {
			log.Printf("[taxii] register indicator failed for connector %s: %v", connectorID, err)
			sum.Malformed++
			continue
		}
		if err := n.store.RecordIngested(ctx, connectorID, env.ID, modified, iocID); err != nil {
			log.Printf("[taxii] record ingested failed for connector %s: %v", connectorID, err)
		}
		sum.Processed++
	}
	return sum, nil
}
