package tcv

import (
	"context"
	"fmt"
	"log"
)

// VersionLookup maps artifact SHA-256 values to registry content_version ids.
// Hashes with no registry row are simply absent from the result.
type VersionLookup func(ctx context.Context, shas []string) (map[string]string, error)

// DBVersionLookup resolves hashes against content_versions.artifact_sha256.
// When several versions share identical bytes, the lowest id wins so the
// result is deterministic across runs.
func DBVersionLookup(q Querier) VersionLookup {
	return func(ctx context.Context, shas []string) (map[string]string, error) {
		out := map[string]string{}
		if len(shas) == 0 {
			return out, nil
		}
		rows, err := q.Query(ctx,
			`SELECT artifact_sha256, id FROM content_versions
			 WHERE artifact_sha256 = ANY($1)
			 ORDER BY artifact_sha256, id`, shas)
		if err != nil {
			return nil, fmt.Errorf("tcv: look up bundle artifact hashes: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var sha, id string
			if err := rows.Scan(&sha, &id); err != nil {
				return nil, fmt.Errorf("tcv: scan bundle artifact hash row: %w", err)
			}
			if _, seen := out[sha]; !seen {
				out[sha] = id
			}
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("tcv: iterate bundle artifact hash rows: %w", err)
		}
		return out, nil
	}
}

// IngestBundleManifest records one bundle_packaged event per shipped file
// that is a known registry artifact. It returns how many events were written
// (a re-run that finds an existing event counts it as written, since the
// ledger is idempotent) and the hashes with no registry match.
//
// It fails only on an invalid manifest or a failed lookup. A failed write is
// logged and skipped, matching the ledger's log-and-continue contract, so one
// bad row never aborts the run.
func IngestBundleManifest(ctx context.Context, q Querier, lookup VersionLookup, m BundleManifest) (recorded int, unmatched []string, err error) {
	if err := m.Validate(); err != nil {
		return 0, nil, err
	}
	shas := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		shas = append(shas, e.SHA256)
	}
	versions, err := lookup(ctx, shas)
	if err != nil {
		return 0, nil, err
	}
	events, unmatched := BundlePackagedEvents(m, versions)
	for _, e := range events {
		if err := RecordPipelineEvent(ctx, q, e); err != nil {
			log.Printf("[tcv/bundle] record bundle_packaged for %s: %v", e.ContentVersionID, err)
			continue
		}
		recorded++
	}
	return recorded, unmatched, nil
}
