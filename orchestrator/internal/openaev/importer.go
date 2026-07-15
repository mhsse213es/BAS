package openaev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// contentStore is the narrow slice of SQLStore the Importer needs — lets tests
// fake it without a real database. *SQLStore satisfies this.
type contentStore interface {
	SyncState(ctx context.Context, openaevScenarioID string) (sourceUpdatedAt time.Time, contentHash string, found bool, err error)
	Upsert(ctx context.Context, scenario Scenario, detail Detail, contentHash string, sizeBytes, sourceVersion int) error
}

type SyncResult struct {
	Created int
	Updated int
	Skipped int
	Errored int
	Errors  []string
}

type Importer struct {
	store contentStore
}

func NewImporter(store contentStore) *Importer {
	return &Importer{store: store}
}

// SyncAll runs a full sync against provider: list, delta-check each ref
// against stored state, fetch+parse+normalize+store only what changed. One
// failing scenario is logged and counted, never aborts the rest — matches the
// ART reseed pattern's error isolation.
func (im *Importer) SyncAll(ctx context.Context, provider ContentProvider) (*SyncResult, error) {
	refs, err := provider.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list scenarios: %w", err)
	}

	result := &SyncResult{}
	for _, ref := range refs {
		storedUpdated, storedHash, found, _ := im.store.SyncState(ctx, ref.ID)
		if found && !ref.SourceUpdated.After(storedUpdated) {
			result.Skipped++
			continue
		}

		data, err := provider.Fetch(ctx, ref.ID)
		if err != nil {
			result.Errored++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: fetch failed: %v", ref.ID, err))
			continue
		}

		hash := sha256Hex(data)
		if found && hash == storedHash {
			result.Skipped++
			continue
		}

		if err := im.processOne(ctx, data, hash, len(data)); err != nil {
			result.Errored++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ref.ID, err))
			continue
		}
		if found {
			result.Updated++
		} else {
			result.Created++
		}
	}
	return result, nil
}

// ImportOne handles the air-gapped manual-upload path: no List/delta-check,
// the uploaded bytes are the one bundle to process.
func (im *Importer) ImportOne(ctx context.Context, data []byte) (*SyncResult, error) {
	result := &SyncResult{}
	hash := sha256Hex(data)
	if err := im.processOne(ctx, data, hash, len(data)); err != nil {
		result.Errored++
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}
	result.Created++
	return result, nil
}

func (im *Importer) processOne(ctx context.Context, data []byte, hash string, size int) error {
	parsed, err := ParseBundle(data)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	scenario, detail := Normalize(parsed)
	if err := im.store.Upsert(ctx, scenario, detail, hash, size, parsed.ExportVersion); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
