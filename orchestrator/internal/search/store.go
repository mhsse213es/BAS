package search

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

// reindexOneType replaces every search_documents row of the given docType
// with docs, in one transaction -- a full rebuild, not incremental
// diffing. Rebuilding one type never empties or blocks queries against any
// other type, since each type's rebuild is its own transaction.
func reindexOneType(ctx context.Context, pool *pgxpool.Pool, docType string, docs []Document) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM search_documents WHERE doc_type = $1`, docType); err != nil {
		return err
	}
	for _, d := range docs {
		// pgx encodes a nil Go []string as SQL NULL, not an empty array --
		// violates tags' NOT NULL constraint for any Document built without
		// explicitly setting Tags. Same recurring gotcha internal/intelligence
		// already coalesces against.
		if d.Tags == nil {
			d.Tags = []string{}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO search_documents (doc_type, source_id, title, description, tags, search_vector)
			 VALUES ($1,$2,$3,$4,$5,
			   setweight(to_tsvector('english', $3::text), 'A') ||
			   setweight(to_tsvector('english', coalesce($4::text, '')), 'B') ||
			   setweight(to_tsvector('english', array_to_string($5::text[], ' ')), 'C'))`,
			docType, d.SourceID, d.Title, d.Description, d.Tags); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ReindexAll rebuilds every indexed entity type, one type at a time.
func ReindexAll(ctx context.Context, pool *pgxpool.Pool, engine *scenario.Engine) error {
	steps := []struct {
		docType string
		build   func() ([]Document, error)
	}{
		{"scenario", func() ([]Document, error) { return scenariosFrom(engine), nil }},
		{"run", func() ([]Document, error) { return runsFrom(ctx, pool) }},
		{"finding", func() ([]Document, error) { return findingsFrom(ctx, pool) }},
	}
	for _, s := range steps {
		docs, err := s.build()
		if err != nil {
			return fmt.Errorf("build %s documents: %w", s.docType, err)
		}
		if err := reindexOneType(ctx, pool, s.docType, docs); err != nil {
			return fmt.Errorf("reindex %s: %w", s.docType, err)
		}
	}
	return nil
}
