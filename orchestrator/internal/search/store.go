package search

import (
	"context"
	"fmt"
	"strings"

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

// Query full-text-searches search_documents and returns a flat, ranked
// list -- never pre-grouped by type, see the design doc's Architecture §4.
// An empty/whitespace-only q returns an empty slice, not an error and not
// the full table.
func Query(ctx context.Context, pool *pgxpool.Pool, q string, limit int) ([]Document, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return []Document{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}

	rows, err := pool.Query(ctx,
		`SELECT doc_type, source_id, title, description, tags
		 FROM search_documents, plainto_tsquery('english', $1) query
		 WHERE search_vector @@ query
		 ORDER BY ts_rank(search_vector, query) DESC
		 LIMIT $2`,
		q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Document{}
	for rows.Next() {
		var d Document
		if err := rows.Scan(&d.DocType, &d.SourceID, &d.Title, &d.Description, &d.Tags); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
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
		{"actor", func() ([]Document, error) { return actorsFrom(ctx, pool) }},
		{"campaign", func() ([]Document, error) { return campaignsFrom(ctx, pool) }},
		{"malware", func() ([]Document, error) { return malwareFrom(ctx, pool) }},
		{"tool", func() ([]Document, error) { return toolsFrom(ctx, pool) }},
		{"technique", func() ([]Document, error) { return techniquesFrom(ctx, pool) }},
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
