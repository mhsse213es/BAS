package search

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Recents returns up to limitEach favorited entities (most-recently-
// favorited first) followed by up to limitEach recently-selected entities
// not already favorited (most-recently-selected first, deduped to one row
// per entity). Powers the ⌘K palette's empty-input "Recents" section. See
// design doc §Architecture 3.
func Recents(ctx context.Context, pool *pgxpool.Pool, userID string, limitEach int) ([]Document, error) {
	if limitEach <= 0 {
		limitEach = 5
	}

	favRows, err := pool.Query(ctx,
		`SELECT sd.doc_type, sd.source_id, sd.title, sd.description, sd.tags
		 FROM search_favorites sf
		 JOIN search_documents sd ON sd.doc_type = sf.doc_type AND sd.source_id = sf.source_id
		 WHERE sf.user_id = $1
		 ORDER BY sf.created_at DESC
		 LIMIT $2`,
		userID, limitEach)
	if err != nil {
		return nil, err
	}
	out := []Document{}
	for favRows.Next() {
		var d Document
		if err := favRows.Scan(&d.DocType, &d.SourceID, &d.Title, &d.Description, &d.Tags); err != nil {
			favRows.Close()
			return nil, err
		}
		d.Favorited = true
		out = append(out, d)
	}
	favRows.Close()
	if err := favRows.Err(); err != nil {
		return nil, err
	}

	recentRows, err := pool.Query(ctx,
		`SELECT sd.doc_type, sd.source_id, sd.title, sd.description, sd.tags, MAX(ss.created_at) AS last_selected
		 FROM search_selections ss
		 JOIN search_documents sd ON sd.doc_type = ss.doc_type AND sd.source_id = ss.source_id
		 WHERE ss.user_id = $1
		   AND NOT EXISTS (
		     SELECT 1 FROM search_favorites sf
		     WHERE sf.user_id = ss.user_id AND sf.doc_type = ss.doc_type AND sf.source_id = ss.source_id
		   )
		 GROUP BY sd.doc_type, sd.source_id, sd.title, sd.description, sd.tags
		 ORDER BY last_selected DESC
		 LIMIT $2`,
		userID, limitEach)
	if err != nil {
		return nil, err
	}
	defer recentRows.Close()
	for recentRows.Next() {
		var d Document
		var lastSelected time.Time
		if err := recentRows.Scan(&d.DocType, &d.SourceID, &d.Title, &d.Description, &d.Tags, &lastSelected); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, recentRows.Err()
}
