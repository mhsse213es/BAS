// Package search provides a maintained, ranked, multi-entity search index
// over the platform's real backend objects -- Scenarios, Runs, Findings,
// Threat Actors, Campaigns, Malware, Tools, and Techniques as of Phase 1.
// The index is a materialized Postgres table (search_documents), rebuilt
// on a timer and on-demand, never written to directly by each entity's own
// create/update code paths. See
// docs/superpowers/specs/2026-07-29-global-search-phase1-design.md.
package search

// Document is one indexed, searchable object -- the shape both the
// reindex-side builders (below) and the query-side results share.
type Document struct {
	DocType     string   `json:"docType"`
	SourceID    string   `json:"sourceId"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	// Favorited is set by Personalize() and Recents() for the requesting
	// user -- Query() never sets it (stays false), since Phase 1's plain
	// search has no notion of a user. See personalize.go.
	Favorited bool `json:"favorited"`
}
