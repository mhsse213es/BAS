# Global Search Phase 3 (Ranking & Personalization) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Layer personal recency, org-wide popularity, and explicit favorites on top of Phase 1's `ts_rank`-only relevance, and add an empty-input "Recents" section to the Phase 2 `⌘K` palette.

**Architecture:** Two new Postgres tables (`search_selections`, an append-only event log; `search_favorites`, a toggle table) feed a new `search.Personalize()` function that re-orders Phase 1's existing `Query()` results in Go — favorites hard-pinned first, then a small recency/popularity score bump layered on relevance for the rest. Three new endpoints (`POST /api/search/select`, `POST /api/search/favorite`, `GET /api/search/recents`) and matching `⌘K` palette changes (a star affordance per result row, a fire-and-forget tracking call, an empty-input Recents section).

**Tech Stack:** Go + pgx v5 + Postgres (backend, matches Phase 1), vanilla JS in `cmd/server/wwwroot/index.html` (frontend, matches Phase 2). No new dependencies.

## Global Constraints

- No changes to Phase 1's `search.Query()` SQL — personalization is a post-processing step over its existing results, not a query rewrite. (Spec §Architecture 2, §Non-Goals)
- Favorites are a **hard pin** above everything else, in their original relevance order among themselves — never a blended score that a strong relevance/recency match could theoretically outrank. (Spec §Architecture 2, brainstorming decision)
- Recency and popularity both use a fixed **30-day window** and fixed constants for v1 — no admin-configurable weights, no decay/cleanup job. (Spec §Non-Goals)
- The star (favorite) affordance appears **only on search-result rows inside the ⌘K palette** (typed-query results and the new Recents section) — not on the static Navigate/Actions rows, not on any entity detail view. (Spec §Non-Goals, brainstorming decision)
- Empty-input behavior gains a new **Recents section prepended above** the existing static Navigate/Actions list — that static list itself keeps rendering exactly as Phase 2 left it; the byte-for-byte guarantee from Phase 2 applies to that list, not to the palette's contents as a whole. (Spec §Architecture 4, brainstorming decision)
- Use the existing `apicall()` helper for all new frontend requests, and `auth.ClaimsFrom(r.Context())` for all new backend handlers that need the current user — both are this codebase's established conventions, confirmed during Phase 1/2/3 planning.
- `internal/search` package tests use the existing `sharedDB *testutil.TestDB` / `RunWithPool` / `testing.Short()`-skip pattern already established in `store_test.go` — do not redeclare `TestMain` in new test files in this package, it already exists.
- **This project has no automated frontend test harness** (confirmed across Phases 1-2) — frontend verification stays manual, as in Phase 2.

---

## File Structure

- Modify `orchestrator/internal/db/content_schema.go` — add `search_selections` and `search_favorites` table definitions.
- Modify `orchestrator/internal/search/document.go` — add `Favorited bool` field to `Document`.
- Create `orchestrator/internal/search/personalize.go` — `Personalize()` and its three signal-loading helpers.
- Create `orchestrator/internal/search/personalize_test.go` — real-Postgres tests for `Personalize()`.
- Create `orchestrator/internal/search/recents.go` — `Recents()`.
- Create `orchestrator/internal/search/recents_test.go` — real-Postgres tests for `Recents()`.
- Modify `orchestrator/internal/api/search_handlers.go` — add `SearchSelect`, `SearchFavorite`, `SearchRecents`; wire `Personalize()` into the existing `Search` handler.
- Create `orchestrator/internal/api/search_handlers_test.go` — handler-level tests for the 3 new endpoints (Phase 1 had none; this phase's handlers are stateful enough to need them).
- Modify `orchestrator/internal/api/routes.go` — register the 3 new routes.
- Modify `orchestrator/internal/api/rbac_matrix_test.go` — add the 3 new route entries.
- Modify `orchestrator/cmd/server/wwwroot/index.html` — extend `openCmdk()`/`cmdkOpenResult()` again, add `cmdkToggleFavorite()`.

---

### Task 1: Schema, `Document.Favorited`, and `Personalize()`

**Files:**
- Modify: `orchestrator/internal/db/content_schema.go:375` (right after the `idx_search_documents_vector` line, before the closing `}` of the `stmts` slice)
- Modify: `orchestrator/internal/search/document.go:12-18`
- Create: `orchestrator/internal/search/personalize.go`
- Create: `orchestrator/internal/search/personalize_test.go`

**Interfaces:**
- Consumes: `Document{DocType, SourceID, Title, Description string, Tags []string}` (`internal/search/document.go`, Phase 1).
- Produces: `Document.Favorited bool` (new field, `json:"favorited"`); `func Personalize(ctx context.Context, pool *pgxpool.Pool, userID string, results []Document) ([]Document, error)` — Task 3's `Search` handler and Task 2 both need this exact signature.

- [ ] **Step 1: Add the two new tables**

In `orchestrator/internal/db/content_schema.go`, find this exact line (the last line of the `stmts` slice from Phase 1):

```go
		`CREATE INDEX IF NOT EXISTS idx_search_documents_vector ON search_documents USING GIN (search_vector)`,
	}
```

Replace it with:

```go
		`CREATE INDEX IF NOT EXISTS idx_search_documents_vector ON search_documents USING GIN (search_vector)`,

		// search_selections is an append-only event log -- one row per time a
		// user opens a search result. Powers both personal recency (rows
		// filtered to one user_id) and org popularity (rows counted across all
		// users) from the same log. See docs/superpowers/specs/2026-07-29-
		// global-search-phase3-design.md Architecture §1.
		`CREATE TABLE IF NOT EXISTS search_selections (
			id         bigserial   PRIMARY KEY,
			user_id    text        NOT NULL REFERENCES users(id),
			doc_type   text        NOT NULL,
			source_id  text        NOT NULL,
			created_at timestamptz NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_search_selections_user ON search_selections (user_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_search_selections_entity ON search_selections (doc_type, source_id, created_at DESC)`,

		// search_favorites is a real toggle table (insert/delete), not an
		// event log -- a favorite is a boolean state, not a history, and the
		// UNIQUE constraint makes "is this favorited" a single indexed lookup.
		`CREATE TABLE IF NOT EXISTS search_favorites (
			id         bigserial   PRIMARY KEY,
			user_id    text        NOT NULL REFERENCES users(id),
			doc_type   text        NOT NULL,
			source_id  text        NOT NULL,
			created_at timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (user_id, doc_type, source_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_search_favorites_user ON search_favorites (user_id)`,
	}
```

- [ ] **Step 2: Add `Favorited` to `Document`**

In `orchestrator/internal/search/document.go`, replace:

```go
type Document struct {
	DocType     string   `json:"docType"`
	SourceID    string   `json:"sourceId"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}
```

With:

```go
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
```

- [ ] **Step 3: Write the failing tests for `Personalize()`**

Create `orchestrator/internal/search/personalize_test.go`:

```go
package search

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedSearchUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, password_hash, role, is_active) VALUES ($1, 'x', 'viewer', true) RETURNING id`,
		username).Scan(&id); err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	return id
}

func TestPersonalize_FavoritesSortFirstInOriginalOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "fav-order-user")
		if _, err := pool.Exec(ctx, `INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,'scenario','s2')`, userID); err != nil {
			t.Fatalf("seed favorite: %v", err)
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "First (relevance order)"},
			{DocType: "scenario", SourceID: "s2", Title: "Second (relevance order, but favorited)"},
			{DocType: "scenario", SourceID: "s3", Title: "Third (relevance order)"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if len(out) != 3 || out[0].SourceID != "s2" {
			t.Fatalf("Personalize() = %+v, want s2 (favorited) first", out)
		}
		if !out[0].Favorited {
			t.Errorf("out[0].Favorited = false, want true")
		}
		if out[1].SourceID != "s1" || out[2].SourceID != "s3" {
			t.Errorf("non-favorited remainder = [%s, %s], want original relevance order [s1, s3]", out[1].SourceID, out[2].SourceID)
		}
	})
}

func TestPersonalize_PersonalRecencyOutranksNeverOpened(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "recency-user")
		if _, err := pool.Exec(ctx, `INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','s2')`, userID); err != nil {
			t.Fatalf("seed selection: %v", err)
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Never opened"},
			{DocType: "scenario", SourceID: "s2", Title: "Recently opened by this user"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if out[0].SourceID != "s2" {
			t.Fatalf("Personalize() = %+v, want s2 (recently opened) ranked first", out)
		}
	})
}

func TestPersonalize_OrgPopularityAffectsUserWithNoPersonalHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		popularUser := seedSearchUser(t, pool, "popular-selector")
		viewerUser := seedSearchUser(t, pool, "no-history-viewer")
		for i := 0; i < 5; i++ {
			if _, err := pool.Exec(ctx, `INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','s2')`, popularUser); err != nil {
				t.Fatalf("seed org selection %d: %v", i, err)
			}
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Unopened by anyone"},
			{DocType: "scenario", SourceID: "s2", Title: "Popular org-wide"},
		}
		out, err := Personalize(ctx, pool, viewerUser, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if out[0].SourceID != "s2" {
			t.Fatalf("Personalize() = %+v, want s2 (org-popular) ranked first even with no personal history", out)
		}
	})
}

func TestPersonalize_SelectionsOlderThan30DaysDontAffectRanking(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "stale-history-user")
		old := time.Now().Add(-45 * 24 * time.Hour)
		if _, err := pool.Exec(ctx,
			`INSERT INTO search_selections (user_id, doc_type, source_id, created_at) VALUES ($1,'scenario','s2',$2)`,
			userID, old); err != nil {
			t.Fatalf("seed stale selection: %v", err)
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "First (relevance order)"},
			{DocType: "scenario", SourceID: "s2", Title: "Selected 45 days ago"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if out[0].SourceID != "s1" {
			t.Fatalf("Personalize() = %+v, want unmodified relevance order (stale selection outside 30-day window must not affect ranking)", out)
		}
	})
}

func TestPersonalize_NoSignalsReturnsUnmodifiedOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "no-signal-user")

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "First"},
			{DocType: "scenario", SourceID: "s2", Title: "Second"},
			{DocType: "scenario", SourceID: "s3", Title: "Third"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		for i, d := range out {
			if d.SourceID != results[i].SourceID {
				t.Fatalf("Personalize() = %+v, want unmodified order %+v", out, results)
			}
		}
	})
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -run TestPersonalize -v`
Expected: FAIL with `undefined: Personalize` (compile error — the function doesn't exist yet).

- [ ] **Step 5: Implement `Personalize()`**

Create `orchestrator/internal/search/personalize.go`:

```go
package search

import (
	"context"
	"math"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

// popularityWeight keeps the org-wide popularity signal intentionally
// smaller than personal recency -- popularity is a secondary nudge, not a
// competing primary signal. See design doc §Architecture 2.
const popularityWeight = 0.1

// Personalize re-orders results (already ranked by ts_rank via Query) for a
// specific user: their favorited entities are hard-pinned first, in their
// original relevance order; the remainder is re-sorted using a small
// recency/popularity score bump layered on top of relevance -- a strong
// relevance match is never inverted by a weak recency/popularity one, since
// ties in the bump (the common case, most results have no personalization
// signal at all) fall back to original relevance order via sort.SliceStable.
func Personalize(ctx context.Context, pool *pgxpool.Pool, userID string, results []Document) ([]Document, error) {
	if len(results) == 0 || userID == "" {
		return results, nil
	}

	favSet, err := favoriteSet(ctx, pool, userID)
	if err != nil {
		return nil, err
	}
	recency, err := recencyScores(ctx, pool, userID)
	if err != nil {
		return nil, err
	}
	popularity, err := popularityScores(ctx, pool)
	if err != nil {
		return nil, err
	}

	favorited := make([]Document, 0, len(results))
	rest := make([]Document, 0, len(results))
	for _, d := range results {
		d.Favorited = favSet[key(d.DocType, d.SourceID)]
		if d.Favorited {
			favorited = append(favorited, d)
		} else {
			rest = append(rest, d)
		}
	}

	type scored struct {
		doc  Document
		bump float64
	}
	scoredRest := make([]scored, len(rest))
	for i, d := range rest {
		k := key(d.DocType, d.SourceID)
		scoredRest[i] = scored{doc: d, bump: recency[k] + popularity[k]}
	}
	sort.SliceStable(scoredRest, func(i, j int) bool {
		return scoredRest[i].bump > scoredRest[j].bump
	})

	out := make([]Document, 0, len(results))
	out = append(out, favorited...)
	for _, s := range scoredRest {
		out = append(out, s.doc)
	}
	return out, nil
}

func key(docType, sourceID string) string { return docType + ":" + sourceID }

func favoriteSet(ctx context.Context, pool *pgxpool.Pool, userID string) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT doc_type, source_id FROM search_favorites WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var dt, sid string
		if err := rows.Scan(&dt, &sid); err != nil {
			return nil, err
		}
		out[key(dt, sid)] = true
	}
	return out, rows.Err()
}

// recencyScores returns, for each entity this user selected in the last 30
// days, 1.0 / (1.0 + daysSinceLastSelection) -- close to 1.0 for something
// opened moments ago, close to 0.03 for something opened 30 days ago.
func recencyScores(ctx context.Context, pool *pgxpool.Pool, userID string) (map[string]float64, error) {
	rows, err := pool.Query(ctx,
		`SELECT doc_type, source_id, EXTRACT(EPOCH FROM (NOW() - MAX(created_at))) / 86400.0
		 FROM search_selections
		 WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days'
		 GROUP BY doc_type, source_id`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var dt, sid string
		var daysSince float64
		if err := rows.Scan(&dt, &sid, &daysSince); err != nil {
			return nil, err
		}
		out[key(dt, sid)] = 1.0 / (1.0 + daysSince)
	}
	return out, rows.Err()
}

// popularityScores returns, for each entity selected by anyone in the last
// 30 days, log(1+count)*popularityWeight -- log-scaled so 50 vs. 500
// selections isn't a 10x swing in the final bump.
func popularityScores(ctx context.Context, pool *pgxpool.Pool) (map[string]float64, error) {
	rows, err := pool.Query(ctx,
		`SELECT doc_type, source_id, COUNT(*)
		 FROM search_selections
		 WHERE created_at > NOW() - INTERVAL '30 days'
		 GROUP BY doc_type, source_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var dt, sid string
		var count int
		if err := rows.Scan(&dt, &sid, &count); err != nil {
			return nil, err
		}
		out[key(dt, sid)] = math.Log(1+float64(count)) * popularityWeight
	}
	return out, rows.Err()
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -run TestPersonalize -v`
Expected: PASS, all 5 tests.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/db/content_schema.go internal/search/document.go internal/search/personalize.go internal/search/personalize_test.go
git commit -m "feat(search): Personalize() -- favorites, recency, popularity ranking (Global Search Phase 3)"
```

---

### Task 2: `Recents()`

**Files:**
- Create: `orchestrator/internal/search/recents.go`
- Create: `orchestrator/internal/search/recents_test.go`

**Interfaces:**
- Consumes: `search_favorites`/`search_selections`/`search_documents` tables (Task 1, Phase 1); `Document` (with `Favorited`, Task 1).
- Produces: `func Recents(ctx context.Context, pool *pgxpool.Pool, userID string, limitEach int) ([]Document, error)` — Task 3's `SearchRecents` handler needs this exact signature.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/search/recents_test.go`:

```go
package search

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRecents_FavoritesBeforeRecentsDedupedAndLimited(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "recents-user")

		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "fav1", Title: "Favorited Scenario"},
			{DocType: "scenario", SourceID: "rec1", Title: "Recently Opened Scenario"},
			{DocType: "scenario", SourceID: "both1", Title: "Favorited AND Selected"},
		}); err != nil {
			t.Fatalf("seed search_documents: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,'scenario','fav1'),($1,'scenario','both1')`,
			userID); err != nil {
			t.Fatalf("seed favorites: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','rec1'),($1,'scenario','both1')`,
			userID); err != nil {
			t.Fatalf("seed selections: %v", err)
		}

		out, err := Recents(ctx, pool, userID, 5)
		if err != nil {
			t.Fatalf("Recents: %v", err)
		}

		var sawFav1, sawBoth1, sawRec1 bool
		both1Count := 0
		for _, d := range out {
			switch d.SourceID {
			case "fav1":
				sawFav1 = true
				if !d.Favorited {
					t.Errorf("fav1.Favorited = false, want true")
				}
			case "both1":
				sawBoth1 = true
				both1Count++
				if !d.Favorited {
					t.Errorf("both1.Favorited = false, want true")
				}
			case "rec1":
				sawRec1 = true
				if d.Favorited {
					t.Errorf("rec1.Favorited = true, want false (never favorited)")
				}
			}
		}
		if !sawFav1 || !sawBoth1 || !sawRec1 {
			t.Fatalf("Recents() = %+v, want fav1, both1, and rec1 all present", out)
		}
		if both1Count != 1 {
			t.Fatalf("both1 (favorited AND selected) appeared %d times, want exactly 1 (deduped, not double-listed)", both1Count)
		}
	})
}

func TestRecents_NoHistoryReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "no-recents-user")

		out, err := Recents(ctx, pool, userID, 5)
		if err != nil {
			t.Fatalf("Recents: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("Recents() = %+v, want empty for a user with no favorites/selections", out)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -run TestRecents -v`
Expected: FAIL with `undefined: Recents` (compile error).

- [ ] **Step 3: Implement `Recents()`**

Create `orchestrator/internal/search/recents.go`:

```go
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -run TestRecents -v`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/search/recents.go internal/search/recents_test.go
git commit -m "feat(search): Recents() -- favorites+recent selections for empty-input palette (Global Search Phase 3)"
```

---

### Task 3: HTTP handlers, routing, RBAC matrix

**Files:**
- Modify: `orchestrator/internal/api/search_handlers.go` (entire file, currently 30 lines)
- Create: `orchestrator/internal/api/search_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go:206-207`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:92-93`

**Interfaces:**
- Consumes: `search.Query`, `search.Personalize`, `search.Recents` (Tasks 1-2, Phase 1); `auth.ClaimsFrom(ctx) (*auth.Claims, bool)` with `Claims.UserID string` (existing, `internal/auth/jwt.go`, `internal/auth/middleware.go`); `respond`/`jsonError` (existing, `internal/api/handlers.go`).
- Produces: `h.SearchSelect`, `h.SearchFavorite`, `h.SearchRecents` (new `*Handler` methods) — Task 4's frontend calls these three endpoints by URL, not by Go symbol, so no further Go interface dependency.

- [ ] **Step 1: Write the failing handler tests**

Create `orchestrator/internal/api/search_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/search"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSearchSelect_NoClaimsUnauthorized(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/search/select", nil)
	rec := httptest.NewRecorder()
	h.SearchSelect(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no claims in context)", rec.Code)
	}
}

func TestSearchFavorite_MalformedBody(t *testing.T) {
	userID := "does-not-matter-claims-check-runs-first"
	req := authedRequest(t, http.MethodPost, "/api/search/favorite", bytes.NewReader([]byte("{not json")), auth.RoleViewer, userID)
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	if rec := callAuthed(h.SearchFavorite, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSearchSelect_InsertsOneRowPerCall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "select-user", "password123", "viewer", true)

		body, _ := json.Marshal(map[string]string{"docType": "scenario", "sourceId": "s1"})
		req1 := authedRequest(t, http.MethodPost, "/api/search/select", bytes.NewReader(body), auth.RoleViewer, userID)
		if rec := callAuthed(h.SearchSelect, req1); rec.Code != http.StatusOK {
			t.Fatalf("first select: status = %d, want 200", rec.Code)
		}
		req2 := authedRequest(t, http.MethodPost, "/api/search/select", bytes.NewReader(body), auth.RoleViewer, userID)
		if rec := callAuthed(h.SearchSelect, req2); rec.Code != http.StatusOK {
			t.Fatalf("second select: status = %d, want 200", rec.Code)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM search_selections WHERE user_id=$1 AND doc_type='scenario' AND source_id='s1'`,
			userID).Scan(&count); err != nil {
			t.Fatalf("count selections: %v", err)
		}
		if count != 2 {
			t.Errorf("selection row count = %d, want 2 (repeat calls accumulate, they don't upsert)", count)
		}
	})
}

func TestSearchFavorite_TogglesOnRepeatedCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "fav-user", "password123", "viewer", true)
		body, _ := json.Marshal(map[string]string{"docType": "scenario", "sourceId": "s1"})

		req1 := authedRequest(t, http.MethodPost, "/api/search/favorite", bytes.NewReader(body), auth.RoleViewer, userID)
		rec1 := callAuthed(h.SearchFavorite, req1)
		var res1 map[string]bool
		if err := json.Unmarshal(rec1.Body.Bytes(), &res1); err != nil {
			t.Fatalf("decode first response: %v", err)
		}
		if !res1["favorited"] {
			t.Fatalf("first toggle: favorited = %v, want true", res1["favorited"])
		}

		req2 := authedRequest(t, http.MethodPost, "/api/search/favorite", bytes.NewReader(body), auth.RoleViewer, userID)
		rec2 := callAuthed(h.SearchFavorite, req2)
		var res2 map[string]bool
		if err := json.Unmarshal(rec2.Body.Bytes(), &res2); err != nil {
			t.Fatalf("decode second response: %v", err)
		}
		if res2["favorited"] {
			t.Fatalf("second toggle: favorited = %v, want false", res2["favorited"])
		}
	})
}

func TestSearchRecents_ReturnsFavoritesBeforeRecents(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		userID := seedUser(t, pool, "recents-handler-user", "password123", "viewer", true)

		if _, err := pool.Exec(ctx,
			`INSERT INTO search_documents (doc_type, source_id, title, description, tags, search_vector)
			 VALUES ('scenario','h-fav','Handler Favorite','','{}', to_tsvector('english','Handler Favorite')),
			        ('scenario','h-rec','Handler Recent','','{}', to_tsvector('english','Handler Recent'))`); err != nil {
			t.Fatalf("seed search_documents: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,'scenario','h-fav')`, userID); err != nil {
			t.Fatalf("seed favorite: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','h-rec')`, userID); err != nil {
			t.Fatalf("seed selection: %v", err)
		}

		req := authedRequest(t, http.MethodGet, "/api/search/recents", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.SearchRecents, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var results []search.Document
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("results = %+v, want 2 (one favorite, one recent)", results)
		}
		if results[0].SourceID != "h-fav" || !results[0].Favorited {
			t.Errorf("results[0] = %+v, want h-fav favorited first", results[0])
		}
		if results[1].SourceID != "h-rec" || results[1].Favorited {
			t.Errorf("results[1] = %+v, want h-rec not favorited", results[1])
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestSearchSelect|TestSearchFavorite|TestSearchRecents" -v`
Expected: FAIL with compile errors (`h.SearchSelect`, `h.SearchFavorite`, `h.SearchRecents` undefined).

- [ ] **Step 3: Implement the handlers and wire `Personalize` into `Search`**

Replace the full contents of `orchestrator/internal/api/search_handlers.go` with:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/search"
)

// GET /api/search?q=<term>&limit=<n>
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	results, err := search.Query(r.Context(), h.db, q, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Personalization is best-effort: if it fails, fall back to
	// unpersonalized relevance-only results rather than erroring the whole
	// search -- a degraded ranking beats no results.
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		if personalized, perr := search.Personalize(r.Context(), h.db, c.UserID, results); perr == nil {
			results = personalized
		}
	}
	respond(w, results)
}

// POST /api/search/reindex
func (h *Handler) SearchReindex(w http.ResponseWriter, r *http.Request) {
	if err := search.ReindexAll(r.Context(), h.db, h.engine); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}

type searchEntityBody struct {
	DocType  string `json:"docType"`
	SourceID string `json:"sourceId"`
}

// POST /api/search/select — fire-and-forget selection tracking, called by
// the frontend right when a search result is opened. Any authenticated
// user; failures here never block navigation client-side.
func (h *Handler) SearchSelect(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body searchEntityBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DocType == "" || body.SourceID == "" {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,$2,$3)`,
		c.UserID, body.DocType, body.SourceID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]string{"status": "ok"})
}

// POST /api/search/favorite — toggles: inserts if absent, deletes if
// present. Any authenticated user.
func (h *Handler) SearchFavorite(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body searchEntityBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DocType == "" || body.SourceID == "" {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}

	var exists bool
	if err := h.db.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM search_favorites WHERE user_id=$1 AND doc_type=$2 AND source_id=$3)`,
		c.UserID, body.DocType, body.SourceID).Scan(&exists); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		if _, err := h.db.Exec(r.Context(),
			`DELETE FROM search_favorites WHERE user_id=$1 AND doc_type=$2 AND source_id=$3`,
			c.UserID, body.DocType, body.SourceID); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respond(w, map[string]bool{"favorited": false})
		return
	}

	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,$2,$3)`,
		c.UserID, body.DocType, body.SourceID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]bool{"favorited": true})
}

// GET /api/search/recents — favorites + recent selections for the empty-
// input ⌘K palette state. Any authenticated user.
func (h *Handler) SearchRecents(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok || c == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	results, err := search.Recents(r.Context(), h.db, c.UserID, 5)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, results)
}
```

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, replace:

```go
		r.Get("/api/search", h.Search)
		r.With(auth.RequirePermission(auth.CanReindexSearch)).Post("/api/search/reindex", h.SearchReindex)
```

With:

```go
		r.Get("/api/search", h.Search)
		r.With(auth.RequirePermission(auth.CanReindexSearch)).Post("/api/search/reindex", h.SearchReindex)
		r.Post("/api/search/select", h.SearchSelect)
		r.Post("/api/search/favorite", h.SearchFavorite)
		r.Get("/api/search/recents", h.SearchRecents)
```

- [ ] **Step 5: Update the RBAC matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, replace:

```go
	{http.MethodGet, "/api/search", tierAny, ""},
	{http.MethodPost, "/api/search/reindex", tierPermission, auth.CanReindexSearch},
```

With:

```go
	{http.MethodGet, "/api/search", tierAny, ""},
	{http.MethodPost, "/api/search/reindex", tierPermission, auth.CanReindexSearch},
	{http.MethodPost, "/api/search/select", tierAny, ""},
	{http.MethodPost, "/api/search/favorite", tierAny, ""},
	{http.MethodGet, "/api/search/recents", tierAny, ""},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestSearchSelect|TestSearchFavorite|TestSearchRecents|TestRBACMatrix" -v`
Expected: PASS, all tests including `TestRBACMatrix_NoDrift`.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/search_handlers.go internal/api/search_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): search select/favorite/recents endpoints, personalized ranking (Global Search Phase 3)"
```

---

### Task 4: `⌘K` palette — star affordance, selection tracking, Recents section

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (the `cmdkOpenResult`/`cmdkResultFallback`/`openCmdk` region, currently lines 11712-11876)

**Interfaces:**
- Consumes: `apicall(path, opts)` (existing); `GET /api/search` (now returns `favorited` per result, Task 3); `POST /api/search/select`, `POST /api/search/favorite`, `GET /api/search/recents` (Task 3).
- Produces: `cmdkToggleFavorite(r, onDone)` (new, module-level) — self-contained, nothing outside this edit calls it yet.

This is one cohesive change to the same function Phase 2 built, same reasoning as Phase 2's Task 1: it can't be shipped half-done.

- [ ] **Step 1: Confirm the current exact content before editing**

```bash
cd orchestrator && sed -n '11712,11876p' cmd/server/wwwroot/index.html
```

Confirm this matches Phase 2's final state (the block quoted in Step 2 below). If it has drifted, stop and re-read the current version before proceeding.

- [ ] **Step 2: Add the tracking call to `cmdkOpenResult` and add `cmdkToggleFavorite`**

Replace this exact current block:

```js
// cmdkOpenResult dispatches a selected search result to a real navigation
// action per docType, or the minimal fallback popup for the 3 types with
// no detail view anywhere in this app yet (campaign/malware/tool).
function cmdkOpenResult(r) {
  if (r.docType === 'run') {
```

With:

```js
// cmdkOpenResult dispatches a selected search result to a real navigation
// action per docType, or the minimal fallback popup for the 3 types with
// no detail view anywhere in this app yet (campaign/malware/tool). Also
// fires a fire-and-forget selection-tracking call (Global Search Phase 3) --
// never blocks navigation, failures are silently swallowed.
function cmdkOpenResult(r) {
  apicall('/api/search/select', {
    method: 'POST',
    body: JSON.stringify({ docType: r.docType, sourceId: r.sourceId })
  }).catch(function() {});
  if (r.docType === 'run') {
```

Then, right after the existing `cmdkResultFallback` function's closing brace and blank line (i.e. immediately before `function openCmdk() {`), insert:

```js
// cmdkToggleFavorite calls POST /api/search/favorite for r, mutates
// r.favorited in place on success (r is a reference into whichever array
// it came from -- cmdkSearchResults or cmdkRecents inside openCmdk()'s
// closure -- so that array reflects the new state on the next render),
// then invokes onDone to trigger a repaint. Fails soft: a network error
// leaves r.favorited untouched but still calls onDone so the UI never hangs.
function cmdkToggleFavorite(r, onDone) {
  apicall('/api/search/favorite', {
    method: 'POST',
    body: JSON.stringify({ docType: r.docType, sourceId: r.sourceId })
  }).then(function(res) {
    r.favorited = !!(res && res.favorited);
    onDone();
  }).catch(function() { onDone(); });
}

```

- [ ] **Step 3: Extend `openCmdk()` with recents fetch, favorite stars, and the Recents section**

Replace this exact current block:

```js
  var flat = [], active = 0;

  // Search state: cmdkSearchResults holds the last successful response
  // (kept across in-flight requests so results don't flicker to empty
  // while typing), null means the last request failed, [] means empty
  // query or genuinely no matches. cmdkSearchToken discards responses to
  // requests a newer keystroke has already superseded.
  var cmdkSearchResults = [];
  var cmdkSearchToken = 0;
  var cmdkSearchTimer = null;
  function cmdkSearch(q, onDone) {
    clearTimeout(cmdkSearchTimer);
    if (!q) { cmdkSearchResults = []; onDone(); return; }
    cmdkSearchTimer = setTimeout(function() {
      var token = ++cmdkSearchToken;
      apicall('/api/search?q=' + encodeURIComponent(q) + '&limit=20')
        .then(function(results) {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = Array.isArray(results) ? results : null;
          onDone();
        })
        .catch(function() {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = null;
          onDone();
        });
    }, 150);
  }

  function selectable() { return flat.map(function(f, i) { return f.sec ? -1 : i; }).filter(function(i) { return i >= 0; }); }
  function paint() {
    var nodes = list.querySelectorAll('[data-ci]');
    Array.prototype.forEach.call(nodes, function(n) { n.classList.toggle('active', +n.dataset.ci === active); });
  }

  function staticFlatFor(q) {
    var out = [];
    cmds.forEach(function(c) {
      var items = c.items.filter(function(i) { return i.t.toLowerCase().indexOf(q) >= 0; });
      if (items.length) { out.push({ sec: c.sec }); items.forEach(function(i) { out.push(i); }); }
    });
    return out;
  }

  function searchFlat() {
    var out = [];
    if (cmdkSearchResults === null) { out.push({ sec: 'Search unavailable' }); return out; }
    var byType = {};
    cmdkSearchResults.forEach(function(r) { (byType[r.docType] = byType[r.docType] || []).push(r); });
    ['scenario', 'run', 'finding', 'actor', 'campaign', 'malware', 'tool', 'technique'].forEach(function(dt) {
      var items = byType[dt];
      if (!items || !items.length) return;
      out.push({ sec: CMDK_SEARCH_LABELS[dt] });
      items.forEach(function(r) { out.push({ t: r.title, fn: function() { cmdkOpenResult(r); } }); });
    });
    return out;
  }

  function render(q) {
    flat = staticFlatFor(q).concat(searchFlat());
    var sel = selectable(); active = sel.length ? sel[0] : 0;
    if (!flat.length) { list.innerHTML = '<div class="cmdk-empty">No matches</div>'; return; }
    list.innerHTML = flat.map(function(f, i) {
      return f.sec ? '<div class="cmdk-sec">' + x(f.sec) + '</div>'
                   : '<div class="cmdk-item" data-ci="' + i + '">' + x(f.t) + '</div>';
    }).join('');
    Array.prototype.forEach.call(list.querySelectorAll('[data-ci]'), function(node) {
      node.onmousemove = function() { active = +node.dataset.ci; paint(); };
      node.onclick = function() { run(+node.dataset.ci); };
    });
    paint();
  }

  function draw(q) {
    q = (q || '').toLowerCase();
    render(q);
    cmdkSearch(input.value, function() { render(q); });
  }
```

With:

```js
  var flat = [], active = 0, currentQ = '';

  // Search state: cmdkSearchResults holds the last successful response
  // (kept across in-flight requests so results don't flicker to empty
  // while typing), null means the last request failed, [] means empty
  // query or genuinely no matches. cmdkSearchToken discards responses to
  // requests a newer keystroke has already superseded.
  var cmdkSearchResults = [];
  var cmdkSearchToken = 0;
  var cmdkSearchTimer = null;
  function cmdkSearch(q, onDone) {
    clearTimeout(cmdkSearchTimer);
    if (!q) { cmdkSearchResults = []; onDone(); return; }
    cmdkSearchTimer = setTimeout(function() {
      var token = ++cmdkSearchToken;
      apicall('/api/search?q=' + encodeURIComponent(q) + '&limit=20')
        .then(function(results) {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = Array.isArray(results) ? results : null;
          onDone();
        })
        .catch(function() {
          if (token !== cmdkSearchToken) return;
          cmdkSearchResults = null;
          onDone();
        });
    }, 150);
  }

  // cmdkRecents holds the one-shot GET /api/search/recents response,
  // fetched once when the palette opens (not on every keystroke) and only
  // ever shown when the input is empty (Global Search Phase 3).
  var cmdkRecents = [];
  apicall('/api/search/recents').then(function(r) {
    cmdkRecents = Array.isArray(r) ? r : [];
    if (currentQ === '') render(currentQ);
  }).catch(function() { cmdkRecents = []; });

  function selectable() { return flat.map(function(f, i) { return f.sec ? -1 : i; }).filter(function(i) { return i >= 0; }); }
  function paint() {
    var nodes = list.querySelectorAll('[data-ci]');
    Array.prototype.forEach.call(nodes, function(n) { n.classList.toggle('active', +n.dataset.ci === active); });
  }

  function staticFlatFor(q) {
    var out = [];
    cmds.forEach(function(c) {
      var items = c.items.filter(function(i) { return i.t.toLowerCase().indexOf(q) >= 0; });
      if (items.length) { out.push({ sec: c.sec }); items.forEach(function(i) { out.push(i); }); }
    });
    return out;
  }

  // recentsFlat only contributes rows when the input is empty -- it's
  // prepended above the static Navigate/Actions list, which keeps
  // rendering unchanged from Phase 2 (see render()'s concat order below).
  function recentsFlat(q) {
    if (q !== '' || !cmdkRecents.length) return [];
    var out = [{ sec: 'Recents' }];
    cmdkRecents.forEach(function(r) {
      out.push({ t: r.title, docType: r.docType, sourceId: r.sourceId, fav: r.favorited, ref: r, fn: function() { cmdkOpenResult(r); } });
    });
    return out;
  }

  function searchFlat() {
    var out = [];
    if (cmdkSearchResults === null) { out.push({ sec: 'Search unavailable' }); return out; }
    var byType = {};
    cmdkSearchResults.forEach(function(r) { (byType[r.docType] = byType[r.docType] || []).push(r); });
    ['scenario', 'run', 'finding', 'actor', 'campaign', 'malware', 'tool', 'technique'].forEach(function(dt) {
      var items = byType[dt];
      if (!items || !items.length) return;
      out.push({ sec: CMDK_SEARCH_LABELS[dt] });
      items.forEach(function(r) { out.push({ t: r.title, docType: r.docType, sourceId: r.sourceId, fav: r.favorited, ref: r, fn: function() { cmdkOpenResult(r); } }); });
    });
    return out;
  }

  function render(q) {
    flat = recentsFlat(q).concat(staticFlatFor(q)).concat(searchFlat());
    var sel = selectable(); active = sel.length ? sel[0] : 0;
    if (!flat.length) { list.innerHTML = '<div class="cmdk-empty">No matches</div>'; return; }
    list.innerHTML = flat.map(function(f, i) {
      if (f.sec) return '<div class="cmdk-sec">' + x(f.sec) + '</div>';
      // f.docType is only set for search-result/recents rows (Phase 3) --
      // static Navigate/Actions rows never get the star affordance.
      var star = f.docType
        ? '<span data-fav-ci="' + i + '" style="cursor:pointer;margin-right:0.5rem;color:' + (f.fav ? 'var(--warning)' : 'var(--muted)') + '">★</span>'
        : '';
      return '<div class="cmdk-item" data-ci="' + i + '">' + star + x(f.t) + '</div>';
    }).join('');
    Array.prototype.forEach.call(list.querySelectorAll('[data-ci]'), function(node) {
      node.onmousemove = function() { active = +node.dataset.ci; paint(); };
      node.onclick = function() { run(+node.dataset.ci); };
    });
    Array.prototype.forEach.call(list.querySelectorAll('[data-fav-ci]'), function(node) {
      node.onclick = function(e) {
        e.stopPropagation(); // don't also trigger the parent row's onclick (navigation)
        var it = flat[+node.dataset.favCi];
        if (!it || !it.ref) return;
        cmdkToggleFavorite(it.ref, function() { render(currentQ); });
      };
    });
    paint();
  }

  function draw(q) {
    q = (q || '').toLowerCase();
    currentQ = q;
    render(q);
    cmdkSearch(input.value, function() { render(q); });
  }
```

Note what changed and what didn't, precisely:
- `move(dir)`, `run(i)`, `close()`, `onKey(e)`, the two `addEventListener` calls, and the trailing `draw(''); setTimeout(...)` are **byte-for-byte unchanged** from Phase 2.
- `staticFlatFor(q)` is unchanged — the static Navigate/Actions list still renders identically for any `q`, including empty.
- `render(q)`'s concat order is `recentsFlat(q).concat(staticFlatFor(q)).concat(searchFlat())` — Recents (only on empty `q`) prepended above the static list, search results still appended after, matching Phase 2.
- The star `<span data-fav-ci>` is nested inside the `<div class="cmdk-item" data-ci>` — clicking it calls `e.stopPropagation()` before the click can bubble to the row's own `onclick`, so starring never triggers navigation, and clicking the row body still navigates exactly as before.

- [ ] **Step 4: Manual check — empty-input regression (static list)**

`go run ./cmd/server` from `orchestrator/` (human operator, same as Phase 2's Step 3 — no documented one-command dev-run path exists for this project). Open the app, log in, press ⌘K/Ctrl-K with a user who has no favorites/selection history yet. Confirm the static Navigate/Actions list still renders exactly as before (Phase 2's regression guarantee still holds for that list specifically).

- [ ] **Step 5: Manual check — Recents section**

As a user who has favorited at least one entity and selected at least one other (use Steps 6-7 below to generate that history, then reopen ⌘K), confirm: opening the palette with empty input shows a "Recents" section above Navigate/Actions, favorites appear before non-favorited recents, favorited rows show a filled/colored star.

- [ ] **Step 6: Manual check — star toggle**

Type a query matching a real entity, click its star (not the row). Confirm: the star's fill color toggles immediately, the palette does NOT close and does NOT navigate. Click it again to un-favorite; confirm it toggles back.

- [ ] **Step 7: Manual check — selection tracking + ranking**

Select several different results across a few searches (mouse and keyboard). Re-open the palette later and type a query matching one of those entities alongside an equally-relevant one you've never selected — confirm the previously-selected one ranks first (personal recency in action).

- [ ] **Step 8: Commit**

```bash
cd orchestrator
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): favorites, selection tracking, Recents section in command palette (Global Search Phase 3)"
```

---

### Task 5: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1` (run in background if it exceeds the interactive timeout)
Expected: PASS across all packages (Docker Desktop must be running). If a single unrelated package fails with a `testcontainers`/Docker provider connection error under full-suite load, re-run that package alone before treating it as a real regression — this project has hit this exact transient flake repeatedly across every phase this session, always confirmed harmless by isolation re-run.

- [ ] **Step 4: Confirm Task 4's full manual QA pass (Steps 4-7) is complete**

This is the actual verification for this phase's UI-visible change — Steps 1-3 above only confirm the Go backend compiles and its own tests pass. If Task 4's manual checks weren't all completed, do them now before considering Phase 3 done.
