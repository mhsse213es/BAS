# Global Search Phase 3 (Ranking & Personalization) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29.
**Depends on:** [[Global Search]] Phase 1 (`internal/search`, `GET /api/search`, `ts_rank`-based relevance) and Phase 2 (`⌘K` palette wired to live search, `cmdkOpenResult`/`cmdkSearch` in `cmd/server/wwwroot/index.html`). Phase 2's manual browser QA is still pending as of this write-up — flagged, not blocking this spec.

## Problem

Phase 1's ranking is pure text relevance (`ts_rank`, title > description > tags) with zero notion of who's searching or what they actually use. Two gaps follow directly from that:
1. Typing a query that matches many things always ranks them the same way for every user, regardless of what that specific user (or the org as a whole) actually opens.
2. Opening `⌘K` with nothing typed shows only the static Navigate/Actions list — there's no "here's what you were just looking at" shortcut, which is the single most-used feature of every Raycast/Linear-style palette.

This phase adds three signals on top of Phase 1's relevance — personal recency, org-wide popularity, and explicit favorites — and uses them for both typed-query ranking and a new empty-input "Recents" section.

## Non-Goals

- **No cross-session/cross-device sync beyond what's already true of the DB** — personalization is per `user_id`, stored server-side, so it already follows the user across devices; no new sync mechanism needed or built.
- **No admin-configurable ranking weights.** The blend weights (below) are fixed constants for v1, not a settings-page knob — YAGNI until there's evidence they need tuning per deployment.
- **No decay/cleanup job for old selection events in this phase.** `search_selections` is append-only and will grow unbounded; a retention/rollup job is a reasonable future addition but isn't needed for this phase's correctness (queries only ever look at a recent window — see Architecture §2) and unbounded growth at BFSI-client search-usage scale is not an operational concern yet.
- **No changes to Phase 1's `internal/search.Query()` SQL.** Personalization is a post-processing step over its existing results, not a rewrite of the ranking query itself.
- **No favorite/recent affordances outside the `⌘K` palette** (e.g. no star icon on entity detail views) — confirmed explicitly during brainstorming; entity detail views are out of scope for v1.

## Architecture

### 1. Two new tables — an event log and a toggle table, not one shared table

```sql
CREATE TABLE search_selections (
  id         bigserial   PRIMARY KEY,
  user_id    text        NOT NULL REFERENCES users(id),
  doc_type   text        NOT NULL,
  source_id  text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_search_selections_user ON search_selections (user_id, created_at DESC);
CREATE INDEX idx_search_selections_entity ON search_selections (doc_type, source_id, created_at DESC);

CREATE TABLE search_favorites (
  id         bigserial   PRIMARY KEY,
  user_id    text        NOT NULL REFERENCES users(id),
  doc_type   text        NOT NULL,
  source_id  text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, doc_type, source_id)
);
CREATE INDEX idx_search_favorites_user ON search_favorites (user_id);
```

`search_selections` is append-only: one row per time a user opens a search result. It powers both personal recency (rows filtered to that `user_id`) and org popularity (rows counted across all users) from the same log — no need for two separate counters. `search_favorites` is a real toggle table (insert to favorite, delete to un-favorite, `UNIQUE(user_id, doc_type, source_id)` makes "is this favorited" a single indexed lookup) — an event log would force scanning for "the latest event for this pair" on every render, which is unnecessary work for what is fundamentally a boolean state, not a history.

`user_id text REFERENCES users(id)` matches the existing `users.id text PRIMARY KEY DEFAULT gen_random_uuid()::text` convention used everywhere else in this schema (`internal/db/postgres.go`).

### 2. Ranking blend — computed in Go over Phase 1's existing results, not new SQL

`internal/search.Query(ctx, pool, q, limit)` is unchanged. A new function wraps it:

```go
func Personalize(ctx context.Context, pool *pgxpool.Pool, userID string, results []Document) ([]Document, error)
```

Called from the `Search` HTTP handler right after `search.Query()`, only when a `Claims`-bearing request has a `userID` (every authenticated request does — `auth.ClaimsFrom(r.Context())`). It:

1. Loads that user's favorited `(doc_type, source_id)` set (one query, `WHERE user_id = $1`).
2. Loads a recency signal: this user's `search_selections` from the last 30 days, most-recent-first, deduped to one row per entity (a `MAX(created_at)` grouped query) — used to compute a per-entity recency score.
3. Loads a popularity signal: selection counts across **all** users from the last 30 days, grouped by entity, log-scaled (`log(1+count)`) so 50 vs. 500 selections isn't a 10x swing.
4. Partitions `results` into two groups: favorited (in original relevance order) and everything else. Non-favorited results get a small additive score bump — `ts_rank`'s existing relative order is preserved as the base, recency and popularity only nudge entities up within it, they don't invert a strong relevance match — then are re-sorted by the bumped score.
5. Returns favorited group first, then the re-sorted remainder — a hard pin, not a blended score, per the brainstorming decision: favorites are meant to be predictable ("my starred thing is always first"), not probabilistically ranked against relevance.

30 days is a fixed window for both recency and popularity in v1 — long enough to be meaningful for infrequent BAS/security workflows (this isn't a consumer app used every minute), short enough that a query stays cheap without needing the decay/rollup job called out in Non-Goals.

### 3. New endpoints

- **`POST /api/search/select`** — body `{docType, sourceId}`. Inserts one `search_selections` row for the current user. Called fire-and-forget from the frontend right when a result is opened — never blocks navigation, and a failure here is silently swallowed (a missed personalization signal is not worth surfacing an error for). `tierAny` (any authenticated user).
- **`POST /api/search/favorite`** — body `{docType, sourceId}`. Toggles: inserts if absent, deletes if present (checked via the same unique constraint), returns `{favorited: bool}`. `tierAny`.
- **`GET /api/search/recents`** — no query param. Returns up to 5 favorited entities (most-recently-favorited first) followed by up to 5 recently-selected entities not already in the favorites list (most-recent-first, deduped to one row per entity) — same `Document` shape Phase 1 already returns, so the frontend's existing rendering code needs no new parsing. `tierAny`.

All three are registered in `internal/api/routes.go` next to the existing `/api/search` and `/api/search/reindex` routes, and added to `rbac_matrix_test.go` the same way Phase 1's routes were.

### 4. Frontend — `cmd/server/wwwroot/index.html`, extending Phase 2's `openCmdk()` again

- **Selection tracking:** `cmdkOpenResult(r)` gains one line at its top — a fire-and-forget `apicall('/api/search/select', {method:'POST', body: JSON.stringify({docType: r.docType, sourceId: r.sourceId})})` with no `.then()`/error handling beyond swallowing failures, matching the "never blocks navigation" rule above.
- **Favorite toggle:** each search-result row (built in Phase 2's `searchFlat()`) gets a small star affordance rendered alongside the title. Clicking it (not selecting the row) calls `POST /api/search/favorite` and re-renders that row's star state — it does not close the palette or navigate, unlike clicking the row itself.
- **Empty-input Recents section:** `draw('')`'s call path already exists (Phase 2's `render(q)` runs before and after the debounced search). A new `cmdkRecents` array is fetched once when `openCmdk()` opens (not on every keystroke — this is a single `GET /api/search/recents` call at palette-open time, cached for the palette's lifetime) and, when `q` is empty, `render('')` prepends a "Recents" section built from it, above the existing static Navigate/Actions sections — which continue to render exactly as Phase 2 left them. If the fetch fails or returns empty, no Recents section appears and empty-input falls back to exactly today's behavior — the byte-for-byte guarantee Phase 2 established for the static list is preserved; it's the *new* section that's additive and fails soft.

## Testing

- `internal/search/personalize_test.go` (new, real-Postgres via `testutil.TestDB`, matching every other test in this package): favorites always sort first and in original-relevance order among themselves; a recently-selected-by-this-user result outranks an equally-relevant one the user has never opened; org-wide popularity affects ranking for a user with no personal history; selections older than 30 days don't affect ranking; a user with zero selections/favorites gets Phase 1's unmodified order back.
- `internal/api/search_handlers_test.go` additions: `POST /api/search/select` inserts exactly one row per call (repeat calls accumulate, they don't upsert); `POST /api/search/favorite` toggles correctly on repeated calls; `GET /api/search/recents` returns favorites before recents and dedupes an entity that's both.
- `rbac_matrix_test.go`: three new route entries, `tierAny` like `GET /api/search`.
- Frontend verification stays manual (no test harness exists for this file, confirmed in Phase 1/2): star icon toggles visually, Recents section appears/disappears correctly, selecting a result still navigates identically to Phase 2's behavior with the new tracking call added.
