# Global Search Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `⌘K` searches use a `type:<value>` operator (`type:scenario ransomware`, or `type:scenario` alone to browse) on top of Phase 1's `Query()`, on a parsing foundation generic enough that future operators (`status:`, `os:`, `tag:`) are additive, not a rewrite.

**Architecture:** A new, field-agnostic `ParseQuery(raw string) ParsedQuery` tokenizes any `field:value` pattern; a separate validation step decides only `type` is currently a real, applied operator — everything else (unsupported fields, bad values, duplicates) is rejected and recorded, never applied. `Query()` keeps its exact external signature and calls `ParseQuery` internally, gaining one new SQL branch (browse mode: `type:` with no free text) and one new SQL clause (`AND doc_type = $N` on the existing ranked search). A new static `GET /api/search/operators` endpoint advertises `["type"]` so a future frontend never hardcodes its own copy.

**Tech Stack:** Go + pgx v5 + Postgres (matches Phases 1-3). No frontend changes this phase — `cmdkSearch()` already forwards the raw typed string verbatim.

## Global Constraints

- `Query(ctx, pool, q string, limit int) ([]Document, error)` keeps its **exact existing signature** — no caller (the `Search` HTTP handler, the frontend) changes this phase. (Spec §Architecture 2)
- Only `type` is validated and applied in v1 — any other `field:value` token is rejected and recorded in `InvalidFilters`, never applied as a filter. (Spec §Non-Goals, §Architecture 1)
- Duplicate occurrences of the same field are **rejected entirely, not last-wins** — neither value applies, one `InvalidFilter` is recorded. (Spec §Architecture 1, explicit brainstorming decision)
- An empty/whitespace query with **no** valid filter still returns `[]Document{}`, exactly as Phase 1 — only an explicit, valid `type:` filter unlocks browse mode. (Spec §Architecture 2)
- `Personalize()` is untouched — it re-orders whatever `Query()` returns regardless of which SQL branch produced it. (Spec §Non-Goals)
- No frontend changes, no new CSS, no UI consumption of `InvalidFilters` or the operators endpoint this phase. (Spec §Non-Goals)
- `internal/search` package tests use the existing `sharedDB`/`RunWithPool`/`testing.Short()`-skip pattern — do not redeclare `TestMain`.

---

## File Structure

- Create `orchestrator/internal/search/query_parse.go` — `ParsedQuery`, `InvalidFilter`, `SupportedOperators`, `ParseQuery()`.
- Create `orchestrator/internal/search/query_parse_test.go` — parser unit tests (no DB needed).
- Modify `orchestrator/internal/search/store.go` — `Query()` calls `ParseQuery` internally, gains the browse-mode and type-filter SQL branches.
- Modify `orchestrator/internal/search/store_test.go` — 4 new `Query()` tests covering type filtering, browse mode, and the ignored/rejected-filter fallback behavior.
- Modify `orchestrator/internal/api/search_handlers.go` — add `SearchOperators`.
- Modify `orchestrator/internal/api/search_handlers_test.go` — add a test for it.
- Modify `orchestrator/internal/api/routes.go` — register the route.
- Modify `orchestrator/internal/api/rbac_matrix_test.go` — add the route entry.

---

### Task 1: `ParseQuery` — generic operator tokenizer + `type`-only validation

**Files:**
- Create: `orchestrator/internal/search/query_parse.go`
- Create: `orchestrator/internal/search/query_parse_test.go`

**Interfaces:**
- Produces: `type ParsedQuery struct { FreeText string; DocType string; InvalidFilters []InvalidFilter }`; `type InvalidFilter struct { Name, Value string }`; `var SupportedOperators []string`; `func ParseQuery(raw string) ParsedQuery` — Task 2's `Query()` and Task 3's operators endpoint both need these exact names/shapes.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/search/query_parse_test.go`:

```go
package search

import (
	"reflect"
	"testing"
)

func TestParseQuery_TypeFilterPlusFreeText(t *testing.T) {
	pq := ParseQuery("type:scenario ransomware")
	if pq.FreeText != "ransomware" {
		t.Errorf("FreeText = %q, want %q", pq.FreeText, "ransomware")
	}
	if pq.DocType != "scenario" {
		t.Errorf("DocType = %q, want %q", pq.DocType, "scenario")
	}
	if len(pq.InvalidFilters) != 0 {
		t.Errorf("InvalidFilters = %+v, want none", pq.InvalidFilters)
	}
}

func TestParseQuery_PluralTypeValueNormalizes(t *testing.T) {
	pq := ParseQuery("type:scenarios")
	if pq.DocType != "scenario" {
		t.Errorf("DocType = %q, want %q (plural normalized to singular)", pq.DocType, "scenario")
	}
}

func TestParseQuery_UnknownTypeValueIgnoredAndRecorded(t *testing.T) {
	pq := ParseQuery("type:bogus ransomware")
	if pq.FreeText != "ransomware" {
		t.Errorf("FreeText = %q, want %q", pq.FreeText, "ransomware")
	}
	if pq.DocType != "" {
		t.Errorf("DocType = %q, want empty (bogus value must not apply)", pq.DocType)
	}
	want := []InvalidFilter{{Name: "type", Value: "bogus"}}
	if !reflect.DeepEqual(pq.InvalidFilters, want) {
		t.Errorf("InvalidFilters = %+v, want %+v", pq.InvalidFilters, want)
	}
}

func TestParseQuery_UnsupportedFieldIgnoredAndRecorded(t *testing.T) {
	pq := ParseQuery("status:failed type:run")
	if pq.DocType != "run" {
		t.Errorf("DocType = %q, want %q", pq.DocType, "run")
	}
	want := []InvalidFilter{{Name: "status", Value: "failed"}}
	if !reflect.DeepEqual(pq.InvalidFilters, want) {
		t.Errorf("InvalidFilters = %+v, want %+v (status is not yet a supported operator)", pq.InvalidFilters, want)
	}
}

func TestParseQuery_DuplicateFieldRejectedNotLastWins(t *testing.T) {
	pq := ParseQuery("type:scenario type:actor ransomware")
	if pq.DocType != "" {
		t.Errorf("DocType = %q, want empty (duplicate type: filters must both be rejected)", pq.DocType)
	}
	if pq.FreeText != "ransomware" {
		t.Errorf("FreeText = %q, want %q", pq.FreeText, "ransomware")
	}
	if len(pq.InvalidFilters) != 1 || pq.InvalidFilters[0].Name != "type" {
		t.Fatalf("InvalidFilters = %+v, want exactly one entry for the duplicated \"type\" field", pq.InvalidFilters)
	}
}

func TestParseQuery_TypeOnlyNoFreeText(t *testing.T) {
	pq := ParseQuery("type:scenario")
	if pq.FreeText != "" {
		t.Errorf("FreeText = %q, want empty", pq.FreeText)
	}
	if pq.DocType != "scenario" {
		t.Errorf("DocType = %q, want %q", pq.DocType, "scenario")
	}
}

func TestParseQuery_EmptyInput(t *testing.T) {
	pq := ParseQuery("")
	if pq.FreeText != "" || pq.DocType != "" || len(pq.InvalidFilters) != 0 {
		t.Errorf("ParseQuery(\"\") = %+v, want all zero values", pq)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -run TestParseQuery -v`
Expected: FAIL with `undefined: ParseQuery` (compile error — nothing in `query_parse.go` exists yet).

- [ ] **Step 3: Implement `ParseQuery`**

Create `orchestrator/internal/search/query_parse.go`:

```go
package search

import "strings"

// ParsedQuery is the result of parsing a raw search-box string into free
// text plus recognized operator filters. Returning a struct (not multiple
// return values) means adding new operator fields later (Status, OS, Tag,
// once those columns exist) never changes any caller's call site. See
// design doc §Architecture 1.
type ParsedQuery struct {
	FreeText string
	DocType  string // "" if no valid type: filter was applied

	// InvalidFilters holds every field:value token that couldn't be
	// applied -- an unsupported field name, an unrecognized value for a
	// supported field, or a field that appeared more than once. Search
	// behaves exactly as if these tokens were never typed; this is kept
	// only so a future UI can surface "unknown filter" hints without
	// touching the parser.
	InvalidFilters []InvalidFilter
}

type InvalidFilter struct {
	Name  string
	Value string
}

// SupportedOperators lists every field name ParseQuery currently validates
// and applies -- the single source of truth shared by validation here and
// the GET /api/search/operators advertisement endpoint, so they can never
// drift from each other.
var SupportedOperators = []string{"type"}

// knownDocTypes are the only values a type: filter can resolve to --
// matches the 8 doc_types ReindexAll builds (internal/search/store.go).
var knownDocTypes = map[string]bool{
	"scenario": true, "run": true, "finding": true, "actor": true,
	"campaign": true, "malware": true, "tool": true, "technique": true,
}

// ParseQuery splits raw on whitespace, treats any token shaped like
// field:value as an operator, and validates only the fields in
// SupportedOperators -- everything else (an unsupported field, a bad
// value, or a duplicated field) is rejected and recorded in
// InvalidFilters rather than applied. See design doc §Architecture 1.
func ParseQuery(raw string) ParsedQuery {
	fields := map[string][]string{} // field -> every value seen, in order
	var freeTextParts []string

	for _, tok := range strings.Fields(raw) {
		field, value, ok := splitOperatorToken(tok)
		if !ok {
			freeTextParts = append(freeTextParts, tok)
			continue
		}
		fields[field] = append(fields[field], value)
	}

	pq := ParsedQuery{FreeText: strings.Join(freeTextParts, " ")}
	for field, values := range fields {
		if len(values) > 1 {
			pq.InvalidFilters = append(pq.InvalidFilters, InvalidFilter{
				Name: field, Value: "duplicate: " + strings.Join(values, ", "),
			})
			continue
		}
		value := values[0]
		if !isSupportedOperator(field) {
			pq.InvalidFilters = append(pq.InvalidFilters, InvalidFilter{Name: field, Value: value})
			continue
		}
		// field == "type" is the only supported operator today. None of
		// the 8 known doc_type values end in "s", so a single trailing-s
		// strip correctly normalizes both "scenarios" and "scenario".
		normalized := strings.TrimSuffix(strings.ToLower(value), "s")
		if knownDocTypes[normalized] {
			pq.DocType = normalized
		} else {
			pq.InvalidFilters = append(pq.InvalidFilters, InvalidFilter{Name: "type", Value: value})
		}
	}
	return pq
}

// splitOperatorToken reports whether tok looks like field:value -- a
// leading run of letters/digits/underscore/hyphen, a colon, then one or
// more non-whitespace characters. strings.Fields already guarantees tok
// has no internal whitespace, so this only needs to find the first colon
// and validate the field portion.
func splitOperatorToken(tok string) (field, value string, ok bool) {
	i := strings.IndexByte(tok, ':')
	if i <= 0 || i == len(tok)-1 {
		return "", "", false
	}
	for _, r := range tok[:i] {
		if !isFieldChar(r) {
			return "", "", false
		}
	}
	return strings.ToLower(tok[:i]), tok[i+1:], true
}

func isFieldChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
}

func isSupportedOperator(field string) bool {
	for _, f := range SupportedOperators {
		if f == field {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -run TestParseQuery -v`
Expected: PASS, all 7 tests.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/search/query_parse.go internal/search/query_parse_test.go
git commit -m "feat(search): ParseQuery -- generic field:value operator parsing (Global Search Phase 4)"
```

---

### Task 2: Wire `type:` filtering and browse mode into `Query()`

**Files:**
- Modify: `orchestrator/internal/search/store.go` (the `Query` function, currently lines 48-82)
- Modify: `orchestrator/internal/search/store_test.go`

**Interfaces:**
- Consumes: `ParseQuery(raw string) ParsedQuery` (Task 1).
- Produces: `Query(ctx, pool, q string, limit int) ([]Document, error)` — **signature unchanged** from Phase 1; Task 3's `Search` handler and the frontend need zero changes.

- [ ] **Step 1: Write the failing tests**

Append these 4 tests to the end of `orchestrator/internal/search/store_test.go`:

```go
func TestQuery_TypeFilterOnlyReturnsMatchingType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Ransomware Simulation"},
		}); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}
		if err := reindexOneType(ctx, pool, "finding", []Document{
			{DocType: "finding", SourceID: "f1", Title: "Ransomware Finding"},
		}); err != nil {
			t.Fatalf("seed finding: %v", err)
		}

		results, err := Query(ctx, pool, "type:scenario ransomware", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 1 || results[0].DocType != "scenario" {
			t.Fatalf("Query(\"type:scenario ransomware\") = %+v, want only the scenario doc", results)
		}
	})
}

func TestQuery_TypeOnlyBrowsesAllOfThatTypeOrderedByTitle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Zebra Scenario"},
			{DocType: "scenario", SourceID: "s2", Title: "Apple Scenario"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		results, err := Query(ctx, pool, "type:scenario", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("Query(\"type:scenario\") = %+v, want both scenarios (browse mode, no keyword needed)", results)
		}
		if results[0].Title != "Apple Scenario" || results[1].Title != "Zebra Scenario" {
			t.Errorf("order = [%s, %s], want alphabetical by title", results[0].Title, results[1].Title)
		}
	})
}

func TestQuery_InvalidTypeFilterIgnoredFallsBackToPlainSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Ransomware Simulation"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		plain, err := Query(ctx, pool, "ransomware", 10)
		if err != nil {
			t.Fatalf("Query(plain): %v", err)
		}
		withBadFilter, err := Query(ctx, pool, "type:bogus ransomware", 10)
		if err != nil {
			t.Fatalf("Query(bad filter): %v", err)
		}
		if len(withBadFilter) != len(plain) || withBadFilter[0].SourceID != plain[0].SourceID {
			t.Fatalf("Query(\"type:bogus ransomware\") = %+v, want identical to plain %+v (bad filter ignored)", withBadFilter, plain)
		}
	})
}

func TestQuery_DuplicateTypeFilterRejectedFallsBackToPlainSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Ransomware Simulation"},
		}); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}
		if err := reindexOneType(ctx, pool, "actor", []Document{
			{DocType: "actor", SourceID: "a1", Title: "Ransomware Actor"},
		}); err != nil {
			t.Fatalf("seed actor: %v", err)
		}

		results, err := Query(ctx, pool, "type:scenario type:actor ransomware", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("Query() = %+v, want both scenario and actor docs (duplicate type: filters rejected, not applied)", results)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/search/... -run TestQuery_Type -v`
Expected: FAIL — `TestQuery_TypeFilterOnlyReturnsMatchingType` returns both docs (no filtering yet), `TestQuery_TypeOnlyBrowsesAllOfThatTypeOrderedByTitle` returns 0 results (current empty-`FreeText` guard fires), the other two may incidentally pass already but re-run after Step 3 regardless.

- [ ] **Step 3: Rewrite `Query()`**

In `orchestrator/internal/search/store.go`, replace:

```go
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
```

With:

```go
// Query full-text-searches search_documents and returns a flat, ranked
// list -- never pre-grouped by type, see the design doc's Architecture §4.
// Supports the type: search operator (Global Search Phase 4, see
// query_parse.go): a valid type: filter with no free text switches to
// browse mode (every entity of that type, ordered by title, no ranking --
// there's no text to rank against); an invalid/duplicate/unsupported
// filter is ignored entirely, falling back to a plain search. An empty
// query with no valid filter at all still returns an empty slice, not an
// error and not the full table, exactly as Phase 1.
func Query(ctx context.Context, pool *pgxpool.Pool, q string, limit int) ([]Document, error) {
	pq := ParseQuery(q)
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	if pq.FreeText == "" && pq.DocType == "" {
		return []Document{}, nil
	}

	sqlQuery := `SELECT doc_type, source_id, title, description, tags
		FROM search_documents, plainto_tsquery('english', $1) query
		WHERE search_vector @@ query
		  AND ($3 = '' OR doc_type = $3)
		ORDER BY ts_rank(search_vector, query) DESC
		LIMIT $2`
	args := []any{pq.FreeText, limit, pq.DocType}
	if pq.FreeText == "" {
		sqlQuery = `SELECT doc_type, source_id, title, description, tags
			FROM search_documents
			WHERE doc_type = $1
			ORDER BY title
			LIMIT $2`
		args = []any{pq.DocType, limit}
	}

	rows, err := pool.Query(ctx, sqlQuery, args...)
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
```

Then remove the now-unused `"strings"` import from this file's import block (`ParseQuery` in `query_parse.go` owns all the string handling now; `store.go`'s only remaining imports are `context`, `fmt`, `github.com/jackc/pgx/v5/pgxpool`, and `github.com/audspect/bas/internal/scenario`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/search/... -v`
Expected: PASS, every test in the package — including all of Phase 1-3's existing `Query`/`Personalize`/`Recents` tests (confirms this change didn't regress plain-text search) and the 4 new ones from Step 1.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/search/store.go internal/search/store_test.go
git commit -m "feat(search): type: filter + browse mode in Query() (Global Search Phase 4)"
```

---

### Task 3: `GET /api/search/operators`

**Files:**
- Modify: `orchestrator/internal/api/search_handlers.go` (append after `SearchRecents`)
- Modify: `orchestrator/internal/api/search_handlers_test.go` (add a test, add `"reflect"` to imports)
- Modify: `orchestrator/internal/api/routes.go:206-210`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:92-96`

**Interfaces:**
- Consumes: `search.SupportedOperators []string` (Task 1).
- Produces: `h.SearchOperators` (new `*Handler` method) — nothing else in this plan depends on it; it's terminal API surface for this phase.

- [ ] **Step 1: Write the failing test**

In `orchestrator/internal/api/search_handlers_test.go`, add `"reflect"` to the existing import block (alphabetically, after `"net/http/httptest"` and before `"testing"`):

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/search"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)
```

Then append this test to the end of the file:

```go
func TestSearchOperators_ReturnsSupportedList(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/search/operators", nil)
	rec := httptest.NewRecorder()
	h.SearchOperators(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string][]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := []string{"type"}
	if !reflect.DeepEqual(body["operators"], want) {
		t.Errorf("operators = %+v, want %+v", body["operators"], want)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSearchOperators -v`
Expected: FAIL with `h.SearchOperators undefined` (compile error).

- [ ] **Step 3: Implement the handler**

In `orchestrator/internal/api/search_handlers.go`, append after the existing `SearchRecents` function (its closing `}` is currently the last line of the file):

```go

// GET /api/search/operators — advertises every field: operator ParseQuery
// currently validates and applies, so a future frontend never has to
// hardcode a second copy of this list. Any authenticated user.
func (h *Handler) SearchOperators(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]any{"operators": search.SupportedOperators})
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, replace:

```go
		r.Get("/api/search", h.Search)
		r.With(auth.RequirePermission(auth.CanReindexSearch)).Post("/api/search/reindex", h.SearchReindex)
		r.Post("/api/search/select", h.SearchSelect)
		r.Post("/api/search/favorite", h.SearchFavorite)
		r.Get("/api/search/recents", h.SearchRecents)
```

With:

```go
		r.Get("/api/search", h.Search)
		r.With(auth.RequirePermission(auth.CanReindexSearch)).Post("/api/search/reindex", h.SearchReindex)
		r.Post("/api/search/select", h.SearchSelect)
		r.Post("/api/search/favorite", h.SearchFavorite)
		r.Get("/api/search/recents", h.SearchRecents)
		r.Get("/api/search/operators", h.SearchOperators)
```

- [ ] **Step 5: Update the RBAC matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, replace:

```go
	{http.MethodGet, "/api/search", tierAny, ""},
	{http.MethodPost, "/api/search/reindex", tierPermission, auth.CanReindexSearch},
	{http.MethodPost, "/api/search/select", tierAny, ""},
	{http.MethodPost, "/api/search/favorite", tierAny, ""},
	{http.MethodGet, "/api/search/recents", tierAny, ""},
```

With:

```go
	{http.MethodGet, "/api/search", tierAny, ""},
	{http.MethodPost, "/api/search/reindex", tierPermission, auth.CanReindexSearch},
	{http.MethodPost, "/api/search/select", tierAny, ""},
	{http.MethodPost, "/api/search/favorite", tierAny, ""},
	{http.MethodGet, "/api/search/recents", tierAny, ""},
	{http.MethodGet, "/api/search/operators", tierAny, ""},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestSearchOperators|TestRBACMatrix" -v`
Expected: PASS, including `TestRBACMatrix_NoDrift`.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/search_handlers.go internal/api/search_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): GET /api/search/operators (Global Search Phase 4)"
```

---

### Task 4: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: no errors

- [ ] **Step 2: Full vet**

Run: `cd orchestrator && go vet ./...`
Expected: no errors

- [ ] **Step 3: Full test suite**

Run: `cd orchestrator && go test ./... -count=1 > /tmp/phase4_fulltest.log 2>&1; echo "EXIT_CODE:$?"` (redirect to a file and check `$?` directly rather than piping through `tail`, which masks `go test`'s real exit code — this project hit that exact masking bug during Phase 2's regression run). Run in background if it exceeds the interactive timeout.
Expected: exit code 0, PASS across all packages (Docker Desktop must be running). If a single package fails with a `testcontainers`/Docker provider connection error under full-suite load, re-run that package alone before treating it as a real regression — this project has hit this exact transient flake repeatedly across every phase this session (two different symptoms so far: "rootless Docker is not supported on Windows" during Phase 2, a bare connection-refused during Phase 3), always confirmed harmless by isolation re-run. If the package that fails is `internal/search` or `internal/api` (the two packages this phase touched), the isolated re-run matters even more than usual — don't wave off a failure in exactly the code you just changed without checking.
