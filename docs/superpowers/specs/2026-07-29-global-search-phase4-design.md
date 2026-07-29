# Global Search Phase 4 (Search-Operator Query Language) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29.
**Depends on:** [[Global Search]] Phase 1 (`internal/search.Query()`, `GET /api/search`), Phase 2 (⌘K palette, results grouped into per-`docType` sections), Phase 3 (`Personalize()` post-processing). Phase 2/3's manual browser QA is still pending as of this write-up — flagged, not blocking this spec.

## Problem

Phase 1's `search_documents` table indexes `docType`/`title`/`description`/`tags` per entity — nothing else. The original Global Search vision named `type:`, `status:`, `os:`, etc. as example operators, but only `type` is actually backed by an indexed field today; the rest would require extending every builder with new per-type columns, a materially bigger change than this phase should take on. Phase 4 delivers real filtering now (`type:`) on a foundation that doesn't have to be re-architected when `status:`/`os:`/etc. get indexed later.

## Non-Goals

- **No operators beyond `type` are validated or applied in v1.** The parser recognizes the general `field:value` syntax (so future fields are additive, not a rewrite), but `status:`, `os:`, `tag:`, etc. all resolve to "unsupported field" this phase — see Architecture §1.
- **No frontend consumption of unknown/duplicate-filter information or the operator-list endpoint.** Both exist as forward-looking API surface (a stable place for a future UI to hang autocomplete or an "unknown filter" hint), not wired into any UI this phase. Confirmed acceptable during brainstorming.
- **No quoted-value support** (e.g. `title:"exact phrase"`). Tokenization is plain whitespace-split; a value containing a space isn't representable as a single `field:value` token in v1.
- **No boolean/exclusion syntax** (`-type:run`, `type:scenario|run`). One positive filter per supported field, full stop.
- **No changes to `Personalize()`.** It re-orders whatever `Query()` returns, regardless of whether that came from a ranked search or the new browse mode — confirmed during brainstorming as the right boundary (search produces candidates, personalization reorders them, the two stay independent).
- **No changes to `GET /api/search`'s external contract or to the frontend.** `cmdkSearch()` already forwards the raw typed string verbatim; the backend owns 100% of the new parsing.

## Architecture

### 1. `ParseQuery` — a generic `field:value` tokenizer, not a `type`-specific one

```go
type ParsedQuery struct {
	FreeText       string
	DocType        string          // "" if no valid type: filter was applied
	InvalidFilters []InvalidFilter // unsupported fields, invalid values, or duplicates -- never applied, kept for future UI use
}

type InvalidFilter struct {
	Name  string
	Value string
}

// SupportedOperators lists every field name ParseQuery currently validates
// and applies -- the single source of truth shared by parsing/validation
// and the GET /api/search/operators advertisement endpoint (§3), so they
// can never drift from each other.
var SupportedOperators = []string{"type"}

func ParseQuery(raw string) ParsedQuery
```

`ParseQuery` is deliberately two-layered, matching the brainstorming decision to keep tokenizing and validation separate:

1. **Tokenize** (generic, knows nothing about `type`): split `raw` on whitespace; any token matching `field:value` (a leading run of letters/digits/`_`/`-`, then `:`, then one or more non-whitespace characters) is an operator token, everything else is free text. Operator tokens are grouped by field name (lowercased).
2. **Validate** (the only place that knows what `type` means): for each field name group —
   - **More than one occurrence of the same field** → never applied, regardless of value. One `InvalidFilter{Name: field, Value: "duplicate: " + comma-joined original values}` is recorded. Rationale from brainstorming: silently taking the last one makes a stale leftover `type:scenario` from an earlier edit invisible — better to flag it than guess.
   - **Field not in `SupportedOperators`** (i.e., not `"type"` in v1) → `InvalidFilter{Name: field, Value: value}`, never applied.
   - **Field is `type`, value (after lowercasing and stripping one trailing `s`, so `type:scenarios` and `type:scenario` both work) matches one of the 8 known `doc_type` values** → sets `DocType`.
   - **Field is `type`, value doesn't match any known `doc_type`** → `InvalidFilter{Name: "type", Value: value}`, `DocType` stays empty.
3. `FreeText` is every non-operator token rejoined with single spaces, trimmed.

`ParsedQuery` returning a struct (not `(freeText, docType string)`) is the one structural requirement from brainstorming: adding `Status`/`OS`/`Tag` fields later, when those columns exist, means widening this struct and `SupportedOperators` — zero changes to any caller's call site.

### 2. `Query()` — same external signature, two new internal branches

`internal/search.Query(ctx, pool, q string, limit int) ([]Document, error)` keeps its exact existing signature — Task 3's HTTP handler and the frontend need **zero changes**. Internally, it calls `ParseQuery(q)` first, then:

- **`FreeText == "" && DocType == ""`** (nothing usable at all, including "just an invalid/duplicate filter and no text") → Phase 1's existing guard applies unchanged: return `[]Document{}`.
- **`FreeText == "" && DocType != ""`** (**browse mode**, the one genuinely new behavior) — a deliberate, explicit scope is not an accidental blank search, so the "avoid a full-table dump" guard doesn't apply here:
  ```sql
  SELECT doc_type, source_id, title, description, tags
  FROM search_documents
  WHERE doc_type = $1
  ORDER BY title
  LIMIT $2
  ```
- **`FreeText != ""`** (ranked search, `DocType` may or may not be set) — Phase 1's existing `ts_rank` query, with one added clause when `DocType != ""`:
  ```sql
  SELECT doc_type, source_id, title, description, tags
  FROM search_documents, plainto_tsquery('english', $1) query
  WHERE search_vector @@ query
    AND ($3 = '' OR doc_type = $3)
  ORDER BY ts_rank(search_vector, query) DESC
  LIMIT $2
  ```

### 3. `GET /api/search/operators` — a trivial, static advertisement endpoint

```go
// GET /api/search/operators
func (h *Handler) SearchOperators(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]any{"operators": search.SupportedOperators})
}
```

Returns `{"operators": ["type"]}` today. `tierAny`, same group as the other search routes. This is the one piece of new API surface beyond `type:` filtering itself — included now because it's a single static-list endpoint (not a design commitment to any particular autocomplete UI), and it means a future frontend never has to hardcode a second copy of "which operators exist" that could drift from the backend's actual validation logic.

## Testing

- `internal/search/query_parse_test.go` (new): `"type:scenario ransomware"` → `FreeText:"ransomware", DocType:"scenario"`; `"type:scenarios"` (plural) → `DocType:"scenario"`; `"type:bogus ransomware"` → `FreeText:"ransomware", DocType:"", InvalidFilters:[{type, bogus}]`; `"status:failed type:run"` → `DocType:"run", InvalidFilters:[{status, failed}]` (status is an unsupported field, not yet a real operator); `"type:scenario type:actor ransomware"` (duplicate) → `DocType:"", FreeText:"ransomware", InvalidFilters:[{type, "duplicate: scenario, actor"}]`; `"type:scenario"` alone → `FreeText:"", DocType:"scenario"`; `""` → both fields empty.
- `internal/search/store_test.go` additions: `Query()` with `"type:scenario ransomware"` only returns scenario docs even when a same-keyword finding/run also matches; `Query()` with `"type:scenario"` alone (browse mode) returns all scenarios ordered by title, including ones that share no keyword with anything; `Query()` with `"type:bogus ransomware"` behaves identically to plain `"ransomware"` (bad filter silently ignored, matches brainstorming decision); `Query()` with duplicate `type:` filters behaves identically to searching without any type filter (both occurrences rejected, not last-wins).
- `internal/api/search_handlers_test.go` addition: a `GET /api/search/operators` handler test asserting the response body is `{"operators":["type"]}`.
- `internal/api/rbac_matrix_test.go`: one new route entry, `tierAny` like the other search routes.
