# Global Search Phase 1 (Search Index Core + API) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-29. User's vision is a Linear/Raycast/Notion/Cursor-style global command interface as the platform's primary navigation layer — this phase is explicitly scoped as the first of five phases toward that vision (see Non-Goals for the rest).
**Depends on:** Nothing new — reads from existing tables/sources (`scenario.Engine`, `scenario_runs`, `findings`, `threat_actor_profiles`, `intelligence_campaigns`/`malware`/`tools`, `techniques`), all already built by Intelligence Expansion Phases 1-5 and prior work.

## Problem

There is no way to search across the platform's entities today. The Scenarios tab has its own local search box (`sc-search`) that only searches loaded scenarios; nothing else — Runs, Findings, Threat Actors, Campaigns, Malware, Tools, Techniques — is searchable at all, and nothing is searchable from outside its own tab. The user's stated end goal is a single global search that becomes the platform's primary navigation layer, matching Linear/Raycast/Notion/Cursor. That full vision spans ~40 entity types, a ranking/personalization engine, a query-operator language, and a rebuilt command-palette UI — far too large for one design. This phase builds only the foundation: a real, ranked, multi-entity search index and a single query API, covering the 8 entity types that already exist as real backend objects today.

## Non-Goals (this phase)

- **No frontend changes.** The existing ⌘K command palette (`openCmdk()`, pure client-side navigation) is untouched. This phase ships a backend API only; wiring it into a rebuilt command interface is Phase 2.
- **No personalization/popularity ranking.** Exact/prefix/substring relevance via Postgres full-text search ships now (see Architecture §1); popularity, recency, favorites, and org-wide usage frequency require new usage-tracking infrastructure that doesn't exist yet — deferred to Phase 3 (Ranking & Personalization).
- **No search-operator query language** (`type:scenario`, `status:failed`, `os:windows`, etc.) — Phase 4.
- **No long-tail entity types.** Detection Profiles, Compliance controls/benchmarks, Connectors, Exercise templates, Sigma/YARA rules, documentation/changelogs, and a real Asset/Endpoint catalog are either not yet real backend objects or are out of scope for this phase — Phase 5. Only the 8 entity types confirmed real today are indexed: **Scenarios, Runs, Findings, Threat Actors, Campaigns, Malware, Tools, Techniques**.
- **No per-result instant actions** (Run/Favorite/Copy ID/Generate Report, etc.) — these are UI affordances that belong to Phase 2's command interface, not this phase's data API.
- **No rich preview data** (variant lists, expected-detection-product lists, etc.) beyond `title`/`description`/`tags` — Phase 2 can layer richer preview fetches on top of a search result's `(doc_type, source_id)` once a UI needs it.

## Architecture

### 1. `search_documents` — one maintained table, Postgres full-text search for ranking

```sql
CREATE TABLE search_documents (
    id            bigserial PRIMARY KEY,
    doc_type      text NOT NULL,   -- 'scenario' | 'run' | 'finding' | 'actor' | 'campaign' | 'malware' | 'tool' | 'technique'
    source_id     text NOT NULL,   -- the entity's own ID/key in its home table/source
    title         text NOT NULL,
    description   text NOT NULL DEFAULT '',
    tags          text[] NOT NULL DEFAULT '{}',
    search_vector tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('english', title), 'A') ||
        setweight(to_tsvector('english', coalesce(description, '')), 'B') ||
        setweight(to_tsvector('english', array_to_string(tags, ' ')), 'C')
    ) STORED,
    updated_at    timestamptz NOT NULL DEFAULT NOW(),
    tenant_id     text NOT NULL DEFAULT 'default',
    UNIQUE (doc_type, source_id)
)
```
GIN index on `search_vector`. `setweight`'s A/B/C tiers mean a title match always outranks a description-only match, which always outranks a tag-only match — combined with Postgres's `ts_rank`, this gives real exact/prefix/substring-aware relevance without any custom ranking code. No `url` column — see Non-Goals; a search result's `(doc_type, source_id)` is enough for a future UI to resolve into whatever navigation action makes sense once one exists.

### 2. Reindexing — full per-type rebuild, not incremental diffing, not per-write hooks

For each of the 8 sources, one function builds `[]search.Document` from that source's current state, then a store function replaces exactly that type's rows in one transaction: `DELETE FROM search_documents WHERE doc_type = $1` then bulk-insert the fresh set. Each type's rebuild is its own transaction — rebuilding `technique` never empties or blocks `scenario` results mid-query.

This uniformly covers both DB-backed sources (Runs, Findings, Actors, Campaigns, Malware, Tools, Techniques — queried directly) and the file-backed Scenarios (`scenario.Engine.List()`, already in memory, no query needed) with one mechanism — no per-write-path upsert hooks scattered across 8 different subsystems, which would be Phase 1's biggest source of invasiveness and risk for comparatively little benefit at this stage (search freshness lagging by up to the reindex interval is an acceptable trade-off for a search feature, unlike e.g. financial data).

Two triggers:
- **Timer**, reusing the exact pattern `internal/connector.Scheduler` already uses (`time.NewTicker` + `for {}` loop, started via a `.Start()` method called once from `cmd/server/main.go` alongside the existing `scheduler.Start()` call). Default interval: 60 seconds — frequent enough that search feels current, infrequent enough not to matter at this data scale.
- **On-demand**: `POST /api/search/reindex`, gated `tierAdminOnly` (this codebase's existing admin-only RBAC tier — confirmed real via `rbac_matrix_test.go`), triggers an immediate full rebuild of all 8 types. Useful right after bulk data changes and for tests.

### 3. Document builders — one function per source, each returning `[]search.Document`

```go
type Document struct {
    DocType     string
    SourceID    string
    Title       string
    Description string
    Tags        []string
}
```

Eight builder functions, each reading its own source and mapping into `Document`:
- `scenariosFrom(engine *scenario.Engine) []Document` — `Name`→Title, `Description`→Description, `Tags` ∪ `MITREPhases` ∪ `ARTTechniques`→Tags.
- `runsFrom(ctx, pool) ([]Document, error)` — queries `scenario_runs`; Title = `name` (falls back to `scenario_id` if empty, matching existing UI convention), Description = `status`, Tags = `[]string{status}`.
- `findingsFrom(ctx, pool) ([]Document, error)` — queries `findings`; Title = `technique_name` (falls back to `technique_id`), Description = `severity` + `exposure_state`, Tags = `[control_class, severity, status]`.
- `actorsFrom(ctx, pool) ([]Document, error)` — queries `threat_actor_profiles`; Title = `name`, Tags = `aliases` ∪ `sectors` ∪ `regions`.
- `campaignsFrom(ctx, pool) ([]Document, error)` — `intelligence.ListCampaigns`; Title = `Name`, Description = `Description`, Tags = `Aliases`.
- `malwareFrom(ctx, pool) ([]Document, error)` — `intelligence.ListMalware`; Title = `Name`, Tags = `Aliases` ∪ `MalwareTypes`.
- `toolsFrom(ctx, pool) ([]Document, error)` — `intelligence.ListTools`; Title = `Name`, Tags = `Aliases`.
- `techniquesFrom(ctx, pool) ([]Document, error)` — queries `techniques`; Title = `technique_id` + `name` (e.g. `"T1059 Command and Scripting Interpreter"`, so both the ID and the name independently match), Description = `description`, Tags = `[tactic]`.

Reusing `internal/intelligence`'s existing `List*` functions for Campaign/Malware/Tool (not raw SQL) keeps this package from re-deriving query logic Phase 1-5 already built and tested.

### 4. Query API

```go
// GET /api/search?q=<term>&limit=<n>
func (h *Handler) Search(w http.ResponseWriter, r *http.Request)
```

Runs `SELECT doc_type, source_id, title, description, tags, ts_rank(search_vector, query) AS rank FROM search_documents, plainto_tsquery('english', $1) query WHERE search_vector @@ query ORDER BY rank DESC LIMIT $2`. Returns a flat JSON array (never nested/pre-grouped — see Non-Goals), each result carrying its own `docType`. `limit` defaults to 25, capped at 100. An empty or whitespace-only `q` returns an empty array, not an error or the full table.

## Testing

- `internal/search`: one test per builder function (hand-seed each source's real table/in-memory engine, assert the mapped `Document` fields), using `testutil.TestDB` (matches every other Postgres-backed package this session).
- `TestReindex_RebuildsOneTypeWithoutTouchingOthers` — seed `search_documents` with rows of two different `doc_type`s, reindex only one type, assert the other type's rows are untouched.
- `TestQuery_RanksTitleMatchAboveDescriptionMatch` — two documents, one matching the query term in `title`, one only in `description`; assert the title match ranks first.
- `TestQuery_EmptyQueryReturnsEmptyNotFullTable` — guards against an accidental full-table dump.
- `internal/api`: RBAC matrix entries for `GET /api/search` (`tierAny`) and `POST /api/search/reindex` (`tierAdminOnly`), matching `rbac_matrix_test.go`'s existing pattern.
- Full regression (`go build ./...`, `go vet ./...`, `go test ./... -count=1`) as the closing task.
