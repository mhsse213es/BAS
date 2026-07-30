# Global Search Phase 5 (Long-Tail Entity Expansion) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-30.
**Depends on:** [[Global Search]] Phase 1 (`internal/search.Query()`, `search_documents`, `ReindexAll`), Phase 2 (⌘K palette, grouped results, `cmdkResultFallback`), Phase 3 (`Personalize()`), Phase 4 (`type:` operator, `ParseQuery`/`knownDocTypes`). Phase 2/3 manual browser QA and Run Workspace Sub-project A's manual QA are still pending as of this write-up — flagged, not blocking this spec.

## Problem

The original Global Search vision named Phase 5 as "long-tail entity expansion: Detection Profiles, Compliance controls, Connectors, Sigma/YARA, docs." Investigated each candidate against real backend objects before committing to scope, rather than indexing everything named in the original one-line roadmap description.

**Dropped, with reasons:**
- **Detection Profiles** (`scenario.DetectionProfile`) — real, but each one is just a slug-like `Profile` name + a `Version` int + an `Extends` list + `Expected []ExpectedDetection`. No title/description prose to rank against, and no UI anywhere lists them individually. Too thin to be a useful search result.
- **Docs** — no in-app help/KB article table exists anywhere in this codebase. Not a real entity; including it would mean fabricating content, which this project's search phases have never done.

**Kept, all real and confirmed to have genuine title/description content:**
- **Detection Rule Library** (`internal/rulelib`) — embedded Sigma rules, each with a real `Title`/`Description`/`TechniqueIDs`.
- **Compliance controls** (`internal/compliance`) — YAML-defined per framework, each with a real `Name`/`Domain`/`Category`/`Techniques`.
- **Connectors** — two genuinely separate Postgres tables, `detection_connectors` and `action_connectors`, each with a real `name`/`provider`.

Connectors introduce a problem none of the first 8 types had: listing them today is **permission-gated** (`CanListDetectionConnectors` / `CanListResponseConnectors`), unlike every type Search has indexed so far, which are all visible to any authenticated user. This spec adds the first RBAC-aware filtering Search has ever needed.

## Non-Goals

- **No merging of `detection_connector` and `action_connector` into one `connector` type.** They're gated by two independently-grantable permissions; merging would force an all-or-nothing filter and either over-hide a connector type from someone who has one permission but not the other, or leak a connector type to someone who has neither. Kept as two distinct doc types, each with its own permission check.
- **No real per-entity navigation for `rule` or `compliance_control`.** Neither has a detail view anywhere in the app today (rulelib is API-only, the compliance tab is framework-level, not addressable per-control). Both reuse the existing `cmdkResultFallback` drawer (the same treatment Phase 2 already gives `campaign`/`malware`/`tool`) rather than building new UI.
- **No generic, table-driven RBAC-filter mechanism.** Only two doc types need permission gating today. A `map[docType]Permission` abstraction for N=2 is speculative generality; the handler gets two explicit, readable `if` checks instead. Revisit if a third gated type ever shows up.
- **No changes to `ParseQuery`'s duplicate/unsupported-field handling, browse-mode logic, or the `/api/search/operators` endpoint.** Phase 4's parser already only needs its `knownDocTypes` set extended — the parsing/validation architecture itself is untouched.
- **No changes to `Personalize()` or `Recents()`.** Both operate generically on whatever `[]Document` they're given; new doc types need no special-casing there. RBAC filtering happens *before* `Personalize()` is called, so favorited/recently-viewed restricted docs a user has since lost access to are excluded the same as any other invisible result — confirmed acceptable since `Personalize()`/`Recents()` were never meant to be an authorization layer.

## Architecture

### 1. Four new builders in `internal/search/builders.go`

Same shape as the existing 8 builders — a function returning `[]Document`, called once per reindex cycle.

```go
// rulesFrom maps every embedded Sigma rule into a Document. engine is never
// nil (rulelib.NewEngine() always returns a valid *Engine, empty on load
// failure) but may hold zero rules.
func rulesFrom(engine *rulelib.Engine) []Document {
	rules := engine.Search(rulelib.SearchFilter{}) // empty filter = every rule, same call ListRules already makes
	out := make([]Document, 0, len(rules))
	for _, r := range rules {
		out = append(out, Document{
			DocType: "rule", SourceID: r.ID, Title: r.Title,
			Description: r.Description, Tags: append([]string{r.Severity, r.Status}, r.TechniqueIDs...),
		})
	}
	return out
}

// complianceControlsFrom maps every control across every loaded framework
// into a Document. mapper may be nil (WithCompliance was never called, or
// compliance.NewMapper() failed at startup) -- returns no documents rather
// than erroring, matching how h.complianceMapper == nil is already handled
// throughout internal/api's compliance handlers.
func complianceControlsFrom(mapper *compliance.Mapper) []Document {
	if mapper == nil {
		return nil
	}
	out := []Document{}
	for _, cwf := range mapper.AllControls() {
		tags := append([]string{cwf.FrameworkID, cwf.Control.Domain, cwf.Control.Category}, cwf.Control.Techniques...)
		out = append(out, Document{
			DocType:  "compliance_control",
			SourceID: cwf.FrameworkID + ":" + cwf.Control.ID, // namespaced -- the same control ID can recur across frameworks
			Title:    cwf.Control.Name,
			Description: cwf.Control.Domain + " · " + cwf.Control.Category,
			Tags:     tags,
		})
	}
	return out
}

// detectionConnectorsFrom maps every detection_connectors row into a
// Document. Selects only name/provider -- never client_secret/api_token,
// matching the same restraint ListDetectionConnectors's own SELECT already
// exercises.
func detectionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, provider FROM detection_connectors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, provider string
		if err := rows.Scan(&id, &name, &provider); err != nil {
			return nil, err
		}
		out = append(out, Document{
			DocType: "detection_connector", SourceID: id, Title: name,
			Description: "provider: " + provider, Tags: []string{provider},
		})
	}
	return out, rows.Err()
}

// actionConnectorsFrom mirrors detectionConnectorsFrom for action_connectors
// (EPP response-action connectors) -- deliberately the same shape, kept as
// a separate function since the two tables have different RBAC gates (see
// Architecture §3) and may diverge in columns later.
func actionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, provider FROM action_connectors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, provider string
		if err := rows.Scan(&id, &name, &provider); err != nil {
			return nil, err
		}
		out = append(out, Document{
			DocType: "action_connector", SourceID: id, Title: name,
			Description: "provider: " + provider, Tags: []string{provider},
		})
	}
	return out, rows.Err()
}
```

### 2. New `compliance.Mapper.AllControls()` accessor

`Mapper` has no flat, cross-framework control list today — only per-framework access via `GenerateReport`. A small, targeted addition (the kind of existing-code improvement writing-plans/brainstorming calls for when it directly serves the current goal):

```go
// ControlWithFramework pairs a control with the ID of the framework that
// defines it -- AllControls flattens every loaded framework's controls into
// one slice for consumers (Global Search Phase 5) that don't care about
// per-framework grouping.
type ControlWithFramework struct {
	FrameworkID string
	Control     ControlDef
}

// AllControls returns every control across every loaded framework, sorted
// by FrameworkID then control ID for deterministic output.
func (m *Mapper) AllControls() []ControlWithFramework {
	out := make([]ControlWithFramework, 0)
	for _, fw := range m.frameworks {
		for _, ctrl := range fw.Controls {
			out = append(out, ControlWithFramework{FrameworkID: fw.ID, Control: ctrl})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FrameworkID != out[j].FrameworkID {
			return out[i].FrameworkID < out[j].FrameworkID
		}
		return out[i].Control.ID < out[j].Control.ID
	})
	return out
}
```

### 3. `ReindexAll` grows two parameters

```go
func ReindexAll(ctx context.Context, pool *pgxpool.Pool, engine *scenario.Engine, rules *rulelib.Engine, mapper *compliance.Mapper) error
```

Four new entries added to its internal `steps` table, same pattern as the existing 8:

```go
{"rule", func() ([]Document, error) { return rulesFrom(rules), nil }},
{"compliance_control", func() ([]Document, error) { return complianceControlsFrom(mapper), nil }},
{"detection_connector", func() ([]Document, error) { return detectionConnectorsFrom(ctx, pool) }},
{"action_connector", func() ([]Document, error) { return actionConnectorsFrom(ctx, pool) }},
```

Both call sites in `cmd/server/main.go` (the synchronous startup reindex and the 60s-ticker reindex) already construct `rulesEngine` (line 212) and `complianceMapper` (line 181) before reaching the `ReindexAll` calls (lines 262/267) — passing them through is a same-call-site signature change, not new wiring. `search_handlers.go`'s `SearchReindex` handler (`POST /api/search/reindex`) also needs both added to its `h.rules`/`h.complianceMapper` call, which the `Handler` struct already holds as fields.

### 4. RBAC filtering — new to Search, lives in the handler

`internal/search` stays free of any `auth` dependency, matching its existing design (Personalize/Recents are user-*scoped*, by ID, but never permission-*gated*). The filter is two explicit checks in `internal/api/search_handlers.go`'s `Search` handler, applied to `Query()`'s output before `Personalize()` re-ranks it:

```go
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	results, err := search.Query(r.Context(), h.db, q, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	c, hasClaims := auth.ClaimsFrom(r.Context())
	results = filterByPermission(results, hasClaims, c)

	if hasClaims && c != nil {
		if personalized, perr := search.Personalize(r.Context(), h.db, c.UserID, results); perr == nil {
			results = personalized
		}
	}
	respond(w, results)
}

// filterByPermission drops connector-type documents the caller's role
// can't see via their own dedicated list endpoints -- the first RBAC-aware
// filtering Search has needed (Phase 5). Every other doc type stays
// visible to any authenticated user, unchanged from Phase 1-4.
func filterByPermission(docs []search.Document, hasClaims bool, c *auth.Claims) []search.Document {
	canDetection := hasClaims && c != nil && auth.HasPermission(c.Role, auth.CanListDetectionConnectors)
	canAction := hasClaims && c != nil && auth.HasPermission(c.Role, auth.CanListResponseConnectors)
	if canDetection && canAction {
		return docs // fast path: nothing to filter
	}
	out := docs[:0]
	for _, d := range docs {
		if d.DocType == "detection_connector" && !canDetection {
			continue
		}
		if d.DocType == "action_connector" && !canAction {
			continue
		}
		out = append(out, d)
	}
	return out
}
```

`GET /api/search` itself stays `tierAny` (any authenticated user can search) — the gate is per-result, not per-route, since a single query can legitimately mix visible and restricted-but-present doc types.

### 5. `ParseQuery`'s `knownDocTypes` grows 4 entries

`internal/search/query_parse.go`'s `knownDocTypes` map gets `"rule"`, `"compliance_control"`, `"detection_connector"`, `"action_connector"` added, so `type:rule` etc. work in both ranked and browse mode exactly like the existing 8 types. No other change to `ParseQuery`, `Query()`'s SQL, or the operators endpoint — Phase 4's architecture already anticipated this.

Browse mode (`type:detection_connector` alone) runs through the same `filterByPermission` step as any other query — a non-admin browsing `type:detection_connector` gets an empty result set, not an error and not a leaked count.

### 6. Frontend — 2 small, necessary edits (not zero-touch)

Both in `cmd/server/wwwroot/index.html`, both inside the same `openCmdk()` closure Phase 2/3 already touched:

- **`CMDK_SEARCH_LABELS`** gains 4 entries: `rule: 'Detection Rules'`, `compliance_control: 'Compliance Controls'`, `detection_connector: 'Detection Connectors'`, `action_connector: 'Response Connectors'`. Without this, `cmdkResultFallback`'s drawer title renders `<title> — undefined`.
- **`searchFlat()`**'s hardcoded doc-type iteration array gains the same 4 names (appended after `'technique'`). Without this, results of the new types are returned by the API but silently dropped from the grouped palette display — they'd never render at all.

No change to `cmdkOpenResult`'s dispatch logic: its existing `else` branch already routes any `docType` it doesn't explicitly recognize to `cmdkResultFallback`, so all 4 new types work through that path with zero new dispatch code.

## Testing

- `internal/search/builders_test.go` additions: `rulesFrom` with a fixture `*rulelib.Engine` (via `loadFromBytes`, matching the existing test pattern) asserting title/description/tags map correctly, including the zero-rules case; `complianceControlsFrom` with a real `*compliance.Mapper` loaded from the existing test mapping fixture, asserting `SourceID` is namespaced `frameworkID:controlID` and a `nil` mapper returns `nil`/no documents; `detectionConnectorsFrom`/`actionConnectorsFrom` against a real Postgres testcontainer, asserting `client_secret`/`api_token`/`tenant_id`/`base_url` never appear in the returned `Document`'s `Title`/`Description`/`Tags`.
- `internal/compliance/mapper_test.go` addition: `TestAllControls_FlattensEveryFrameworkSortedDeterministically`.
- `internal/search/store_test.go` additions: `ReindexAll` populates all 4 new doc types given non-nil `rules`/`mapper` args; `ReindexAll` with a `nil` `mapper` still succeeds and simply indexes zero `compliance_control` docs (not an error).
- `internal/search/query_parse_test.go` additions: `"type:rule sigma"`, `"type:compliance_control"` (browse mode), `"type:detection_connector"`, `"type:action_connector"` all parse to the expected `DocType`.
- `internal/api/search_handlers_test.go` additions: `TestSearch_NonAdminNeverSeesDetectionConnectorResults`, `TestSearch_NonAdminNeverSeesActionConnectorResults`, `TestSearch_AdminWithBothPermissionsSeesConnectorResults`, `TestSearch_BrowseModeConnectorTypeEmptyForNonAdmin` — each seeds `search_documents` directly (matching existing handler-test style) with a mix of restricted and unrestricted docs, issues the request with a role that has/lacks the relevant permission, and asserts the restricted doc types are present/absent accordingly.
- `internal/api/rbac_matrix_test.go`: no new route (this phase adds no new endpoint), so no new entry needed — confirmed by checking the matrix only tracks routes, not per-result filtering.

## Manual QA (deferred, matching this project's established pattern)

Palette shows "Detection Rules"/"Compliance Controls"/"Detection Connectors"/"Response Connectors" section headers when a query matches; a non-admin user's search never surfaces connector results even when the query text matches a real connector's name; `type:rule`, `type:compliance_control` browse mode list everything of that type; an admin sees connector results, a non-admin doesn't, for the identical query.
