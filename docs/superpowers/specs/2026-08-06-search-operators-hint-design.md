# Search Operators Hint Design

**Goal:** Wire up `GET /api/search/operators` into the title-bar ⌘K command palette so users can discover the `type:` filter and its valid values, instead of the endpoint sitting unused.

## Background

The palette (`orchestrator/wwwroot/index.html`, `openCmdk()`, ~lines 13241-13391) is the real Global Search UI — confirmed this session it does live, ranked, RBAC-aware, personalized search against `GET /api/search`. `GET /api/search/operators` already exists (`orchestrator/internal/api/search_handlers.go:159-161`) but the frontend never calls it (confirmed by grep — zero references), and even if it did, today's response is too thin to be useful as a hint:

```json
{"operators": ["type"]}
```

This tells you the operator *name* exists, not what values it accepts. The valid values (the 12 doc types: `scenario`, `run`, `finding`, `actor`, `campaign`, `malware`, `tool`, `technique`, `rule`, `compliance_control`, `detection_connector`, `action_connector`) currently live only in an unexported map, `knownDocTypes` (`orchestrator/internal/search/query_parse.go:36-40`), used internally by `ParseQuery()`.

## 1. Backend: export the doc-type list and enrich the response

Add a new exported var to `query_parse.go`, built once from `knownDocTypes` so there is still exactly one source of truth (not a third hand-maintained copy):

```go
// KnownDocTypes lists every value a type: filter can resolve to, sorted for
// stable output. Built once from knownDocTypes so GET /api/search/operators
// and ParseQuery's validation can never drift from each other.
var KnownDocTypes = func() []string {
	out := make([]string, 0, len(knownDocTypes))
	for dt := range knownDocTypes {
		out = append(out, dt)
	}
	sort.Strings(out)
	return out
}()
```

Change `SearchOperators` (`search_handlers.go:159-161`) to return operator name **and** valid values, shaped as a list of objects rather than a flat map — so a second operator added later (the codebase already anticipates this; `ParsedQuery`'s `InvalidFilters` doc comment mentions future fields like Status/OS/Tag) doesn't require a response-shape change, just another entry:

```json
{
  "operators": [
    { "name": "type", "values": ["action_connector", "actor", "campaign", "compliance_control", "detection_connector", "finding", "malware", "rule", "run", "scenario", "technique", "tool"] }
  ]
}
```

Today there's only one operator (`type`), so this is a one-entry array — but the shape doesn't need revisiting when a second one is added.

## 2. Frontend: fetch once, render as a persistent footer hint

In `openCmdk()`, alongside the existing one-shot `GET /api/search/recents` fetch (fired once when the palette opens, not per-keystroke), add a matching one-shot `GET /api/search/operators` fetch. Render the result as a static footer line below `#cmdk-list`, styled with the existing `.bld-mode-help` convention (muted, small text — the same class the Technique Selector's example line uses, so this doesn't introduce a new visual pattern):

> Tip: type:scenario, type:run, type:finding... to filter by type.

This line is always visible whenever the palette is open, independent of query state — no flicker, no logic tied to what the user is typing. If the fetch fails, the footer is simply omitted (fails soft, matching how `recents` already fails soft to an empty list on error).

## Non-goals

- No contextual/inline hint that appears specifically while typing `type:` (e.g. an autocomplete dropdown of valid values as you type past the colon) — that's a real but separate enhancement, not part of this pass.
- No changes to `ParseQuery()`'s validation logic, `InvalidFilters`, or any other operator-parsing behavior — this is purely a discoverability addition on top of what already works.
- No new operators — `type` remains the only supported filter; this spec only makes its existing, already-working values discoverable.

## Testing

Backend: `KnownDocTypes` gets a small Go unit test in `orchestrator/internal/search` confirming it matches `knownDocTypes`'s key set and is sorted. No automated frontend test framework exists for `wwwroot/index.html` (established pattern) — frontend verification is manual: open the palette, confirm the footer hint appears, confirm it lists all 12 doc types, confirm typing `type:scenario` still filters results correctly (unchanged existing behavior), confirm the palette still opens/works normally if the network request is blocked (fails soft, no broken palette).
