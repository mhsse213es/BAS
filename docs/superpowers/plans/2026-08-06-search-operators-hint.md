# Search Operators Hint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire up `GET /api/search/operators` into the ⌘K command palette so the `type:` filter's valid values are discoverable, instead of the endpoint sitting unused with a too-thin response.

**Architecture:** Backend exports the doc-type list already used internally by `ParseQuery()` (single source of truth, no third duplicated list), and the handler returns it alongside the operator name. Frontend fetches it once when the palette opens (same one-shot pattern as the existing `recents` fetch) and renders a persistent footer hint.

**Tech Stack:** Go (`net/http`), vanilla JS (`orchestrator/wwwroot/index.html`, no build step).

## Global Constraints

- No changes to `ParseQuery()`'s validation logic, `InvalidFilters`, or any other operator-parsing behavior — this is a discoverability addition only.
- No new operators — `type` remains the only supported filter.
- No automated frontend test framework exists for `wwwroot/index.html` (established pattern in this codebase) — frontend verification is manual/browser-based.
- The response shape must stay extensible for a future second operator without another shape change: an array of `{name, values}` objects, not a flat map.

---

### Task 1: Export the doc-type list, enrich the endpoint, wire the palette hint

**Files:**
- Modify: `orchestrator/internal/search/query_parse.go` (add `KnownDocTypes`)
- Test: `orchestrator/internal/search/query_parse_test.go` (create if it doesn't exist, or add to it if it does — check first)
- Modify: `orchestrator/internal/api/search_handlers.go:159-161` (`SearchOperators`)
- Modify: `orchestrator/wwwroot/index.html` (`openCmdk()`, currently starting at line 13241)

**Interfaces:**
- Produces: `search.KnownDocTypes []string` — sorted, built once from the existing private `knownDocTypes` map. `GET /api/search/operators` now returns `{"operators": [{"name": "type", "values": [...]}]}` instead of `{"operators": ["type"]}`.

- [ ] **Step 1: Check for an existing test file**

Run: `ls orchestrator/internal/search/query_parse_test.go 2>&1`

If it exists, Step 2's test gets appended to it. If not, Step 2 creates it fresh with a `package search` header.

- [ ] **Step 2: Write the failing test**

Add to `orchestrator/internal/search/query_parse_test.go` (create the file with `package search` + `import "testing"` + `import "sort"` at the top if it doesn't already exist):

```go
package search

import (
	"sort"
	"testing"
)

// KnownDocTypes must expose exactly the same set ParseQuery validates
// type: values against, and must be sorted (the /api/search/operators
// response depends on stable ordering).
func TestKnownDocTypesMatchesInternalSet(t *testing.T) {
	if len(KnownDocTypes) != len(knownDocTypes) {
		t.Fatalf("KnownDocTypes has %d entries, knownDocTypes has %d", len(KnownDocTypes), len(knownDocTypes))
	}
	for _, dt := range KnownDocTypes {
		if !knownDocTypes[dt] {
			t.Errorf("KnownDocTypes contains %q, not present in knownDocTypes", dt)
		}
	}
	if !sort.StringsAreSorted(KnownDocTypes) {
		t.Error("KnownDocTypes must be sorted")
	}
}
```

(If the file already exists with its own `package search` line and imports, just add the test function and merge any missing imports rather than duplicating the header.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/search/... -run TestKnownDocTypesMatchesInternalSet -v`
Expected: `FAIL` — `KnownDocTypes` is undefined (compile error).

- [ ] **Step 4: Implement `KnownDocTypes`**

In `orchestrator/internal/search/query_parse.go`, add right after the existing `knownDocTypes` map (currently lines 34-40):

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

Add `"sort"` to the file's import block (currently just `import "strings"` at line 3):

```go
import (
	"sort"
	"strings"
)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/search/... -v`
Expected: `PASS` for `TestKnownDocTypesMatchesInternalSet` and every other test already in the package (nothing else should be affected).

- [ ] **Step 6: Update the `SearchOperators` handler**

In `orchestrator/internal/api/search_handlers.go`, replace (currently lines 159-161):

```go
func (h *Handler) SearchOperators(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]any{"operators": search.SupportedOperators})
}
```

with:

```go
// searchOperatorInfo describes one supported search-box operator and the
// values it accepts, for the ⌘K palette's discoverability hint.
type searchOperatorInfo struct {
	Name   string   `json:"name"`
	Values []string `json:"values,omitempty"`
}

func (h *Handler) SearchOperators(w http.ResponseWriter, r *http.Request) {
	ops := make([]searchOperatorInfo, 0, len(search.SupportedOperators))
	for _, name := range search.SupportedOperators {
		info := searchOperatorInfo{Name: name}
		if name == "type" {
			info.Values = search.KnownDocTypes
		}
		ops = append(ops, info)
	}
	respond(w, map[string]any{"operators": ops})
}
```

(The `if name == "type"` branch is deliberately explicit rather than a generic lookup table — there's exactly one operator today, and a second one later will need its own values source decided at that time anyway, not a premature generic mechanism now.)

- [ ] **Step 7: Build and run the backend test suite for the touched packages**

Run: `cd orchestrator && go build ./... && go test ./internal/search/... ./internal/api/... -run "TestKnownDocTypes|TestRBAC" -v`
Expected: build succeeds, `TestKnownDocTypesMatchesInternalSet` passes, and the RBAC matrix tests (which already cover `GET /api/search/operators` at `tierAny`, per `rbac_matrix_test.go:107`) still pass — confirming the handler change didn't alter its auth tier or break the route.

- [ ] **Step 8: Add the palette footer markup**

In `orchestrator/wwwroot/index.html`, inside `openCmdk()`, find the `wrap.innerHTML` assignment (currently lines 13247-13253):

```js
  wrap.innerHTML =
    '<div class="cmdk" role="dialog" aria-label="Command palette">' +
      '<div class="cmdk-in">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>' +
        '<input id="cmdk-input" placeholder="Type a command or search…" autocomplete="off">' +
        '<span class="cmdk-esc">esc</span>' +
      '</div><div class="cmdk-list" id="cmdk-list"></div></div>';
```

Replace with (adds a hidden-by-default footer div, shown once the operators fetch resolves in Step 9):

```js
  wrap.innerHTML =
    '<div class="cmdk" role="dialog" aria-label="Command palette">' +
      '<div class="cmdk-in">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>' +
        '<input id="cmdk-input" placeholder="Type a command or search…" autocomplete="off">' +
        '<span class="cmdk-esc">esc</span>' +
      '</div><div class="cmdk-list" id="cmdk-list"></div>' +
      '<div class="bld-mode-help" id="cmdk-ops-hint" style="display:none;margin:0;padding:8px 15px;border-top:1px solid var(--border)"></div>' +
    '</div>';
```

- [ ] **Step 9: Fetch the operators list and populate the footer**

In the same function, right after the existing one-shot `recents` fetch (currently lines 13289-13293):

```js
  var cmdkRecents = [];
  apicall('/api/search/recents').then(function(r) {
    cmdkRecents = Array.isArray(r) ? r : [];
    if (currentQ === '') render(currentQ);
  }).catch(function() { cmdkRecents = []; });
```

add immediately after it:

```js
  apicall('/api/search/operators').then(function(r) {
    var ops = (r && Array.isArray(r.operators)) ? r.operators : [];
    var typeOp = ops.filter(function(o) { return o.name === 'type' && Array.isArray(o.values) && o.values.length; })[0];
    if (!typeOp) return;
    var hint = wrap.querySelector('#cmdk-ops-hint');
    hint.textContent = 'Tip: ' + typeOp.values.map(function(v) { return 'type:' + v; }).join(', ') + ' to filter by type.';
    hint.style.display = '';
  }).catch(function() { /* fails soft -- footer just stays hidden */ });
```

- [ ] **Step 10: Verify the syntax is still valid**

Run:

```bash
node -e "
  const fs = require('fs');
  const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  new Function(m[1]);
  console.log('script block parses OK');
"
```

Expected: `script block parses OK`.

- [ ] **Step 11: Manual browser verification**

No automated frontend test framework exists for this file. Start the dashboard (Docker Compose rebuild, since `wwwroot` is baked into the image, or `go run ./cmd/server` against a reachable local Postgres with `BAS_LICENSE_PATH` set) and in a browser:

1. Open the ⌘K palette (click the launcher or press Ctrl/Cmd-K). Confirm the footer hint appears below the results list, listing all 12 doc types as `type:scenario, type:run, type:finding, ...`.
2. Type `type:scenario` in the search box — confirm results still filter to scenarios only (unchanged existing behavior; this feature only adds discoverability, it doesn't touch filtering logic).
3. Open dev tools' Network tab, reopen the palette — confirm `GET /api/search/operators` fires exactly once per palette open, not per keystroke.
4. Simulate the operators request failing (e.g. block the route or throttle to offline briefly right as you open the palette) — confirm the palette still opens and works normally, just without the footer hint (fails soft, no broken UI).

If any of these fail, stop and report — do not proceed to commit with a known-broken hint or a regression in existing filter behavior.

- [ ] **Step 12: Commit**

```bash
git add orchestrator/internal/search/query_parse.go \
        orchestrator/internal/search/query_parse_test.go \
        orchestrator/internal/api/search_handlers.go \
        orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(search): surface supported type: values in the command palette

GET /api/search/operators previously returned just the operator name
("type"), not what values it accepts -- not useful as a discoverability
hint on its own. Now returns {name, values} per operator, sourced from
a newly-exported search.KnownDocTypes (built once from the same map
ParseQuery already validates against, so there's still one source of
truth). The ⌘K palette fetches it once per open and shows a persistent
footer hint listing every type:<value> filter, failing soft if the
request errors.
EOF
)"
git push
```

---

## Self-Review Notes

- **Spec coverage:** Backend export + enriched response (spec §1) → Steps 1-7. Frontend one-shot fetch + persistent footer render, `.bld-mode-help` styling reused, fails-soft on error (spec §2) → Steps 8-9. Non-goals (no contextual/inline hint, no `ParseQuery` changes, no new operators) are not implemented anywhere in this plan. The spec's 4-point manual testing list is Step 11's 4 checks, in the same order.
- **Placeholder scan:** none — every step has literal, complete code or an exact shell command.
- **Type consistency:** `searchOperatorInfo{Name, Values}` (Go, Step 6) matches exactly what the frontend reads in Step 9 (`o.name`, `o.values` — JSON's `omitempty` on `Values` means a future operator with no values simply omits the key, and the frontend's `Array.isArray(o.values) && o.values.length` guard already handles that case correctly without needing a change). `KnownDocTypes` (Step 4) is consumed by exactly one place (Step 6's handler), no drift risk elsewhere.
