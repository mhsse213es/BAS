# Technique Selector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the plain "Technique ID" text input in the Scenario Builder's custom-step editor with a searchable ATT&CK technique combobox — ranked matching across ID/name/tactic/keyword/synonym/fuzzy tiers, rich result cards, full keyboard navigation, and validation.

**Architecture:** Three layers. (1) A new read-only backend endpoint serves the full ATT&CK catalog from already-embedded STIX data. (2) A pure, DOM-free JS matching/ranking engine, verified standalone via a Node script before it's wired to anything. (3) A combobox UI component replacing the old field, consuming both.

**Tech Stack:** Go (`net/http`, `chi`), vanilla JS (no framework, no build step — `orchestrator/wwwroot/index.html` is edited and served directly), Node (verification only, not shipped).

## Global Constraints

- No database schema changes anywhere in this feature — the backend layer is built entirely from data already embedded in `orchestrator/internal/reporting/attackdata`.
- The synonym dictionary lives server-side as a new curated JSON file (`technique_synonyms.json`), following the exact loading pattern of the existing `curated_overlay.json` — not hardcoded in JS.
- Only the custom-step `st-tech` field is replaced. The separate ART/Caldera "Browse catalog" picker (`renderPickerList()`) is untouched.
- No automated frontend test framework exists for `wwwroot/index.html` (established pattern in this codebase) — frontend verification is manual/browser-based, except the pure matching engine, which gets a standalone Node-based verification script during development (not committed — this repo has no JS test runner to house it in).
- Non-goals (do not implement): multi-select, recent/favorite techniques, filter-by-tactic/platform/data-source, ART/Caldera/local-executor coverage badges, description/mitigation preview panel.

---

### Task 1: Backend — technique catalog endpoint

**Files:**
- Create: `orchestrator/internal/reporting/attackdata/technique_synonyms.json`
- Modify: `orchestrator/internal/reporting/attackdata/attackdata.go` (add `Aliases` field to `Enrichment`, embed the new file, extend `load()`, add `SubtechniqueCounts()`)
- Modify: `orchestrator/internal/api/handlers.go` (add `TechniqueCatalogEntry` type + `GetTechniqueCatalog` handler, add the `attackdata` import)
- Modify: `orchestrator/internal/api/routes.go` (register the route)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add the route to the tier table)
- Test: `orchestrator/internal/reporting/attackdata/attackdata_test.go`

**Interfaces:**
- Produces: `GET /api/techniques/catalog` returning `[]TechniqueCatalogEntry`, where each entry is `{id, name, tactics, platforms, description, detection, dataSources, permissions, subCount, aliases, url}` (all `omitempty` except `id`/`name`). Task 3 consumes this exact shape client-side.
- Produces: `attackdata.Enrichment.Aliases []string` and `attackdata.SubtechniqueCounts() map[string]int` — new, used only by `GetTechniqueCatalog`.

**Note — deliberate deviation from the spec's exact wording:** the spec describes a standalone `Synonyms(id string) []string` function. Instead, aliases are merged directly into `Enrichment.Aliases` during `load()`, exactly like the curated overlay's OWASP/CWE/CVE fields — so `Lookup(id)` already returns aliases with everything else, and no separate function is needed. Same behavior, one less function, more consistent with the existing "Lookup returns everything" pattern.

- [ ] **Step 1: Create the synonym dictionary file**

Create `orchestrator/internal/reporting/attackdata/technique_synonyms.json`:

```json
{
  "_README": "ANALYST-MAINTAINED SEARCH-SYNONYM DICTIONARY — used only by the Technique Selector's search matching, not authoritative ATT&CK data. Add/edit entries keyed by ATT&CK technique ID; each value is a list of alternate search terms. Keys starting with '_' are ignored.",
  "T1055": ["dll injection"],
  "T1547": ["startup", "autorun"],
  "T1003": ["mimikatz", "lsass dump"],
  "T1053": ["schtasks"]
}
```

- [ ] **Step 2: Write the failing test for alias merging**

Add to `orchestrator/internal/reporting/attackdata/attackdata_test.go`:

```go
// The synonym dictionary must merge into Lookup() results the same way the
// curated overlay does.
func TestLookupAliasesMerge(t *testing.T) {
	e := Lookup("T1055")
	if e == nil {
		t.Fatal("T1055 not found in embedded dataset")
	}
	if !slices.Contains(e.Aliases, "dll injection") {
		t.Errorf("T1055 should carry alias %q, got %v", "dll injection", e.Aliases)
	}
	// Authoritative data must survive the merge.
	if e.Name == "" {
		t.Error("authoritative name lost after alias merge")
	}
}

func TestLookupNoAliases(t *testing.T) {
	// T1078 (Valid Accounts) has no entry in technique_synonyms.json.
	e := Lookup("T1078")
	if e == nil {
		t.Fatal("T1078 not found in embedded dataset")
	}
	if len(e.Aliases) != 0 {
		t.Errorf("T1078 should have no aliases, got %v", e.Aliases)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/... -run TestLookupAliases -v`
Expected: `FAIL` — `e.Aliases` is undefined (compile error), since `Enrichment` has no `Aliases` field yet.

- [ ] **Step 4: Add the `Aliases` field, embed the file, and extend `load()`**

In `orchestrator/internal/reporting/attackdata/attackdata.go`, add the embed directive next to the existing two (after line 28, `var rawOverlay []byte`):

```go
//go:embed technique_synonyms.json
var rawSynonyms []byte
```

Add the `Aliases` field to the `Enrichment` struct, in the curated-overlay section (after `AnalystNotes` and `Curated`, currently lines 79-80):

```go
	AnalystNotes string   `json:"notes,omitempty"`
	Curated      bool     `json:"-"` // any curated field is set

	// Search-only synonym dictionary (technique_synonyms.json). Not ATT&CK
	// authoritative, not part of report enrichment — used solely by the
	// Scenario Builder's Technique Selector search matching.
	Aliases []string `json:"aliases,omitempty"`
```

Extend `load()` (currently lines 189-213) to also merge the synonym file, appending after the existing overlay-merge block:

```go
	var syn map[string]json.RawMessage
	if json.Unmarshal(rawSynonyms, &syn) == nil {
		for k, raw := range syn {
			if strings.HasPrefix(k, "_") { // documentation keys (e.g. _README)
				continue
			}
			var aliases []string
			if json.Unmarshal(raw, &aliases) != nil {
				continue // malformed entry — skip rather than fail the whole load
			}
			key := normalize(k)
			e := data[key]
			if e == nil {
				e = &Enrichment{TechniqueID: key}
				data[key] = e
			}
			e.Aliases = aliases
		}
	}
```

(`map[string]json.RawMessage` is used instead of `map[string][]string` because the `_README` value is a plain string, not an array — unmarshaling straight into `map[string][]string` would fail on that one entry and abort the whole file's load.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/... -run TestLookupAliases -v`
Expected: `PASS` for both `TestLookupAliasesMerge` and `TestLookupNoAliases`.

- [ ] **Step 6: Write the failing test for `SubtechniqueCounts`**

Add to the same test file:

```go
// SubtechniqueCounts must count sub-techniques under their parent and never
// count a technique under itself.
func TestSubtechniqueCounts(t *testing.T) {
	counts := SubtechniqueCounts()
	if counts["T1055"] == 0 {
		t.Error("T1055 (Process Injection) should have a nonzero sub-technique count")
	}
	if _, exists := counts["T1055.001"]; exists {
		t.Error("a sub-technique ID must not itself appear as a parent key")
	}
}
```

- [ ] **Step 7: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/... -run TestSubtechniqueCounts -v`
Expected: `FAIL` — `SubtechniqueCounts` is undefined.

- [ ] **Step 8: Implement `SubtechniqueCounts`**

Add to `attackdata.go`, after `GroupTechniqueIndex()` (currently ending at line 277):

```go
// SubtechniqueCounts returns, for every parent technique ID present in the
// loaded set, the number of its loaded sub-techniques (IDs carrying it as a
// dot-prefix, e.g. "T1055" → count of "T1055.001", "T1055.012", ...). A
// technique with no sub-techniques is simply absent from the map — callers
// should treat a missing key as zero.
func SubtechniqueCounts() map[string]int {
	once.Do(load)
	counts := make(map[string]int)
	for id := range data {
		if i := strings.IndexByte(id, '.'); i > 0 {
			counts[id[:i]]++
		}
	}
	return counts
}
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/attackdata/... -v`
Expected: `PASS` for all tests in the package, including the two new ones and `TestSubtechniqueCounts`.

- [ ] **Step 10: Add the handler**

In `orchestrator/internal/api/handlers.go`, add the import (after line 42, `"github.com/audspect/bas/internal/reporting"`):

```go
	"github.com/audspect/bas/internal/reporting/attackdata"
```

Add the type and handler near `GetUnifiedTechniques` (after its closing brace, currently line 3226):

```go
// TechniqueCatalogEntry is one row in the full ATT&CK technique search
// catalog served to the Scenario Builder's Technique Selector. Built
// entirely from the embedded attackdata dataset — read-only, no DB access.
type TechniqueCatalogEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactics     []string `json:"tactics,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Description string   `json:"description,omitempty"`
	Detection   string   `json:"detection,omitempty"`
	DataSources []string `json:"dataSources,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	SubCount    int      `json:"subCount,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// GET /api/techniques/catalog — the full ATT&CK technique catalog (every
// loaded technique, not just ones with ART/Caldera/BAS coverage) for the
// Scenario Builder's client-side Technique Selector search. Read-only,
// Viewer+, no DB access — built entirely from the embedded attackdata
// dataset, so it's safe to compute fresh on every request.
func (h *Handler) GetTechniqueCatalog(w http.ResponseWriter, r *http.Request) {
	refs := attackdata.All()
	subCounts := attackdata.SubtechniqueCounts()
	out := make([]TechniqueCatalogEntry, 0, len(refs))
	for _, ref := range refs {
		entry := TechniqueCatalogEntry{ID: ref.ID, Name: ref.Name, Tactics: ref.Tactics, SubCount: subCounts[ref.ID]}
		if e := attackdata.Lookup(ref.ID); e != nil {
			entry.Platforms = e.Platforms
			entry.Description = e.Description
			entry.Detection = e.Detection
			entry.DataSources = e.DataSources
			entry.Permissions = e.PermissionsRequired
			entry.Aliases = e.Aliases
			entry.URL = e.URL
		}
		out = append(out, entry)
	}
	respond(w, out)
}
```

- [ ] **Step 11: Register the route**

In `orchestrator/internal/api/routes.go`, add after line 181 (`r.Get("/api/techniques/unified", h.GetUnifiedTechniques)`):

```go
		r.Get("/api/techniques/catalog", h.GetTechniqueCatalog)
```

- [ ] **Step 12: Add the RBAC matrix entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, add after line 81 (`{http.MethodGet, "/api/techniques/unified", tierAny, ""},`):

```go
	{http.MethodGet, "/api/techniques/catalog", tierAny, ""},
```

- [ ] **Step 13: Build and run the full package test suite**

Run: `cd orchestrator && go build ./... && go test ./internal/reporting/attackdata/... ./internal/api/... -run "TestLookup|TestSubtechnique|TestRBAC" -v`
Expected: build succeeds, all matched tests `PASS` (this also exercises the RBAC matrix test, confirming the new route is registered and reachable at the intended tier).

- [ ] **Step 14: Commit**

```bash
git add orchestrator/internal/reporting/attackdata/technique_synonyms.json \
        orchestrator/internal/reporting/attackdata/attackdata.go \
        orchestrator/internal/reporting/attackdata/attackdata_test.go \
        orchestrator/internal/api/handlers.go \
        orchestrator/internal/api/routes.go \
        orchestrator/internal/api/rbac_matrix_test.go
git commit -m "$(cat <<'EOF'
feat(api): add full ATT&CK technique catalog endpoint

New GET /api/techniques/catalog serves every loaded technique (not
just ones with ART/Caldera/BAS coverage) with the richer fields the
Scenario Builder's upcoming Technique Selector needs: description,
platforms, detection, data sources, permissions, sub-technique count,
and a new curated synonym dictionary. Built entirely from the
already-embedded attackdata STIX bundle — no DB changes.
EOF
)"
git push
```

---

### Task 2: Frontend — matching/ranking engine

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (insert new functions before `addStep()`, currently line 10356)
- Verification (not committed): a temporary Node script in the scratchpad directory

**Interfaces:**
- Consumes: nothing from Task 1 directly (this task only handles plain JS objects shaped like `TechniqueCatalogEntry`, decoupled from the actual HTTP call).
- Produces: `techNormalize(s)`, `techTokenize(s)`, `techBuildIndex(catalog)`, `techSearch(index, query)` — Task 3 wires these to the real catalog fetch and the combobox UI. `techBuildIndex` returns index entries shaped `{raw, idNorm, nameNorm, nameTokens, tacticNorms, aliasTokens, descNorm}` where `raw` is the original catalog entry — `techSearch` returns an array of `raw` objects (not index entries), so Task 3 can read `.id`/`.name`/`.tactics`/etc. directly off each result.

- [ ] **Step 1: Add the matching engine functions**

In `orchestrator/wwwroot/index.html`, insert immediately before `function addStep(st) {` (currently line 10356):

```js
/* ── Technique Selector: matching engine ─────────────────────────────────
   Pure functions, no DOM access — kept together so they can be verified
   standalone before being wired into the combobox UI. */

function techNormalize(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function techTokenize(s) {
  return String(s || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function techBuildIndex(catalog) {
  return (catalog || []).map(function(t) {
    return {
      raw: t,
      idNorm: techNormalize(t.id),
      nameNorm: techNormalize(t.name),
      nameTokens: techTokenize(t.name),
      tacticNorms: (t.tactics || []).map(techNormalize),
      aliasTokens: (t.aliases || []).reduce(function(acc, a) {
        return acc.concat(techTokenize(a));
      }, []),
      descNorm: techNormalize(t.description)
    };
  });
}

// techEditDistance computes Levenshtein edit distance. Only ever called on
// short tokens (technique-name words), so the O(m*n) DP table is cheap.
function techEditDistance(a, b) {
  var m = a.length, n = b.length;
  if (Math.abs(m - n) > 2) return 99; // cheap short-circuit for the fuzzy threshold
  var dp = [], i, j;
  for (i = 0; i <= m; i++) dp[i] = [i];
  for (j = 0; j <= n; j++) dp[0][j] = j;
  for (i = 1; i <= m; i++) {
    for (j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// techScore ranks one index entry against a query. Higher is better; 0 means
// no match. Tiers match the design spec's priority order exactly.
function techScore(entry, queryNorm, queryTokens) {
  if (!queryNorm) return 0;
  if (entry.idNorm === queryNorm) return 1000;                              // exact ID
  if (entry.nameNorm === queryNorm) return 900;                             // exact name
  if (entry.idNorm.indexOf(queryNorm) === 0) return 800;                    // ID prefix
  if (entry.idNorm.indexOf(queryNorm) !== -1) return 750;                   // ID substring
  if (entry.nameNorm.indexOf(queryNorm) === 0) return 700;                  // name prefix
  if (queryTokens.length && queryTokens.every(function(qt) {
    return entry.nameTokens.some(function(nt) { return nt.indexOf(qt) === 0 || nt.indexOf(qt) !== -1; });
  })) return 650;                                                           // broken-word name match
  if (entry.tacticNorms.some(function(tn) { return tn === queryNorm || tn.indexOf(queryNorm) === 0; })) return 550; // tactic
  if (queryTokens.length && entry.aliasTokens.length && queryTokens.every(function(qt) {
    return entry.aliasTokens.some(function(at) { return at.indexOf(qt) === 0 || at.indexOf(qt) !== -1; });
  })) return 500;                                                           // synonym
  if (queryTokens.length && queryTokens.every(function(qt) { return entry.descNorm.indexOf(qt) !== -1; })) return 400; // description keyword
  var fuzzyHit = queryTokens.some(function(qt) {
    return entry.nameTokens.some(function(nt) {
      var threshold = qt.length <= 5 ? 1 : 2;
      return Math.abs(nt.length - qt.length) <= threshold && techEditDistance(qt, nt) <= threshold;
    });
  });
  return fuzzyHit ? 200 : 0;                                                // fuzzy fallback
}

// techSearch runs a query against a prebuilt index and returns up to 20
// matching catalog entries (the original `raw` objects), best match first.
function techSearch(index, query) {
  var queryNorm = techNormalize(query);
  var queryTokens = techTokenize(query);
  if (!queryNorm) return [];
  return index
    .map(function(e) { return { entry: e, score: techScore(e, queryNorm, queryTokens) }; })
    .filter(function(s) { return s.score > 0; })
    .sort(function(a, b) { return b.score - a.score || (a.entry.idNorm < b.entry.idNorm ? -1 : 1); })
    .slice(0, 20)
    .map(function(s) { return s.entry.raw; });
}

/* ── /Technique Selector: matching engine ────────────────────────────── */

```

- [ ] **Step 2: Verify the syntax is still valid**

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

- [ ] **Step 3: Write and run the standalone verification script**

Create `C:\Users\ADMINI~1\AppData\Local\Temp\claude\C--Users-Administrator-Downloads-Audspect-Cloud\76be556d-bf6b-4e85-a7ce-d0885849aac3\scratchpad\verify-technique-search.js` (adjust the path to whatever this session's actual scratchpad directory is — do not commit this file, it's a one-off verification tool with no home in this repo's test setup):

```js
const fs = require('fs');
const assert = require('assert');

const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const start = html.indexOf('/* ── Technique Selector: matching engine');
const end = html.indexOf('/* ── /Technique Selector: matching engine');
if (start === -1 || end === -1) throw new Error('matching engine block markers not found');
const src = html.slice(start, end);

const engine = new Function(src + '\nreturn { techNormalize, techTokenize, techBuildIndex, techScore, techSearch };')();
const { techNormalize, techBuildIndex, techSearch } = engine;

const catalog = [
  { id: 'T1055',     name: 'Process Injection',                 tactics: ['defense-evasion', 'privilege-escalation'], description: 'Adversaries may inject code into processes.', aliases: ['dll injection'] },
  { id: 'T1055.012', name: 'Process Hollowing',                 tactics: ['defense-evasion', 'privilege-escalation'], description: 'Process hollowing is a method of executing arbitrary code.' },
  { id: 'T1003',     name: 'OS Credential Dumping',              tactics: ['credential-access'], description: 'Adversaries may attempt to dump credentials, commonly using tools like Mimikatz to access LSASS memory.', aliases: ['mimikatz', 'lsass dump'] },
  { id: 'T1003.001', name: 'LSASS Memory',                       tactics: ['credential-access'], description: 'Adversaries may access LSASS memory to obtain credentials.' },
  { id: 'T1555',     name: 'Credentials from Password Stores',   tactics: ['credential-access'], description: 'Adversaries may search for common password storage locations.' },
  { id: 'T1547',     name: 'Boot or Logon Autostart Execution',  tactics: ['persistence', 'privilege-escalation'], description: 'Adversaries may configure system settings to run a program automatically.', aliases: ['startup', 'autorun'] },
  { id: 'T1547.001', name: 'Registry Run Keys / Startup Folder', tactics: ['persistence', 'privilege-escalation'], description: 'Adding an entry to the Registry run keys or startup folder.' },
  { id: 'T1053',     name: 'Scheduled Task',                     tactics: ['execution', 'persistence'], description: 'Adversaries may abuse task scheduling, e.g. via schtasks.exe.', aliases: ['schtasks'] },
  { id: 'T1059',     name: 'Command and Scripting Interpreter',  tactics: ['execution'], description: 'Adversaries may abuse command and script interpreters.' },
  { id: 'T1059.001', name: 'PowerShell',                         tactics: ['execution'], description: 'Adversaries may abuse PowerShell.' },
  { id: 'T1021',     name: 'Remote Services',                    tactics: ['lateral-movement'], description: 'Adversaries may use valid accounts to log into a remote service.' },
];
const index = techBuildIndex(catalog);
const topId = (results) => results.length ? results[0].id : null;
const ids = (results) => results.map(r => r.id);

// 1. Exact Technique ID
assert.strictEqual(topId(techSearch(index, 'T1055')), 'T1055', 'exact ID T1055 must rank first');

// 2. Partial Technique ID
assert.ok(ids(techSearch(index, 'T10')).includes('T1003'), '"T10" prefix should include T1003');
assert.ok(ids(techSearch(index, '105')).includes('T1055'), '"105" substring should include T1055');

// 3. Technique Name
assert.strictEqual(topId(techSearch(index, 'process')), 'T1055', '"process" should rank Process Injection first (name prefix)');
assert.ok(ids(techSearch(index, 'credential')).includes('T1003') && ids(techSearch(index, 'credential')).includes('T1555'),
  '"credential" should match both credential-named techniques');

// 4. Broken words
assert.ok(ids(techSearch(index, 'cred')).includes('T1003'), '"cred" should find OS Credential Dumping');
assert.ok(ids(techSearch(index, 'dump')).includes('T1003'), '"dump" should find OS Credential Dumping');
assert.ok(ids(techSearch(index, 'sched')).includes('T1053'), '"sched" should find Scheduled Task');

// 5. ATT&CK Tactic
assert.ok(ids(techSearch(index, 'lateral movement')).includes('T1021'), '"lateral movement" should return Remote Services');
assert.ok(ids(techSearch(index, 'credential access')).includes('T1003'), '"credential access" should return Credential Access techniques');

// 6. Keywords
assert.ok(ids(techSearch(index, 'lsass')).includes('T1003'), '"lsass" should find OS Credential Dumping via description');
assert.ok(ids(techSearch(index, 'mimikatz')).includes('T1003'), '"mimikatz" should find OS Credential Dumping');
assert.ok(ids(techSearch(index, 'registry run')).includes('T1547.001'), '"registry run" should find Registry Run Keys / Startup Folder');

// 7. Synonyms
assert.ok(ids(techSearch(index, 'dll injection')).includes('T1055'), '"dll injection" synonym should find Process Injection');
assert.ok(ids(techSearch(index, 'autorun')).includes('T1547'), '"autorun" synonym should find Boot or Logon Autostart Execution');

// 8. Fuzzy
assert.ok(ids(techSearch(index, 'credetial')).includes('T1003'), 'fuzzy "credetial" should still find OS Credential Dumping');
assert.ok(ids(techSearch(index, 'powershel')).includes('T1059.001'), 'fuzzy "powershel" should still find PowerShell');
assert.ok(ids(techSearch(index, 'schedul task')).includes('T1053'), 'fuzzy "schedul task" should still find Scheduled Task');

// Ranking: exact ID always wins even when other techniques also match some lower tier.
assert.strictEqual(topId(techSearch(index, 'T1055')), 'T1055');

// Normalization: case/space/hyphen/punctuation must all collapse identically.
assert.strictEqual(techNormalize('Credential-Dumping'), techNormalize('credential dumping'));
assert.strictEqual(techNormalize('credentialdumping'), techNormalize('Credential Dumping'));

console.log('All technique-search engine assertions passed.');
```

Run: `node <path-to-scratchpad>/verify-technique-search.js`
Expected: `All technique-search engine assertions passed.` with exit code 0. If any assertion fails, fix the engine code from Step 1 (not the test) unless the test itself is wrong, and re-run until green.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(scenario-builder): add technique search matching engine

Pure client-side ranking engine for the upcoming Technique Selector:
exact/prefix/substring ID and name matching, broken-word matching,
tactic search, synonym lookup, description-keyword search, and a
fuzzy typo-tolerant fallback. Verified standalone against the design
spec's match-rule examples before being wired into any UI.
EOF
)"
git push
```

---

### Task 3: Frontend — combobox UI, validation, and legacy datalist cleanup

**Files:**
- Modify: `orchestrator/wwwroot/index.html`:
  - CSS: after `.bld-mode-help` (currently line 205)
  - `addStep()` (currently line 10356) — replace the Technique ID field
  - `collectBuilder()` (currently line 10442-10443) — refine the validation message
  - `openBuilder()` (currently line 10299) — remove the dead datalist pre-warm call
  - `fillBuilder()` (currently ends line 10340) — add the catalog pre-fetch
  - Remove: `<datalist id="att-techniques">` block (currently lines 4138-4165), `_fillDatalistFromCatalog()` (currently line 10182), `_enrichDatalistFromScenarios()` (currently line 10195), `_populateARTDatalist()` (currently line 10214), and their two remaining call sites in `loadCatalogs()` (currently line 6548) and `loadScenarios()` (currently line 6582)

**Interfaces:**
- Consumes: `techBuildIndex`, `techSearch`, `techNormalize` from Task 2; `GET /api/techniques/catalog` from Task 1 (via the existing `apicall()` helper).
- Produces: nothing new consumed elsewhere — this is the terminal UI layer.

- [ ] **Step 1: Add the CSS**

In `orchestrator/wwwroot/index.html`, insert after line 205 (`.bld-mode-help { ... }`):

```css
.st-tech-wrap { position: relative; }
.st-tech-panel {
  display: none; position: absolute; left: 0; top: 100%; width: 100%; z-index: 30;
  background: var(--elevated); border: 1px solid rgba(47,129,247,0.4); border-radius: var(--radius-lg);
  box-shadow: 0 12px 36px rgba(0,0,0,0.45); margin-top: 4px; max-height: 320px; overflow-y: auto;
}
.st-tech-panel.show { display: block; }
.st-tech-row { padding: 0.5rem 0.7rem; cursor: pointer; border-bottom: 1px solid var(--border); }
.st-tech-row:last-child { border-bottom: none; }
.st-tech-row.active, .st-tech-row:hover { background: var(--surface); }
.st-tech-row-id { font-weight: 700; color: var(--accent); font-size: 0.78rem; }
.st-tech-row-name { font-size: 0.8rem; margin-left: 0.4rem; }
.st-tech-row-meta { font-size: 0.68rem; color: var(--muted); margin-top: 0.15rem; }
.st-tech-selected {
  display: flex; align-items: flex-start; justify-content: space-between; gap: 0.5rem;
  padding: 0.5rem 0.7rem; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface);
}
.st-tech-selected.unresolved { border-color: rgba(210,153,34,0.5); }
.st-tech-sel-id { font-weight: 700; color: var(--accent); font-size: 0.8rem; }
.st-tech-sel-name { font-size: 0.82rem; margin-left: 0.4rem; }
.st-tech-sel-actions { font-size: 0.72rem; white-space: nowrap; display: flex; gap: 0.5rem; }
.st-tech-sel-actions a { color: var(--accent); cursor: pointer; text-decoration: none; }
.st-tech-sel-actions a:hover { text-decoration: underline; }
```

- [ ] **Step 2: Add the combobox JS functions**

Insert immediately after the matching engine block added in Task 2 (before `function addStep(st) {`):

```js
/* ── Technique Selector: combobox UI ─────────────────────────────────── */

var techniqueCatalog = null; // null = not yet fetched; [] = fetched but empty/failed
var techniqueIndex = null;
var _techSearchTimer = null;

function ensureTechniqueCatalog(cb) {
  if (techniqueCatalog !== null) { cb(); return; }
  apicall('/api/techniques/catalog').then(function(list) {
    techniqueCatalog = Array.isArray(list) ? list : [];
    techniqueIndex = techBuildIndex(techniqueCatalog);
    cb();
  }).catch(function() {
    techniqueCatalog = [];
    techniqueIndex = [];
    cb();
  });
}

function techFindById(id) {
  if (!techniqueCatalog) return null;
  var norm = techNormalize(id);
  for (var i = 0; i < techniqueCatalog.length; i++) {
    if (techNormalize(techniqueCatalog[i].id) === norm) return techniqueCatalog[i];
  }
  return null;
}

function techFieldHTML(st) {
  var techId = (st && st.techniqueId) || '';
  var hasSelection = !!techId;
  return '<div class="bld-field full st-tech-wrap">' +
      '<label>Technique</label>' +
      '<input class="st-tech" type="hidden" value="' + x(techId) + '">' +
      '<div class="st-tech-selected" style="display:' + (hasSelection ? '' : 'none') + '"></div>' +
      '<input class="st-tech-search" type="text" placeholder="Search ATT&amp;CK technique (ID, name, keyword...)" autocomplete="off" ' +
        'style="display:' + (hasSelection ? 'none' : '') + '" ' +
        'oninput="techOnInput(this)" onkeydown="techOnKeydown(event,this)" onblur="techOnBlur(this)">' +
      '<div class="bld-mode-help" style="margin:0.3rem 0 0">Examples: T1055 &middot; credential dumping &middot; lsass &middot; powershell &middot; registry run</div>' +
      '<div class="st-tech-panel"></div>' +
    '</div>';
}

// techInitField renders the initial selected-card state for a freshly-added
// step row that already has a techniqueId (edit mode). Called right after
// the row is appended to the DOM.
function techInitField(wrap, techId) {
  if (!techId) return;
  techRenderSelected(wrap, techId);
}

function techRenderSelected(wrap, id) {
  var box = wrap.querySelector('.st-tech-selected');
  var search = wrap.querySelector('.st-tech-search');
  var hidden = wrap.querySelector('.st-tech');
  hidden.value = id;
  search.style.display = 'none';
  box.style.display = '';
  var t = techFindById(id);
  if (!t) {
    box.className = 'st-tech-selected unresolved';
    box.innerHTML =
      '<div><span class="st-tech-sel-id">' + x(id) + '</span>' +
        '<span class="tiny muted" style="margin-left:0.4rem">' +
        (techniqueCatalog === null ? 'resolving…' : 'not recognized') + '</span></div>' +
      '<span class="st-tech-sel-actions"><a href="javascript:void(0)" onclick="techChangeSelection(this)">&#10005; change</a></span>';
    return;
  }
  box.className = 'st-tech-selected';
  var tactics = (t.tactics || []).join(', ');
  var subText = t.subCount ? (t.subCount + (t.subCount === 1 ? ' sub-technique' : ' sub-techniques')) : '';
  box.innerHTML =
    '<div><span class="st-tech-sel-id">' + x(t.id) + '</span> <span class="st-tech-sel-name">' + x(t.name) + '</span>' +
      (tactics ? '<div class="st-tech-row-meta">' + x(tactics) + '</div>' : '') +
      (subText ? '<div class="st-tech-row-meta">' + x(subText) + '</div>' : '') +
    '</div>' +
    '<span class="st-tech-sel-actions">' +
      (t.url ? '<a href="' + x(t.url) + '" target="_blank" rel="noopener">View ATT&amp;CK</a> ' : '') +
      '<a href="javascript:void(0)" onclick="techCopyId(this)" data-id="' + x(t.id) + '">Copy ID</a> ' +
      '<a href="javascript:void(0)" onclick="techChangeSelection(this)">&#10005; change</a>' +
    '</span>';
}

function techRefreshAllTechCards() {
  document.querySelectorAll('.st-tech-wrap').forEach(function(wrap) {
    var hidden = wrap.querySelector('.st-tech');
    if (hidden.value) techRenderSelected(wrap, hidden.value);
  });
}

function techChangeSelection(el) {
  var wrap = el.closest('.st-tech-wrap');
  wrap.querySelector('.st-tech').value = '';
  wrap.querySelector('.st-tech-selected').style.display = 'none';
  var search = wrap.querySelector('.st-tech-search');
  search.style.display = '';
  search.value = '';
  search.focus();
}

function techCopyId(el) {
  var id = el.getAttribute('data-id');
  if (navigator.clipboard && id) {
    navigator.clipboard.writeText(id).then(function() { showToast('Copied ' + id, 'ok'); });
  }
}

function techOnInput(input) {
  var wrap = input.closest('.st-tech-wrap');
  var panel = wrap.querySelector('.st-tech-panel');
  if (_techSearchTimer) clearTimeout(_techSearchTimer);
  if (!input.value) { panel.classList.remove('show'); panel.innerHTML = ''; return; }
  _techSearchTimer = setTimeout(function() {
    ensureTechniqueCatalog(function() { techRenderResults(wrap, input.value); });
  }, 150);
}

function techRenderResults(wrap, query) {
  var panel = wrap.querySelector('.st-tech-panel');
  var results = techSearch(techniqueIndex || [], query);
  if (!results.length) {
    panel.innerHTML = '<div class="st-tech-row" style="cursor:default;color:var(--muted)">No matching technique.</div>';
    panel.classList.add('show');
    return;
  }
  panel.innerHTML = results.map(function(t, i) {
    var tactics = (t.tactics || []).join(', ');
    var platforms = (t.platforms || []).join(', ');
    return '<div class="st-tech-row' + (i === 0 ? ' active' : '') + '" data-id="' + x(t.id) + '" onmousedown="techSelectRow(this)">' +
      '<span class="st-tech-row-id">' + x(t.id) + '</span><span class="st-tech-row-name">' + x(t.name) + '</span>' +
      (tactics ? '<div class="st-tech-row-meta">' + x(tactics) + '</div>' : '') +
      (platforms ? '<div class="st-tech-row-meta">' + x(platforms) + '</div>' : '') +
    '</div>';
  }).join('');
  panel.classList.add('show');
}

function techSelectRow(row) {
  var wrap = row.closest('.st-tech-wrap');
  techRenderSelected(wrap, row.getAttribute('data-id'));
  var panel = wrap.querySelector('.st-tech-panel');
  panel.classList.remove('show');
  panel.innerHTML = '';
}

function techOnKeydown(ev, input) {
  var wrap = input.closest('.st-tech-wrap');
  var panel = wrap.querySelector('.st-tech-panel');
  if (!panel.classList.contains('show')) return;
  var rows = panel.querySelectorAll('.st-tech-row[data-id]');
  if (!rows.length) return;
  var activeIdx = -1;
  rows.forEach(function(r, i) { if (r.classList.contains('active')) activeIdx = i; });
  if (ev.key === 'ArrowDown') {
    ev.preventDefault();
    activeIdx = (activeIdx + 1) % rows.length;
    rows.forEach(function(r, i) { r.classList.toggle('active', i === activeIdx); });
  } else if (ev.key === 'ArrowUp') {
    ev.preventDefault();
    activeIdx = (activeIdx - 1 + rows.length) % rows.length;
    rows.forEach(function(r, i) { r.classList.toggle('active', i === activeIdx); });
  } else if (ev.key === 'Enter') {
    ev.preventDefault();
    techSelectRow(activeIdx >= 0 ? rows[activeIdx] : rows[0]);
  } else if (ev.key === 'Escape') {
    panel.classList.remove('show');
    panel.innerHTML = '';
  } else if (ev.key === 'Tab') {
    techSelectRow(rows[0]); // selection completes; default Tab behavior still advances focus
  }
}

function techOnBlur(input) {
  var wrap = input.closest('.st-tech-wrap');
  setTimeout(function() {
    var panel = wrap.querySelector('.st-tech-panel');
    panel.classList.remove('show');
    panel.innerHTML = '';
  }, 150); // delay so a row's onmousedown fires before the panel is cleared
}

/* ── /Technique Selector: combobox UI ────────────────────────────────── */

```

- [ ] **Step 3: Wire the new field into `addStep()`**

In `addStep()` (currently line 10356), replace the Technique ID grid line:

```js
      '<div class="bld-field"><label>Technique ID</label><input class="st-tech" list="att-techniques" type="text" value="' + x(st.techniqueId || '') + '" placeholder="T1003.001"></div>' +
```

with:

```js
      techFieldHTML(st) +
```

After the row is appended to `#bld-steps` and before `renumberSteps();` (the existing `document.getElementById('bld-steps').appendChild(div);` line), add:

```js
  techInitField(div, st.techniqueId);
```

So the tail of `addStep()` reads:

```js
  document.getElementById('bld-steps').appendChild(div);
  techInitField(div, st.techniqueId);
  renumberSteps();
}
```

- [ ] **Step 4: Update `collectBuilder()`'s validation**

Replace (currently lines 10442-10443):

```js
      var tech = r.querySelector('.st-tech').value.trim();
      if (!tech) { err.textContent = 'Step ' + (i + 1) + ': technique ID is required.'; return null; }
```

with:

```js
      var tech = r.querySelector('.st-tech').value.trim();
      if (!tech) {
        var searchVal = (r.querySelector('.st-tech-search').value || '').trim();
        err.textContent = 'Step ' + (i + 1) + ': ' +
          (searchVal ? 'select a technique from the search results.' : 'a technique is required.');
        return null;
      }
```

- [ ] **Step 5: Pre-fetch the catalog when the builder opens**

In `fillBuilder()`, after the steps-population block (currently `if (mode === 'custom' && !steps.children.length) addStep(null);`, line 10337) and before `renderBuilderMode();`, add:

```js
  ensureTechniqueCatalog(techRefreshAllTechCards);
```

This resolves any pre-existing steps' selected-card display (including the "not recognized" legacy state) as soon as the catalog loads, without requiring the user to type anything, and also warms the cache before they open the search box.

- [ ] **Step 6: Remove the dead datalist pre-warm call**

In `openBuilder()` (currently line 10299), remove the line:

```js
  _populateARTDatalist();
```

(`artCatalog` — the underlying fetch/cache this line indirectly warmed — is still populated on-demand by `openBuilderARTPicker()`'s own fallback fetch, so the ART "Browse catalog" picker is unaffected; it just always fetches on first open now instead of sometimes finding a pre-warmed cache from builder-open time. This is a disclosed, accepted minor behavior change, not a regression — the picker was never guaranteed a warm cache before either, since `_populateARTDatalist()` itself only fired if `openBuilder()` had already run.)

- [ ] **Step 7: Remove the datalist markup and its three populate functions**

Remove lines 4138-4165 (the `<!-- common ATT&CK techniques for autocomplete -->` comment through the closing `</datalist>`).

Remove the three now-dead functions: `_fillDatalistFromCatalog()` (currently line 10182), `_enrichDatalistFromScenarios()` (currently line 10195), `_populateARTDatalist()` (currently line 10214) — delete from the start of `_fillDatalistFromCatalog`'s doc comment or opening brace through the end of `_populateARTDatalist`'s closing brace as one contiguous block, since all three are defined back-to-back.

Remove their two remaining call sites:
- In `loadCatalogs()`, delete the line `if (artCatalog.length) _fillDatalistFromCatalog(artCatalog);` (currently line 6548) — the line above it, `artCatalog = Array.isArray(d) ? d : [];`, stays untouched.
- In `loadScenarios()`, delete the line `_enrichDatalistFromScenarios();` (currently line 6582) — the surrounding `scenarios = (data || []).map(...)` assignment and `renderScenarios();` call stay untouched.

- [ ] **Step 8: Verify the syntax is still valid**

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

- [ ] **Step 9: Confirm no remaining references to the removed datalist**

Run: `grep -n "att-techniques\|_fillDatalistFromCatalog\|_enrichDatalistFromScenarios\|_populateARTDatalist" orchestrator/wwwroot/index.html`
Expected: no output (zero matches) — confirms the datalist and all three functions and both call sites are fully gone with nothing left dangling.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(scenario-builder): wire technique search into custom-step editor

Replaces the plain Technique ID text field with the search combobox:
rich result cards, full keyboard navigation (arrows/enter/escape/tab),
a selected-technique summary card with View ATT&CK / Copy ID actions,
non-blocking handling of legacy/unrecognized stored IDs, and
validation that only blocks save when search text was typed but never
resolved to a selection. Removes the now-dead static datalist and its
three populate-only helper functions.
EOF
)"
git push
```

---

### Task 4: Manual end-to-end browser verification

**Files:** none (verification only).

**Interfaces:** consumes the fully-wired feature from Tasks 1-3; produces nothing further.

**Known risk, carried over from the last feature worked in this session:** `wwwroot` is baked into the orchestrator's Docker image (not bind-mounted — confirmed in `packaging/compose/docker-compose.yml`'s own comments), and a bare `go run ./cmd/server` needs a reachable local Postgres plus a license file at `BAS_LICENSE_PATH` (the repo's `audspect-dev.lic` works for this). Local Postgres access was NOT successfully established during the previous plan's execution this session. If the same blocker recurs, stop and ask rather than guessing credentials again, exactly as was done last time — this step is not worth spending an unbounded number of attempts on.

- [ ] **Step 1: Start the stack**

Either rebuild and run the full Docker Compose stack, or `go run ./cmd/server` from `orchestrator/` against a reachable Postgres with `BAS_LICENSE_PATH` set to the repo's `audspect-dev.lic`. If this fails after 2-3 attempts, stop and ask for the right connection details rather than continuing to guess.

- [ ] **Step 2: Catalog fetch**

Open Scenario Builder → New Scenario → Custom steps → Add step, focus the technique search field. Open the browser's Network tab and confirm exactly one `GET /api/techniques/catalog` request fires (not one per keystroke) the first time the field is touched.

- [ ] **Step 3: Ranking spot-checks**

Type each of the following and confirm the result matches the corresponding row (using whatever the *real* embedded ATT&CK data actually names things — the fixture data in Task 2's Node script was illustrative, not a literal promise about MITRE's exact naming, so verify against what the app actually shows, not the fixture strings):

- `T1055` → top result is the real Process Injection entry.
- `T10` then `105` → both return prefix/substring ID matches including something like T1055.
- `process`, then `cred`, then `dump` → broken-word/name matching surfaces plausible results for each.
- `lateral movement` → returns Lateral Movement-tactic techniques.
- `lsass`, `mimikatz`, `schtasks`, `registry run` → each returns a relevant technique via description or synonym matching.
- `credetial`, `powershel`, `schedul task` → each still resolves via the fuzzy fallback.

- [ ] **Step 4: Selection and actions**

Select a result. Confirm the collapsed card shows the correct sub-technique count, "View ATT&CK" opens the real MITRE page for that technique in a new tab, and "Copy ID" copies the bare ID (confirm via pasting somewhere, or a toast confirmation).

- [ ] **Step 5: Validation**

Try to save a step with search text typed but nothing selected — confirm it's blocked with the "select a technique from the search results" message. Clear the search text entirely on an untouched row — confirm it's blocked with "a technique is required."

- [ ] **Step 6: Legacy data**

Open an existing custom scenario that predates this feature (or one saved via the plain field before this change) whose step has a technique ID not in the catalog. Confirm it renders as a "not recognized" card, and the scenario saves successfully if nothing else on that step is changed.

- [ ] **Step 7: Keyboard-only pass**

Type a query, use ArrowDown/ArrowUp to move through results, press Enter to select. Separately: type a query, press Escape, confirm the dropdown closes without selecting. Separately: type a query, press Tab, confirm it both selects the top result and moves focus to the next field.

- [ ] **Step 8: Report results**

If every check passes, report completion. If anything fails, do not attempt more than 2-3 fix-and-retry cycles inline — if it's still broken after that, stop and discuss before continuing (per this codebase's established systematic-debugging discipline for anything that isn't a one-line fix).

---

## Self-Review Notes

- **Spec coverage:** Data layer (§1) → Task 1. Client-side matching (§2) → Task 2, with every one of the spec's 8 example categories (exact ID, partial ID, name, broken words, tactic, keywords, synonyms, fuzzy) turned into a concrete assertion in the Node verification script. UI component (§3) → Task 3, including keyboard nav, selected-state card, legacy-data handling exactly per the earlier-agreed non-blocking design, and validation. Cleanup (§4) → Task 3 Steps 6-7, with every function/call-site named in the spec's cleanup section accounted for. Non-goals are not implemented anywhere in this plan.
- **Placeholder scan:** none — every step has literal, complete code or an exact shell command.
- **Type consistency:** `techBuildIndex`/`techSearch`/`techNormalize` signatures introduced in Task 2 are used identically in Task 3 (`ensureTechniqueCatalog`, `techRenderResults`). `TechniqueCatalogEntry`'s JSON field names (Task 1) match exactly what Task 3's `techFindById`/`techRenderSelected`/`techRenderResults` read (`t.id`, `.name`, `.tactics`, `.platforms`, `.subCount`, `.url`, `.aliases`). The disclosed `Synonyms()`-vs-`Aliases`-field deviation in Task 1 doesn't leak into any other task — `Lookup(id).Aliases` and `GetTechniqueCatalog`'s `entry.Aliases` are the only places aliases are touched, both self-consistent.
- **A second disclosed refinement beyond Task 1's:** the spec said the catalog is "fetched once, lazily, on first entry into Custom-steps mode." Task 3 Step 5 instead pre-fetches on every `fillBuilder()` call (i.e., whenever the builder drawer opens, regardless of mode) so that pre-existing steps' cards resolve without requiring a keystroke. `ensureTechniqueCatalog()`'s cache guard means this is still exactly one fetch per builder session either way — the only change is triggering it slightly earlier for a better edit-mode experience.
