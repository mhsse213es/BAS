# Technique Selector Design

**Goal:** Replace the plain "Technique ID" text input in the Scenario Builder's custom-step editor with a searchable autocomplete combobox over the full ATT&CK technique catalog — exact/prefix/substring ID matching, name and broken-word matching, tactic search, description-keyword search, a synonym dictionary, and fuzzy typo tolerance, ranked and rendered as rich result cards with full keyboard navigation.

## Background

The custom-step editor's `st-tech` input (`orchestrator/wwwroot/index.html:10356`, inside `addStep()`) is a plain text field backed by `<datalist id="att-techniques">` (`:4139`) containing ~14 hardcoded common techniques, optionally topped up at runtime from the ART-only catalog. It has no ranking, no fuzzy matching, no rich metadata, and no validation — any string is accepted as a technique ID.

This is the **only** place in the app that references `att-techniques` (confirmed by grep across `index.html`) — a separate, unrelated "Browse catalog" picker modal exists for bulk ART/Caldera technique selection elsewhere (`renderPickerList()`, plain substring filter, checkbox multi-select), which this spec does not touch or extend.

## Data foundation (already exists)

`orchestrator/internal/reporting/attackdata` (`attackdata.go`) embeds the full MITRE ATT&CK Enterprise STIX bundle offline:

- `All() []TechniqueRef` — every technique (including sub-techniques), ID-sorted, with ID/Name/Tactics.
- `Lookup(id string) *Enrichment` — per-technique Description, Platforms, PermissionsRequired, DataSources, Detection, URL (the real MITRE ATT&CK page for that technique), plus threat-intel fields not needed here (Groups, Software, Mitigations, CVEs, etc.).

This already covers every field the selector needs except aliases/synonyms, which don't exist anywhere in the codebase and require new curated data (see below).

## 1. Backend: new catalog endpoint

**New file:** `orchestrator/internal/reporting/attackdata/technique_synonyms.json` — a curated synonym dictionary, following the exact same embed pattern as the existing `curated_overlay.json` (analyst-maintained, not MITRE-authoritative). Seeded from the examples in the original feature brief:

```json
{
  "T1055":  ["dll injection"],
  "T1547":  ["startup", "autorun"],
  "T1003":  ["mimikatz", "lsass dump"],
  "T1053":  ["schtasks"]
}
```

**New function in `attackdata.go`:** `Synonyms(id string) []string` — embeds and looks up `technique_synonyms.json` the same way `Lookup()` does for `curated_overlay.json` (normalize the ID, direct map lookup, no sub-technique fallback since aliases are meant to be specific).

**New handler:** `GetTechniqueCatalog` in `orchestrator/internal/api/handlers.go` (near `GetUnifiedTechniques`, `:3140`). For every entry in `attackdata.All()`, look up its `Enrichment` via `Lookup()` and its aliases via `Synonyms()`, and compute `subCount` (count of other entries whose ID has this one as a dot-prefix, e.g. `T1055` counts `T1055.001`, `T1055.012`, ...). Emit one lean JSON object per technique:

```json
{
  "id": "T1055", "name": "Process Injection",
  "tactics": ["defense-evasion", "privilege-escalation"],
  "platforms": ["Windows", "Linux", "macOS"],
  "description": "...", "detection": "...",
  "dataSources": ["Process: OS API Execution", "..."],
  "permissions": ["User", "Administrator"],
  "subCount": 12,
  "aliases": ["dll injection"],
  "url": "https://attack.mitre.org/techniques/T1055/"
}
```

**New route:** `orchestrator/internal/api/routes.go`, alongside the existing technique-catalog routes (`:179-181`):

```go
r.Get("/api/techniques/catalog", h.GetTechniqueCatalog)
```

Same trust tier as `/api/art/techniques` and `/api/techniques/unified` (Viewer+, read-only, no DB access — pure in-memory embedded data). Needs a corresponding entry in `orchestrator/internal/api/rbac_matrix_test.go` (pattern at `:79-81`).

No database schema changes. No changes to `attackdata.Enrichment` or any existing function's behavior — purely additive.

## 2. Frontend: client-side index and matching

The catalog is fetched once, lazily, on first entry into Custom-steps mode (mirroring the existing `_populateARTDatalist()` lazy-cache pattern), and cached in a module-level `techniqueCatalog` array. From it, build a precomputed search index: for each technique, a normalized ID (lowercased), a normalized name with all whitespace/hyphens/punctuation stripped (`normalize()` — satisfies "ignore case/spaces/hyphens/punctuation": `credential dumping`, `Credential-Dumping`, and `credentialdumping` all collapse to the same string), a tokenized word list from the name (split on non-alphanumeric), and normalized tactic/description/alias text.

Search runs on every keystroke after a 150ms debounce, starting at 1 character. Each technique is scored against the tokenized query in one linear pass (at ~600-900 techniques total, this comfortably clears a <50ms budget with no indexing structure beyond the precomputed strings above). Score tiers, highest first — ties broken by technique ID ascending:

1. **Exact ID** — `normalize(query) === technique.idNorm`. Guarantees `T1055` always ranks `T1055 — Process Injection` first regardless of what else matches.
2. **Exact name** — `normalize(query) === technique.nameNorm`.
3. **ID prefix** — `technique.idNorm.startsWith(normalize(query))` (`T10` → T1003, T1021, T1053, T1055, T1059...).
4. **ID substring** — `technique.idNorm.includes(normalize(query))` (`105` → T1055, T1053...).
5. **Name prefix** — `technique.nameNorm.startsWith(normalize(query))` (`process` → Process Injection).
6. **Broken-word name match** — every token in the tokenized query is a prefix or substring of *some* word in `technique.nameTokens`, order-independent (`cred` → Credential Dumping; `dump` → Credential Dumping, LSASS Memory Dump).
7. **Tactic match** — query, normalized, equals or prefixes a known ATT&CK tactic name (`lateral movement`, `credential access`, `execution`); matches every technique carrying that tactic.
8. **Synonym match** — every query token is a prefix/substring of some token in `technique.aliasTokens`.
9. **Description keyword** — every query token appears as a substring somewhere in `technique.descNorm`.
10. **Fuzzy fallback** — only evaluated if a technique matched none of tiers 1-9. Simple edit-distance check between the (whitespace-stripped) query and each name token; threshold scales with word length (1 edit for words ≤5 chars, 2 for longer) — catches `credetial`, `powershel`, `schedul task`.

Results are capped at ~20 rows for render performance and UX (a dropdown shouldn't show hundreds of matches), sorted by score tier then ID.

## 3. Frontend: UI component

Replace `<input class="st-tech" list="att-techniques" ...>` (`:10375` in the current `addStep()`) with:

- A visible `<input class="st-tech-search">` (placeholder: `Search ATT&CK technique (ID, name, keyword...)`, with the example list from the brief shown as static help text beneath it).
- A hidden `<input class="st-tech" type="hidden">` — the field `collectBuilder()` already reads (`:10411` onward), so no changes needed on the read side beyond the validation check below.
- An absolutely-positioned dropdown `<div class="st-tech-results">`, populated with one card per result: ID (accent-colored, matching the existing `.bld-field` label convention), name, a tactics line, a platforms line — built using the same badge/card visual conventions already used by `renderPickerList()`, no new styling system introduced.

**Keyboard navigation:** ArrowDown/ArrowUp move a `.active` class between rows (wraps at both ends); Enter selects the active row (or the top result if none is active yet); Escape closes the dropdown without selecting; Tab selects the top result and advances focus, so keyboard-only flows never get stuck.

**Selected state:** once a technique is chosen, the input area collapses into a compact card — ID, name, tactics, platforms, `subCount` ("12 sub-techniques") — with "View ATT&CK" (opens `technique.url`, real MITRE data, not a generated link) and "Copy ID" actions, plus a "✕ change" control that reopens search. Typing while a technique is selected clears the hidden field until a new one is explicitly chosen, so a stale valid ID never silently lingers behind new unresolved query text.

**Legacy/unresolved data:** when editing an existing custom scenario whose stored `techniqueId` isn't found in the catalog (typo, deprecated ID, or simply predates this feature), the field renders in the selected-card layout with a "not recognized" badge instead of blank/blocking. The stored value round-trips untouched on save unless the user actively clears or changes it.

**Validation:** `collectBuilder()`'s custom-steps branch (`:10432` onward) gains one check per row — block save only when the hidden `st-tech` is empty *and* the visible search text is non-empty/unresolved (i.e., the user typed something but never selected a result). A row left completely untouched still fails the existing "technique ID is required" check it already has today; a row showing a legacy unresolved ID is not blocked unless actively edited into a new invalid state.

**Catalog fetch failure:** if `GET /api/techniques/catalog` fails, the combobox shows "Technique search unavailable — enter an ID manually" and falls back to a plain text input for the hidden field, rather than blocking scenario authoring entirely.

## 4. Cleanup (in-scope, mechanical consequence of this change)

Once `att-techniques` has no consumer, three now-dead functions and the datalist markup are removed as part of this change (not a separate refactor):

- `<datalist id="att-techniques">` and its ~14 static `<option>` entries (`:4139`).
- `_fillDatalistFromCatalog()` (`:10182`), `_enrichDatalistFromScenarios()` (`:10195`), `_populateARTDatalist()` (`:10214`) — all three exist solely to populate that datalist. Call sites checked: `:6548`, `:6582`, and within `openBuilderARTPicker()` (`:10226`) and `openBuilder()` — all confirmed to serve only the datalist being removed.
- `artCatalog` itself (the underlying `/api/art/techniques` fetch/cache variable) is **not** removed — it's still used by the separate ART "Browse catalog" picker.

## Non-goals

All explicitly deferred in the original feature brief's own "Future Enhancements" list — none are touched by this spec: multi-select technique picking per step, recent/favorite techniques, filtering by tactic/platform/data-source, ART/Caldera/local-executor coverage-availability badges on results, and a description/mitigation preview side panel.

## Testing

No automated frontend test framework exists for `wwwroot/index.html` (established pattern in this codebase). Backend: `GetTechniqueCatalog` and `attackdata.Synonyms()` get standard Go unit tests (table-driven, following the existing `attackdata_test.go` pattern) covering catalog shape, `subCount` computation, and synonym lookup/fallback. Frontend verification is manual/browser-based:

1. Open Custom-steps mode, focus the technique field — confirm the catalog fetches once (check network tab: one `GET /api/techniques/catalog` call, not per-keystroke).
2. Type `T1055` — confirm it's the top result with the correct name/tactics/platforms card.
3. Type `T10` then `105` — confirm both return the prefix and substring ID matches described above.
4. Type `process`, then `cred`, then `dump` — confirm broken-word/substring name matching per the spec's examples.
5. Type `lateral movement` — confirm it returns Lateral Movement-tactic techniques.
6. Type `lsass`, `mimikatz`, `schtasks`, `registry run` — confirm description-keyword and synonym matches per the spec's examples.
7. Type `credetial`, `powershel`, `schedul task` — confirm fuzzy fallback still resolves them.
8. Select a result, confirm the collapsed card shows correct sub-technique count and both actions work (View ATT&CK opens the right MITRE page, Copy ID copies the bare ID).
9. Try to save a step with unresolved search text and no selection — confirm it's blocked with a clear error.
10. Open an existing custom scenario with a legacy/unrecognized technique ID — confirm it renders as a "not recognized" card and the scenario still saves untouched if nothing else on that step changes.
11. Keyboard-only pass: type a query, ArrowDown/ArrowUp through results, Enter to select; separately, Escape to close without selecting; separately, Tab to select-and-advance.
