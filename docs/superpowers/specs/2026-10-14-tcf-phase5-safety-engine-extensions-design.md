# TCF Phase 5 — Safety Engine Extensions Design

**Goal:** Extend the factory's safety story to cover *assembled* content — refusing a composed candidate whose individually-safe parts, taken together, create real emergent risk that no individual step's existing classification already caught — while leaving the existing per-step classifier (`safetyVerdict`/`execclass.go`) completely unmodified, so every non-composed content path is byte-for-byte unaffected.

## 1. Current-state evidence (gap analysis, verified against code)

### 1.1 No cross-step reasoning exists anywhere today
`safetyVerdict` (`analyze.go:182-203`) iterates `sc.Steps` independently and keeps the single worst `ExecutionClassification` — pure per-step, stateless, zero notion of ordering, accumulation, or interaction. `scenario.ResolveExecutionClass(techniqueID, actionKey)` (`execclass.go:1088-1108`) is a `map[string]map[string]*ExecutionClassification` lookup against ~389 hand-audited (technique_id, action_key) pairs, with a fail-closed `unclassified` default (`execclass.go:38-42`) for anything not in the catalog. There is no existing concept of combinatorial, interaction, pairwise, or ordering-dependent risk anywhere in this codebase (confirmed by grep across `execclass.go`, `contentregistry/*.go`, `scenario/*.go`, `connector/*.go`) — Phase 5 is additive from zero, not an extension of an existing mechanism.

### 1.2 `Step`'s existing risk fields are free-text, not structured inputs
`Risk`, `BlastRadius`, `Telemetry`, `Detection` (`scenario/types.go:149-153`) are human-readable labels for reporting, never consulted by any resolution logic. No step declares a structured precondition or a structured effect another step could react to. This rules out inferring combination risk from existing per-step metadata without adding something new.

### 1.3 A clean insertion seam already exists, with zero changes needed to `safetyVerdict`
`Compose` (`compose.go:30-92`, TCF Phase 4) already runs `analyzeArtifact` — structural check, then `safetyVerdict` — and refuses before `createVersion` is ever called on either failure. `components []loadedComponent`, the ordered, pre-assembly list, is already in scope at that point. A new check can run right after the existing safety-destructive refusal and before `createVersion`, reusing `safetyVerdict` completely unmodified — preserving Phase 4's "reused unmodified" promise, and critically, never touching the single code path every non-composed content version also runs through.

### 1.4 No schema migration is needed
`content_safety_verdicts` (`content_registry_schema.go:118-128`) has `UNIQUE(content_version_id, classifier, classifier_version)` — a second row with a different `classifier` string is already structurally supported. `content_validations` already allows `level = 'STATIC'` in its CHECK constraint. Neither table needs a migration for this phase.

### 1.5 `VALIDATING` stays correctly dead; this phase doesn't revive it
The new check is synchronous and deterministic, exactly like Phase 4's own refusal checks — it needs no new lifecycle state, no async step. `VALIDATING`'s more plausible eventual consumer is Phase 6's real sandboxed execution (inherently async), not this phase.

### 1.6 An authoritative, already-safe-to-use ATT&CK tactic lookup exists
`internal/reporting/attackdata.Lookup(id string) *Enrichment` (`attackdata.go:258`) returns an `Enrichment` with `Tactics []string` (line 71), backed by an embedded, verified `enterprise-attack 16.1` dataset. Sub-technique resolution is correct and intentional: an exact miss strips everything from the first `.` and retries the parent technique (e.g. `T1003.002` → `T1003`'s tactics if no exact record exists) — `attackdata.go`'s own comment documents this as deliberate. The lookup is pure, in-memory (`sync.Once`-loaded embedded JSON), no DB or network call, and is already safely imported from `internal/contentregistry` today (`intake.go:34` calls the same package's `GroupByID`) — zero import-cycle risk.

This means every component's tactic(s) can be derived automatically from its existing `technique_id` (already stored on every `content_components` row, both internal and external) — no new manually-curated tag, no new required field at promotion or reference time.

## 2. Design

### 2.1 What "unsafe combination" means here

Not "this looks like a real attack chain" — that is this product's entire purpose, and flagging it would refuse legitimate, intentional red-team content and work directly against Phase 4's goal. The target is narrower: **combinations where one part's effect removes a safety net another part's existing (individually non-destructive or potentially-destructive) rating implicitly depended on.** Concretely: a persistence or execution step in this library is engineered to be reversible/self-cleaning partly because it is assumed to be observable; disabling defenses first and then running it removes that assumption without changing its per-step classification. `safetyVerdict` cannot see this, because it only ever looks at one step at a time.

### 2.2 Tactic derivation (no new tagging)

For each `loadedComponent` already available to `Compose`, resolve its tactic set via `attackdata.Lookup(c.techniqueID).Tactics`. Union every component's tactics across the whole candidate into one set. An unresolvable `technique_id` (lookup returns nil) is a fail-closed refusal of the entire composition — mirroring `execclass.go`'s own `unclassified = destructive` default — even if no flagged pair would otherwise apply; the composition cannot be assessed, so it is not allowed through.

### 2.3 The rule table: a small, hardcoded, version-controlled catalog

A new Go value, in the same spirit as `execclass.go`'s own catalog — code-reviewed via git history, never a runtime-editable database table. Each entry names an unordered pair of ATT&CK tactics and a reason string for audit/error messages. Lookup canonicalizes the two tactic strings (e.g. sorted) before matching, so a composed candidate's tactic union is checked against each catalog entry's pair without caring which component contributed which tactic or in what order.

**Starter catalog (v1, conservative — exact tactic string literals to be pinned against `attackdata`'s real output at implementation time, not guessed here):**

1. **Defense Evasion + Persistence** — defenses disabled, then something persists; the persistence mechanism's reversibility assumption (it would normally be caught if something goes wrong) no longer holds.
2. **Defense Evasion + Execution** — defenses disabled, then a payload runs; same reasoning.

Explicitly not included in v1, left as documented future-expansion candidates once the mechanism is proven: Defense Evasion + Exfiltration, Defense Evasion + Lateral Movement, Privilege Escalation + Persistence. Also explicitly not included: any pairing involving Credential Access or Impact tactics, since the techniques most commonly carrying those tactics in this catalog are typically already individually rated `ClassDestructive` by `execclass.go` — flagging them again at the combination level would be redundant with a check that already exists, not new coverage.

### 2.4 Where this runs

Inside `Compose` (`compose.go`), immediately after the existing `a.safety.verdict == ClassDestructive` refusal and before `createVersion` is called — refusing before anything is created, same as every other Phase 4 refusal check. On refusal, no `content_versions` row is written, matching the OS-intersection and per-step-safety refusal paths exactly; nothing needs to be recorded for a refused composition, since nothing was created.

### 2.5 Recording a successful check

A composed candidate that passes gets a second `content_safety_verdicts` row (`classifier = "combinatorial"`, `classifier_version` following the same versioning convention `safetyClassifierVersion` already uses, `verdict = "PASS"`, `detail` jsonb carrying the resolved tactic union and which catalog pairs were checked against it) — giving an auditor visibility that this check actually ran, not just the absence of a refusal. This write happens in `Compose`'s own post-`createVersion` step, alongside the existing `content_version_components` provenance writes — inheriting that same, already-documented (Phase 4 final review, Minor #2-adjacent) non-atomicity profile rather than introducing a new one. Given this write has no caller-supplied duplicate-key risk (it's exactly one row per successfully composed candidate, not N rows keyed on client input), its failure-mode risk is materially smaller than the provenance-write gap Phase 4 fixed.

## 3. Acceptance criteria

1. A composed candidate whose components' combined ATT&CK tactic set contains both tactics of a flagged pair is refused before any `content_versions` row is created.
2. A composed candidate whose components' tactics include only one half of any flagged pair succeeds — proving this is not an over-broad "contains attack-shaped content" filter.
3. A component whose `technique_id` does not resolve via `attackdata.Lookup` causes the whole composition to be refused, even when no flagged pair would otherwise apply.
4. A successfully composed candidate has exactly one `content_safety_verdicts` row with `classifier = "combinatorial"`, distinct from and in addition to the existing `execclass` structural/safety verdict row `createVersion` already writes.
5. `scenario.ResolveExecutionClass`, `execclass.go`'s catalog, and `safetyVerdict` are unmodified by this phase's diff — every non-composed content path's behavior is provably unaffected.
6. The tactic-pair catalog is a hardcoded Go value, not a database table and not editable through any API this phase adds.

## 4. Out of scope (this phase)

- **Order/sequence sensitivity.** The check is presence-based (is both tactics anywhere in the union), not sequence-aware. Deliberate: presence-based is simpler, YAGNI-justified, and more robust against an author trivially reordering steps to dodge an order-sensitive check.
- **Explicit N-ary (3+) tactic combination rules.** A 3-step chain matching the spec's own example is already caught transitively as long as any pairwise subset of its tactics is flagged — no dedicated 3+-way rule mechanism is needed for v1.
- **A runtime-editable UI or API for the rule table.** Stays a hardcoded, code-reviewed Go value, consistent with `execclass.go`'s own precedent for safety-classification data.
- **Expanding the starter rule set beyond the 2 confirmed pairs.** The 3 named candidates (Defense Evasion+Exfiltration, Defense Evasion+Lateral Movement, Privilege Escalation+Persistence) are explicitly deferred to a future addition once this mechanism is proven in practice, not enumerated exhaustively now.
- **Retrofitting this check onto single-source (non-composed) content.** Matches the roadmap's own framing ("extend the classifier to reason about ASSEMBLED content") and Phase 4's existing trust assumption that a single-source scenario is presumptively author-vetted as one coherent unit (the same assumption promotion eligibility already relies on).
- **Any lab/sandbox empirical validation of whether a flagged-or-passed candidate's risk assessment is actually correct.** That is Phase 6's job (automated validation lab), not this phase's.

## 5. Review Focus

- Composing a Defense-Evasion-tactic component with a Persistence-tactic component (the spec's own motivating example) — confirm refusal, before any row is created.
- Composing a Defense-Evasion-tactic component with a Discovery-tactic component (an unflagged pair) — confirm success, proving the check isn't an over-broad attack-shape filter.
- A component whose `technique_id` doesn't resolve via `attackdata.Lookup` — confirm the whole composition is refused (fail-closed default), even when no catalog pair would otherwise fire.
- A successful composition — confirm exactly one `content_safety_verdicts` row with `classifier = "combinatorial"` exists, separate from the existing `execclass` row, and that its `detail` is traceable to the actual resolved tactic union.
- `execclass.go`/`analyze.go`'s `safetyVerdict` — confirm the diff leaves both byte-for-byte unmodified, as a regression check protecting every non-composed content path.
