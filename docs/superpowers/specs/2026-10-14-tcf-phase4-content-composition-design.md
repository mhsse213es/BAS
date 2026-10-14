# TCF Phase 4 — Content Reuse and Composition Design

**Goal:** Let the factory assemble a new content candidate from existing, proven pieces — ART/Caldera technique references and steps lifted from Audspect's own previously-published scenarios — instead of only generating single-source content from scratch, while keeping every composed candidate's provenance, compatibility, and safety story as honest as the rest of this codebase already insists on.

## 1. Current-state evidence (gap analysis, verified against code)

### 1.1 No existing component-reuse mechanism
Every provenance primitive in this codebase records *which intel justified this content*, never *which other content this reuses*. `contentregistry.RegisterGenerated`'s `generation jsonb` column and its `snapshotSources` machinery (`generated.go:20-128`) snapshot `threat_actor_sources`/`intelligence_entity_sources` rows — actor/campaign/malware/tool evidence, not component lineage. `content_version_threats.relationship_kind CHECK IN ('generated_for','emulates')` (`threat_identity_schema.go:214-219`) is a content-version↔threat link, not a content-version↔content-version link. There is no existing way to record "version X was assembled from version Y." Phase 4 builds this from nothing.

### 1.2 "Component" has no existing database-level meaning
`Step` (`types.go:122-184`) is the natural composition unit — rich enough (technique, framework, command/ability/test-index, safety metadata) to stand alone — but it has no persisted, addressable identity today; it exists only embedded inside one scenario's `artifact_bytes` YAML blob. `execclass.go`'s `ExecutionClass`/`ResolveExecutionClass` is a static, hardcoded, in-memory classification lookup, not a component registry. `ComponentVersions{ART, Caldera}` (`builder.go:84-87`) is a false lead — a library-release-version string pair used only for post-dispatch drift detection, unrelated to composition.

### 1.3 The generator does no assembly today, not even dynamic
`buildYAML` (`generator.go:386-459`) emits `art_techniques: [...]` — a dynamic-mode scenario (per the execution-mode priority list, `types.go:195-202`) resolved against whatever the ART library contains at *dispatch* time. The generator never selects or pins specific step content at generation time. Phase 4 is additive from zero, not a reuse layer bolted onto an existing assembly step.

### 1.4 `variant.go` is confirmed unrelated
`variant.go:17-18`'s own doc comment: the Variant Engine "multiplies the base ART atomic test library at dispatch time rather than at seed time." Pure runtime encoding/privilege/exec-context transform of one base ART test. Never touches `content_versions`. Not composition in any sense.

### 1.5 Safety classification already aggregates per-step
`safetyVerdict` (`analyze.go:178-203`) iterates `sc.Steps` and takes the worst static step's classification (`classRank` comparison per step). This is already per-step aggregation, not scenario-level, contrary to the roadmap's framing. A composed candidate's `Steps` list gets a correct worst-case verdict through this existing function unchanged — no new code needed for that part. What it does *not* do: detect combinatorial/interaction risk, where two individually-safe steps' combination isn't (§4, out of scope this phase).

### 1.6 Phase 7 stays correctly deferred
Composed output is `OriginLocal` by construction (this project's origin/trust model: LOCAL can never acquire VENDOR_SIGNED), identical to today's generator output — no path through composition ever needs `AttachVendorSignature`. The compatibility/safety-refusal check this phase needs is synchronous and deterministic (§3.3), not the kind of async/human-reviewable work `VALIDATING` was built for — so this phase does not revive it either. Phase 7's two dead-code gaps remain correctly out of scope.

### 1.7 Compatibility signals exist only at whole-scenario granularity
`supported_os text[]` lives on `content_versions` (`content_registry_schema.go:71`) and `Scenario.SupportedOS` (`types.go:257-261`), never per-step. Scenarios are single-mode today — exactly one of the seven execution modes applies per scenario, never mixed. A composed candidate resolves this cleanly by always using the existing, fully-general `steps: [...]` mode (§3.2) regardless of which component kind contributed each step.

## 2. Design

### 2.1 Two component kinds, one registry table

New table `content_components` — `id`, `kind` (`'internal'` | `'external'`), `technique_id`, `title`, `supported_os text[]`, `promoted_by`, `promoted_at`, plus kind-specific columns:

- **Internal** (`kind = 'internal'`): `origin_content_version_id` (FK to `content_versions`, provenance pointer) + `step_snapshot jsonb` (an immutable copy of the promoted `Step`, taken at promotion time — content_versions are already immutable per Phase 1's acceptance test, so the snapshot and the live origin always agree; storing it directly avoids re-parsing `artifact_bytes` YAML on every composition). `supported_os` is carried forward from the origin scenario's own `supported_os` — the step ran successfully in that context, so that's the proven compatibility envelope.
- **External** (`kind = 'external'`): `framework` (`'art'` | `'caldera'`), `ability_id`/`test_index` (whichever the framework uses), `library_version` (the ART/Caldera library version active at promotion/reference time, mirroring the existing `ComponentVersions` drift-detection pattern — not reusing that struct, since its purpose there is different, but reusing its idea).

### 2.2 Promotion: explicit, not automatic

A step becomes an internal component only through an explicit promotion action — never implicit extraction of every step from every published scenario. Reasoning: not every step is written with standalone reuse in mind (some assume prior-step state or scenario-specific ordering), and automatic extraction would flood the catalog with steps nobody vetted for reuse while erasing the "who decided this is reusable" provenance question.

**Eligibility bar for promotion: the same `Executable()` gate everything else in this codebase already uses** (`PUBLISHED_LOCAL`/`PUBLISHED`) — not a new, stricter "composition-ready" tier. Phase 10 just established this project's honesty rule: validation today is structural-only, and inventing an unenforceable second claim would repeat exactly the kind of overclaim Phase 7 and Phase 10 have been closing off. If a scenario is good enough to run today, its steps are good enough to promote; the promotion act itself is the judgment call, not a new validation tier.

New endpoint: `POST /api/content-registry/components/promote` — takes a `content_version_id` + step index, validates the version is currently executable, and creates one `content_components` row. External components are registered via `POST /api/content-registry/components/reference` — a separate, simpler endpoint that just records the framework reference (no origin content_version to validate against — ART/Caldera's own catalogs are the source of truth for whether the reference is real). Both gated by a new `CanManageComponents` permission at the same Admin tier `CanTransitionContent` already uses — a new permission, not a reuse of that one, since component management and lifecycle transition are different capabilities even though they share a tier.

### 2.3 Composition: a new content_version, assembled, gated synchronously

New endpoint: `POST /api/content-registry/compose` (same new `CanManageComponents` permission) — takes an ordered list of `content_components` IDs plus a target threat (for the usual `content_version_threats` link). The handler:

1. Resolves each component into a concrete `Step`: internal components use their stored `step_snapshot` directly; external components get a freshly-built `Step` with `Framework`/`TechniqueID`/`AbilityID`/`TestIndex` **pinned at composition time** (not left dynamic) — this is what makes a composed candidate always valid under the existing `steps: [...]` execution mode (§1.7), with no new execution-mode handling needed anywhere in the dispatch path.
2. Runs the refusal check (§2.4) **before** any `content_versions` row is written — "refused before reaching the registry" per the roadmap's exit criteria means refused before creation, not blocked later at a publish step.
3. On success, calls `createVersion` with the assembled `Steps` list, same as any other content creation path — the resulting row is an ordinary `content_versions` row (`origin = 'LOCAL'`), created as `DRAFT`, going through the same `DRAFT → PUBLISHED_LOCAL` transition governance as everything else. No new lifecycle state, no special-casing anywhere downstream (Phase 10's threat-coverage view, `GET /api/scenarios`, the dispatch gate — all see a composed candidate exactly like any other local content_version).
4. Records provenance in a new join table `content_version_components` (`content_version_id`, `component_id`, `step_order`) — the same shape as `content_version_threats`, giving "which components built this" a trivial, always-one-level-deep query (§2.5).

### 2.4 The refusal check (synchronous, inside creation — not a new lifecycle state)

Two checks, both deterministic:

- **Compatibility**: intersect every chosen component's `supported_os`. If the intersection is empty, refuse — the components share no platform they're all proven to run on.
- **Safety**: build the assembled `Steps` list and run it through the existing `safetyVerdict` (`analyze.go:178-203`) unchanged — the worst-step-wins aggregation already works correctly over any step list, composed or not. If the result fails the same closed-by-default rule generation already enforces, refuse.

Both checks run inside the same synchronous STRUCTURAL-check slot `createVersion` already has — not a new async stage, not a revived `VALIDATING`.

### 2.5 Provenance depth: one level, by design

A component can only be promoted from a **single-source, non-composed** published content_version — a composed candidate's own steps can never themselves be promoted as components for a further composition. This is a direct consequence of §4's scoping decision (combinatorial/interaction risk is out of scope for v1): allowing composition-of-compositions would compound that same blind spot with every new generation, since a "promoted" step from an already-composed scenario would carry an unverified interaction risk one layer removed from anything that's actually run as a single coherent, individually-authored scenario. This keeps the provenance query trivial (always exactly: composed candidate → its direct components → each component's one origin scenario, never a chain) and keeps the safety story honest (every component traces back to a step that ran as part of one coherent scenario, not an assembled one).

## 3. Acceptance criteria

1. An internal component can only be promoted from a `content_version` that currently passes the existing `Executable()` gate — promotion from a DRAFT or non-executable version is refused.
2. A `content_components` row of `kind = 'internal'` stores an immutable `step_snapshot` taken at promotion time — later changes to any other content (the origin scenario cannot itself change, since content_versions are immutable, but this is still verified directly) never alter an already-promoted component.
3. Composing from components whose `supported_os` sets share no common platform is refused before any `content_versions` row is created — no DRAFT row, no partial state.
4. Composing from components whose assembled `Steps` list fails the existing `safetyVerdict` worst-step-wins check is refused the same way (before creation), using the unmodified existing function — no new safety-scoring logic duplicated.
5. A successfully composed candidate is an ordinary `content_versions` row: `origin = 'LOCAL'`, created `DRAFT`, visible to every existing surface (dispatch gate, `GET /api/scenarios`, Phase 10's threat-coverage view) exactly like single-source generated content, with no special-casing required in any of them.
6. `content_version_components` records every component a composed candidate was built from; a provenance query for any composed candidate returns every source component in one join, never a multi-hop chain.
7. A `content_components` row can never be created from a composed candidate's own content_version — attempting to promote a step from a composed candidate is refused.
8. External components reference the ART/Caldera library version active at promotion/reference time; composing with one pins that exact reference into the new candidate's `Steps` (not left dynamic), consistent with how internal components are already handled.

## 4. Out of scope (this phase)

- **Combinatorial/interaction safety risk** — two individually-safe components whose *combination* isn't (e.g., ordering-dependent persistence) is not detected. The v1 safety bar is "worst single step wins," already free via the unmodified existing `safetyVerdict`. This is a known, documented limitation, not a silent gap — flagged explicitly rather than attempted with a bespoke interaction-risk model on the first pass.
- **Transitive/multi-level composition** — composing from an already-composed candidate's steps. See §2.5; a direct consequence of scoping out combinatorial risk.
- **Reviving `VALIDATING`** or any new intermediate lifecycle state — the refusal check is synchronous and belongs in the existing STRUCTURAL-check slot (§2.4).
- **Phase 5's safety-engine extension** (reasoning about assembled content beyond worst-step-wins) — this phase deliberately ships without it, per the combinatorial-risk scoping above; Phase 5 remains the place to revisit if/when combinatorial risk needs real coverage.
- **Phase 6's validation lab** — promotion eligibility uses the existing structural-only `Executable()` bar, not anything Phase 6 would eventually provide; no dependency on Phase 6 existing.
- **Automatic/implicit component extraction** — every internal component requires an explicit promotion action (§2.2).
- **A UI for browsing/selecting components** — this spec covers the API and data model only; a composition UI is a natural but separate follow-up.

## 5. Review Focus

- Promoting a step from a `DRAFT` or otherwise non-executable content_version — confirm it's refused, not silently allowed through a looser check than the stated `Executable()` bar.
- Composing with components whose `supported_os` sets have zero overlap — confirm refusal happens before any `content_versions` row is written (not after, not as a later publish-time check).
- Composing with a mix of internal and external components whose assembled `Steps` list contains a step that fails `safetyVerdict`'s worst-step-wins check — confirm refusal, and confirm the existing function is reused unmodified rather than a parallel safety check being invented.
- Attempting to promote a component from a composed candidate's own content_version — confirm this is refused, not silently permitted (the one-level provenance guarantee depends entirely on this holding).
- A composed candidate's downstream visibility — confirm it appears correctly in at least one existing consumer (e.g., Phase 10's `GET /api/threats/exposure`, or `GET /api/scenarios`'s `Summary`) with no special-casing needed, proving §2.3's "ordinary content_versions row" claim is actually true in practice, not just in intent.
