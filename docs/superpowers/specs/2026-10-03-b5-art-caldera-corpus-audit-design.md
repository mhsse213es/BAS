# B5 ART/Caldera Corpus Classification Audit — Design

## Context

[[B5 — Destructive-Action Guardrail]] Phase 1 shipped a classification
catalog (`orchestrator/internal/scenario/execclass.go`) that resolves every
scenario step's `(technique_id, action_key)` pair to an `ExecutionClass`
(`non_destructive` / `potentially_destructive` / `destructive`), fail-closed
to `destructive` for any pair the catalog doesn't recognize. The
hand-authored scenario corpus (389 steps) is now 100% classified (commit
`e8371b57`). Two other content sources that feed the same dispatch path were
explicitly deferred as out of scope for Phase 1, because they were believed
to need live infrastructure no prior session had:

- The **ART atomic corpus**, loaded at orchestrator startup from the real
  `atomic-red-team` GitHub repo (fetched at Docker build time into
  `/art-atomics`, parsed into the `art_atomic_tests` Postgres table by
  `orchestrator/internal/scenario/content_import.go`).
- The **Caldera ability library** (~2,200 abilities), fetched live from a
  running Caldera instance by `orchestrator/internal/scenario/caldera_store.go`.

Neither `art.go` nor `caldera_store.go` ever sets `ActionKey` on the
`ScenarioStep`s they build — it is always empty. `ResolveExecutionClass`
treats an empty `ActionKey` as `"enumerate"`, so today every ART/Caldera
step for a given technique collapses onto one lookup
`(technique_id, "enumerate")`, which is either accidentally absent (fails
closed to `destructive`, the current universal outcome) or — if the
technique happens to coincide with a hand-authored entry — wrongly shared
across atomics/abilities with genuinely different destructiveness under the
same technique (e.g. T1490 has both a safe-enumerate atomic and a
genuinely destructive one).

**Re-scoping finding (2026-10-03):** the "needs live infra" blocker no
longer holds. `packaging/compose/docker-compose.yml` already stands up
Postgres + Caldera + the orchestrator together, locally, with no external
or staging dependency. `bas-caldera` images are already cached locally from
prior sessions. ART's source YAML is public and already vendored into the
orchestrator's own Docker build. This spec treats the audit as locally
runnable now, not blocked on staging access.

## Goals

1. Give every ART atomic and Caldera ability a real `(technique_id,
   action_key)` classification, replacing today's universal fail-closed
   default for these two sources.
2. Classify per atomic/ability, not per technique — a technique with mixed
   safe/destructive content must not collapse into one shared bucket.
3. Make the audit **reproducible**: re-runnable against an updated corpus,
   not a one-time hand edit.
4. Make the audit **honest about confidence**: a pattern scanner's silence
   is not proof of safety. Every item either carries a positive reason to
   be `non_destructive`, or is explicitly `unresolved` and blocks the gate
   — it is never silently defaulted to safe.
5. Keep reachability (would this item ever actually be dispatched) and
   destructiveness (is it dangerous if it were) as separate, both-recorded
   attributes, not one proxy for the other.

## Non-goals

- Changing `ResolveExecutionClass`, `AttachExecutionClassifications`, or
  the 3-tier `ExecutionClass` model itself. This spec only adds data and a
  per-item identifier to two existing sources; the resolution mechanism is
  unchanged.
- Re-litigating the hand-authored catalog. Existing entries are never
  overwritten by this work.
- A grant/override UI or any "Phase 2" mechanism referenced elsewhere in
  the B5 ledger. Out of scope here.

## Architecture

### 1. Pattern-scan engine: reuse `agent/destructiveguard.Classify`

No new vocabulary list. `destructiveguard` is the real runtime enforcement
mechanism, already hardened by B5's own final review against obfuscation
bypasses (backtick/caret stripping, narration-line filtering, the
`format`/`wmic` regex fixes). A second, independently-maintained "dangerous
command" list would drift from it over time — the project's own B5 ledger
already discovered exactly this kind of drift once (I1/I2's bypass
findings). `go.work` ties `agent` and `orchestrator` together, so the new
orchestrator-side tool imports `agent/destructiveguard` directly.

`destructiveguard.Class` is binary (`NonDestructive` / `Destructive` — see
B5 final review's I4 ruling: "destructiveguard's local backstop is binary
non_destructive/destructive only"). This gives the audit's triage split:

- `Classify(command) == Destructive` → **manual-review queue**.
- `Classify(command) == NonDestructive` → `candidate_non_destructive`,
  promoted to `non_destructive` (see Promotion rule below).

`potentially_destructive` is never auto-derived — it only ever comes from a
human decision in the reviewed-decisions file (matching how the
hand-authored audit used it for self-limiting content like
`T1562.001:stop_auditd`).

`candidate_non_destructive` is purely an internal audit-workflow label that
exists only during generation, never a persisted or runtime state. The
`ExecutionClass` type and the 3-tier model it already defines
(`non_destructive` / `potentially_destructive` / `destructive`) are
unchanged (see Non-goals) — every entry that lands in
`execclass_generated.go` is one of those three, never "candidate" anything.

### 2. Promotion rule

A `candidate_non_destructive` item is promoted to `non_destructive` on
"no dangerous-pattern match" alone — no additional positive safe-pattern
allowlist is required. Rationale: `destructiveguard` remains an
independent runtime backstop regardless of what this audit concludes (it
re-evaluates every command at dispatch time, per B5's existing design).
The audit's job is classification *completeness*, not re-proving from
first principles that every command is safe — that proof already happens
at runtime, every time, via the backstop. This keeps the manual-review
queue scoped to genuine pattern hits rather than every item that merely
fails to match an allowlist.

### 3. Human-reviewed exception queue

A checked-in file, `orchestrator/internal/scenario/execclass_reviewed.yaml`,
holds every human decision made so far:

```yaml
- technique_id: T1490
  action_key: vss_delete_akira_style
  class: destructive
  reviewer: <name>
  reviewed_at: 2026-10-03
  note: "Win32_ShadowCopy.Delete() via WMI, same family as the hand-authored catalog's vss_delete"
- technique_id: T1562.001
  action_key: stop_windows_defender_service
  class: potentially_destructive
  reviewer: <name>
  reviewed_at: 2026-10-03
  note: "self-limiting: stops a real service, no persistence, same tier as the hand-authored stop_auditd entry"
```

Every `destructiveguard.Destructive`-flagged item that has a matching
entry here (by `technique_id` + `action_key`) takes that entry's `class`.
Every `Destructive`-flagged item with NO matching entry is `unresolved`.
New corpus content that trips the scanner on a later run, with no existing
reviewed-decisions entry, surfaces as a new `unresolved` item — this is
the mechanism that makes the audit re-runnable: a corpus update can only
ever *add* unresolved items for a human to triage, never silently resolve
them.

### 4. Identifier scheme

Both `art.go` and `caldera_store.go` already build a `TaskID` from each
atomic/ability's `Name` field. This spec reuses the same source:

```
action_key = slugify(Name)
```

If two distinct real commands under the same `technique_id` would
otherwise slugify to the same `action_key` (checked by comparing the
actual `Command` text, not assumed from the name), the executor is
appended: `slugify(Name) + "_" + executor` (e.g. `_psh`, `_sh`). If that
*still* collides — same slug, same executor, genuinely different command
text — the item is `unresolved`, never silently overwritten or arbitrarily
picked. Hand-authored catalog entries are never overwritten: a
`(technique_id, action_key)` pair that already resolves via the existing
hand-authored map is skipped and recorded in the report as
"already covered by hand-authored catalog."

### 5. Catalog storage

Rather than hand-writing thousands of Go map-literal lines into the
existing `execclass.go` (today: 126 hand-typed entries, 1047 lines), the
generator writes a separate file, `execclass_generated.go`, headed with a
`// Code generated by cmd/auditcorpus. DO NOT EDIT.` comment. Its `init()`
appends into the same package-level `executionClassifications` map that
`execclass.go` already populates. `ResolveExecutionClass` and
`AttachExecutionClassifications` are completely unchanged — same map, same
resolver, additive only, matching the exact pattern the original B5
pre-flight scan established for every other task in that plan.

### 6. Data sourcing — reuse production loaders, never a parallel parser

The generator imports `orchestrator/internal/scenario` directly and drives
the real loaders:

- ART: the same path `NewARTStoreFromDB` uses against a real
  `art_atomic_tests` table (populated by the orchestrator's own normal
  startup import against a locally-run `docker compose up` stack), then
  `ListTechniques()` / `GetSteps()` for real `ScenarioStep`s with real
  `Command` text.
- Caldera: the same path `NewCalderaStore` / `fetchAllCalderaAbilities`
  uses against a real, locally-running Caldera instance (same compose
  stack).

This guarantees the audit sees exactly what would actually be dispatched —
never a hand-rolled re-parse of the YAML/API shape that could drift from
the real loader's own interpretation (e.g. executor selection, elevation
mapping).

### 7. Tool shape

A permanent, checked-in Go command, `orchestrator/cmd/auditcorpus`,
re-runnable on demand (`go run ./cmd/auditcorpus`) against a locally-running
compose stack. Not a throwaway script — the reproducibility and
unresolved-gate requirements both imply running it again later, not just
once. It:

1. Loads the real ART store and Caldera store as described above.
2. For every discovered item, records reachability (has a real non-empty
   command, has a technique mapping — today's existing `tryLoad`-style
   filter for Caldera, the analogous check for ART) as its own attribute,
   never conflated with destructiveness.
3. Derives `action_key` per item (collision handling as above).
4. Skips anything already covered by the hand-authored catalog.
5. Runs `destructiveguard.Classify` on every remaining item's real command
   text.
6. Merges in `execclass_reviewed.yaml` decisions for anything flagged
   `Destructive`.
7. Writes `execclass_generated.go` (committed) and a coverage report
   (below, also committed).
8. Exits non-zero if the live stack (DB or Caldera) is unreachable —
   never writes a partial or stale-fallback catalog file on failure.

### 8. Coverage report

Written to `orchestrator/internal/scenario/testdata/execclass_corpus_report.md`
on every regeneration, split by source:

```
ART:
  discovered: N
  reachable: N
  classified: N
  destructive candidates: N
  manually reviewed: N
  unresolved: N

Caldera:
  discovered: N
  reachable: N
  classified: N
  destructive candidates: N
  manually reviewed: N
  unresolved: N
```

Counts come from the live corpus on the run that generated the report —
never hard-coded. An unreachable item is still counted in `discovered`,
flagged non-dispatchable in `reachable`, and still classified (a
non-dispatchable item can still carry real command text worth auditing if
it ever becomes dispatchable later).

### 9. The gate

A Go test in `orchestrator/internal/scenario`,
`TestExecutionClassifications_ARTCalderaCorpusFullyResolved`, re-runs the
same resolution the generator used (against the same live stack) and
asserts `unresolved == 0` for both sources. This needs the live stack to
run meaningfully, so it skips cleanly (not a hard failure) when no
Caldera/DB is reachable — matching this repo's existing convention for
testcontainer-backed suites (e.g. `internal/api`'s pattern). A CI or local
run with the stack up gets the real gate; a run without it gets a visible
skip, not a false green.

## Testing strategy

**Generator unit tests** (no live stack needed, fast, always run):
synthetic ART/Caldera fixtures covering — action_key slug collision +
executor disambiguation, a true unresolvable collision, hand-authored
precedence skip, the three-way triage (pattern-match / no-match-promoted /
reviewed-file override), and report-count arithmetic.

**Live-stack gate test** (`TestExecutionClassifications_ARTCalderaCorpusFullyResolved`):
needs the real compose stack, skips cleanly without it, is the actual
release gate.

**Manual-review verification:** for every item merged from
`execclass_reviewed.yaml`, the generator's own unit tests confirm the file
is parsed and applied correctly — but the *judgment* in that file (is this
command really `destructive` vs. `potentially_destructive`) is a human
decision, not something a test can verify out of its own content. This
mirrors Task 10's own precedent: a human read every real match.

## Open questions for the implementation plan

- Exact slugify algorithm (lowercase, strip punctuation, collapse
  whitespace to `_`) — mechanical, resolved during planning, not a design
  fork.
- Whether `cmd/auditcorpus` takes compose connection details via flags, env
  vars, or a config file — follows this repo's existing CLI conventions,
  resolved during planning.
- Initial population of `execclass_reviewed.yaml`: the plan's own
  implementation tasks will include the first real run against the live
  stack, reading every `Destructive`-flagged item's real command text, and
  writing that file's first real entries — this is the actual audit work,
  not infrastructure.

## Links

[[project_group_e_agent_trust_model]] · B5 Phase 1 ledger:
`.superpowers/sdd/2026-09-29-destructive-action-guardrail-b5-phase1/progress.md`
