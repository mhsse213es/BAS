# G1b — XSS Sink CI Regression Guard — Design

## Context

[[Group G — Frontend XSS Surface]] G1a closed (`a7a7eebb` through `05aa7cbe`,
2026-10-04): every one of the 459 original `.innerHTML =` sinks in
`orchestrator/wwwroot/index.html` got a human read, 23 genuine escaping gaps
across 14+ functions were fixed, the escaping layer was canonicalized to one
`escapeHTML()`/`x()`, and a 5th duplicate escaper (`xe()`, functionally
identical but missed by the original canonicalization search) was found and
removed. The current state (455 sinks, `Assessment/G1_FINAL_CLASSIFICATION.csv`)
is the **intended baseline** — not the pre-remediation 459-sink inventory.

The classifier (`scripts/g1-innerhtml-sink-classifier.py`) and indirect-sink
tracer (`scripts/g1-trace-indirect-sinks.py`) that did this audit are
hand-rolled, battle-tested Python tools. Nothing currently re-runs them: the
only CI workflow (`.github/workflows/test.yml`) is 100% Go (`gofmt`, `vet`,
`staticcheck`, `build`, `test`), and there is no Node/npm/frontend build step
anywhere in this repo — `orchestrator/wwwroot/` is a single static
`index.html`. Without enforcement, every fix this session made is one
careless future edit away from quietly regressing, and nothing would notice.

G1b's job: make that regression structurally hard, using only what the repo
already has (Python 3 stdlib, GitHub Actions' existing Go-only workflow),
adding nothing new (no Node, no pip install, no new frontend tooling).

## Goals

1. Catch a sink's security posture getting worse — an `escaped` sink
   becoming `partial_escaped`, a canonical-escaper regression — automatically,
   in CI, on every PR.
2. Catch the baseline going stale — someone edits `index.html` without
   re-running the audit tools and committing the result — automatically.
3. Never auto-fail on a brand-new sink merely because of its classification.
   G1a's entire premise was that `unescaped_html` is sometimes fine once a
   human reads the real code (126 of 455 sinks are exactly that, today,
   accepted). A guard that hard-blocks every new sink at the same tier 126
   existing ones already sit at would repeat the "455 ≠ 455 vulnerabilities"
   mistake this initiative exists to correct. New sinks are reported, not
   blocked; a human reviews them in the PR like any other code.
4. Survive ordinary development. Editing code elsewhere in a 22K-line file
   must never generate false "sink disappeared" / "sink appeared" noise —
   this session hit exactly that problem once (deriving a manual line-shift
   formula after a single escaper edit) and the guard must not reproduce it.
5. Make "did someone hand-edit the baseline instead of running the tools"
   detectable: the committed baseline must be exactly reproducible by
   re-running the pipeline, byte-for-byte.

## Non-goals

- Changing `scripts/g1-innerhtml-sink-classifier.py` or
  `scripts/g1-trace-indirect-sinks.py`. Both are proven; G1b adds a merge
  step and a checker around them, nothing inside them.
- Introducing Node, npm, a JS test framework, or a JS execution environment
  of any kind. The escaper-contract check is static/source-level, not
  behavioral/executed — see Architecture §4.
- A general "no unescaped HTML in this codebase" policy. G1a's own exit
  criteria were explicit: not "innerHTML reaches zero."
- Re-litigating any of G1a's accepted sinks. The committed baseline this
  guard protects already reflects informed human review of all 455.

## Architecture

```
orchestrator/wwwroot/index.html
        │
        ▼
scripts/g1-innerhtml-sink-classifier.py   (existing, unchanged)
scripts/g1-trace-indirect-sinks.py         (existing, unchanged)
        │
        ▼
scripts/g1-merge-classification.py          (NEW)
        │
        ▼
Assessment/G1_FINAL_CLASSIFICATION.json     (NEW — CI source of truth)
Assessment/G1_FINAL_CLASSIFICATION.csv      (existing — human/audit view;
                                              now generated, not hand-run)
        │
        ▼
scripts/g1-check-no-regression.py           (NEW — the CI guard)
        │
        ▼
.github/workflows/test.yml                  (one new step)
```

### 1. `scripts/g1-merge-classification.py` — deterministic merge

Replaces the ad-hoc merge this session ran from a scratchpad script.
Reads `G1_INNERHTML_SINK_INVENTORY.csv` + `G1_INDIRECT_SINK_TRACE.csv`
(both already committed by the two unchanged scripts), resolves every
`indirect_builder`/`indirect_variable` row to its traced `resolved_category`,
and emits both `G1_FINAL_CLASSIFICATION.json` (authoritative) and `.csv`
(audit view, same schema as today's: `line, function, target, op,
baseline_category, final_category, data_source_tags, trace_notes, rhs`).

**Determinism is a hard requirement**, not a nice-to-have — it's what makes
the freshness check (§5) meaningful:
- Row order: sorted by `(function, target, op, sink_id)` — a stable,
  content-derived order, not file line order (which shifts).
- Field order: fixed key list in both the CSV `DictWriter` and the JSON
  (plain dicts in a fixed order; Python 3.7+ dicts preserve insertion order,
  so building each record with the same key sequence every time is enough —
  no `sort_keys` needed, but `json.dump(..., indent=2)` with no additional
  whitespace variance).
- No timestamps, no absolute/machine-specific paths (`orchestrator/wwwroot/
  index.html`, never a resolved absolute path).
- Explicit `encoding="utf-8", newline="\n"` on every file write (the repo's
  Windows dev box has already produced CRLF/LF warnings on every commit this
  session touched — this must not leak into the generated baseline's
  byte-identity check).

`python3 scripts/g1-merge-classification.py` run twice in a row on an
unchanged tree must produce byte-identical output. This is the thing CI
actually checks (§5).

### 2. Sink identity: `sink_id`, not line number, not a bare ordinal

A sink's identity is derived, not positional:

```python
sink_id = f"{function}:{target}:{op}:{sha256(normalize(rhs)).hexdigest()[:12]}"
```

- `function` — the classifier's existing enclosing-function resolution
  (nearest preceding `function` declaration; already relied on throughout
  G1a's manual review and found reliable in practice).
- `target` — the LHS being assigned (`tb`, `el`, `document.getElementById(...)`,
  etc.), exactly as the classifier already extracts it.
- `op` — `=` or `+=`.
- `normalize(rhs)` — the RHS with every run of whitespace (including
  newlines) collapsed to a single space, then trimmed. Hashed (not stored
  raw) to keep the id short and stable; the full `rhs` stays in the record
  for human reading.

`line` is kept in the record as **metadata only** — useful for a human
jumping to the sink, never used for identity or comparison. This is the
direct fix for the line-shift problem: inserting an `innerHTML` assignment
earlier in a function no longer invalidates every `sink_id` after it, the
way a line-number or bare-ordinal key would.

Known, accepted edge case: two distinct sinks sharing the same
`(function, target, op)` *and* an identical (post-truncation) RHS text
would collide into one `sink_id`. Given `function`+`target`+`op` already
disambiguates almost everything, and an identical RHS at that point really
is the same code, this is deliberately not solved further — flagging it
here rather than adding complexity for a case that hasn't occurred once
across 455 real sinks.

### 3. The "slot" — `(function, target, op)` without the RHS hash — and the regression rule

Two sinks belong to the same **slot** if they share `function`+`target`+`op`,
regardless of `sink_id`. The checker compares old (main) vs. new (PR)
baselines slot-by-slot:

| Old slot state | New slot state | Verdict |
|---|---|---|
| exists, severity *N* | gone entirely | **OK** — sink eliminated (this is exactly what a `textContent` conversion does: the slot's `.innerHTML =` stops existing). No further check. |
| exists, severity *N* | exists, severity ≤ *N* (same or safer `sink_id`, or a different `sink_id` at ≤ *N*) | **OK** |
| exists, severity *N* | exists, severity > *N* (different `sink_id`, now more dangerous) | **FAIL** — a replacement at the same slot got worse. This is the "removed sink + new dangerous sink in its place" case your review flagged — caught because it's the *same slot* regressing, not an unrelated new sink. |
| doesn't exist | exists, any severity | **Reported only, never auto-failed** (Goal 3) |

Severity tiers (low → high), computed from `final_category`:

| Tier | Categories |
|---|---|
| 0 | `static`, `static_empty` |
| 1 | `escaped` |
| 2 | `unescaped_likely_safe` |
| 3 | `partial_escaped` |
| 4 | `unescaped_text`, `unescaped_html` |

`unescaped_text` and `unescaped_html` share the top tier deliberately: both
mean an unescaped runtime value reaches `.innerHTML` — `unescaped_text`
differs only in that the developer's literal template had no HTML tag,
making it a `textContent`-conversion *candidate*, not a lower-risk category.
The original fine-grained `category` (and `baseline_category`/
`final_category` for traced sinks) stays in the JSON unchanged alongside the
new `severity_tier` field — severity drives the guard, category drives the
human remediation hint, and G1a's existing per-sink notes are never lost.

### 4. Canonical-escaper check — semantic, not textual

Scans the whole file for every function definition using the same
comment/string/regex-aware brace-matching approach as
`g1-trace-indirect-sinks.py`'s `scan_function_spans()` (duplicated rather
than imported — see Open Questions) to find each candidate function's real
body bounds, including nested ones. For each body, runs four independent,
whitespace/ordering-tolerant regex checks against the *semantic* contract
rather than one literal multi-line signature:

- contains a substitution mapping `&` → `&amp;`
- contains a substitution mapping `<` → `&lt;`
- contains a substitution mapping `>` → `&gt;`
- contains a substitution mapping `"` → `&quot;`

A function satisfying **all four** is "escaper-like," regardless of
variable names, statement order, semicolon style, or chaining vs. sequential
`.replace()` calls — this is what makes it robust against reformatting,
unlike matching one exact `.replace(/&/g,'&amp;').replace(/</g,...)` chain
(which is exactly how `xe()` would have been missed again by a differently
-styled duplicate). The check fails when:

- zero escaper-like functions exist (the canonical one lost a required
  substitution), or
- more than one escaper-like function exists (a duplicate, named anything),
  or
- the one canonical escaper-like function *also* contains a substitution
  mapping a bare `'` to any HTML entity (`&#39;`/`&apos;`/`&#x27;`) — this
  is the deliberate, documented contract (several callers apply their own
  quote-context escaping after calling `x()`, relying on receiving a raw
  `'`) and the check exists specifically so a well-intentioned "let's also
  escape quotes" edit gets caught, not silently shipped.

This is static/source-level, not an executed behavioral test — no JS
interpreter, no Node, matching the project's stdlib-only constraint.

### 5. The two checks CI actually runs

```yaml
- name: G1 XSS sink regression guard
  run: |
    python3 scripts/g1-merge-classification.py
    git diff --exit-code Assessment/G1_FINAL_CLASSIFICATION.json Assessment/G1_FINAL_CLASSIFICATION.csv || \
      (echo "::error::Baseline is stale — run scripts/g1-merge-classification.py and commit the result." && exit 1)
    git show origin/main:Assessment/G1_FINAL_CLASSIFICATION.json > /tmp/main_baseline.json 2>/dev/null || echo "{}" > /tmp/main_baseline.json
    python3 scripts/g1-check-no-regression.py --against /tmp/main_baseline.json
```

- **Freshness**: re-run the merge script against the actual working tree,
  then `git diff --exit-code` the two generated files against what's
  committed. Any difference means the baseline doesn't reflect the real
  code — fails immediately, before the regression check ever runs against
  possibly-stale data. This step alone depends on determinism (§1).
- **Regression**: `g1-check-no-regression.py` loads the (now-confirmed-fresh)
  committed JSON and the base branch's JSON, applies the slot-based rule
  (§3) and the escaper check (§4), prints a human-readable report (every
  slot's verdict, every brand-new sink listed with its classification for
  reviewer visibility), and exits non-zero only on a genuine regression.
- On `main` itself (no PR, no meaningful base to diff against — e.g. a
  direct push), `git show origin/main:...` naturally fails and the fallback
  `{}` makes the regression check a no-op; only the freshness check applies.
- `python3` ships on GitHub's `ubuntu-latest` runners already — no
  `actions/setup-python`, no `pip install`, no new job, just three new lines
  inside the existing `test` job (after the Go steps, since this check is
  independent of them and either order is fine).

### 6. Baseline-update workflow

A PR that genuinely changes a sink (new feature, refactor, further
remediation) runs `python3 scripts/g1-merge-classification.py` locally and
commits the regenerated `G1_FINAL_CLASSIFICATION.json`+`.csv` in the same
PR — exactly the same motion as updating any other generated artifact
(`go generate`, a lockfile). The guard's only opinion is whether that
update is *honest* (§3's slot rule), never whether an update is allowed.

## Testing strategy

`scripts/g1-check-no-regression.py` gets its own test file using Python's
stdlib `unittest` (no `pytest`, no new dependency), run via `python3 -m
unittest` as part of the same CI step. Synthetic before/after JSON fixtures
(small, hand-written — not derived from the real 455-sink baseline) exercise
each rule independently:

- a slot eliminated entirely → pass
- a slot's severity increasing at the same slot → fail
- a slot's severity decreasing or staying level → pass
- a brand-new slot at the top severity tier → pass, but present in the
  reported output
- the canonical escaper losing one of its four required substitutions → fail
- a second escaper-like function appearing anywhere in the fixture → fail
- the canonical escaper gaining a `'` substitution → fail

`scripts/g1-merge-classification.py` gets one `unittest` case: run it twice
against the same fixture input, assert byte-identical output (the
determinism requirement from §1, proven, not just asserted in a comment).

No test depends on the real `orchestrator/wwwroot/index.html` — all fixtures
are small, synthetic, and inline in the test file, so the test suite runs in
milliseconds and never needs the real file's 22K lines to validate the
checker's logic.

## Open questions for the implementation plan

- `scan_function_spans()` in `g1-trace-indirect-sinks.py` is a module-level
  function operating on that module's own `text` global, not structured as
  an importable library function — the tracer script runs it as a top-level
  statement (`SPANS = scan_function_spans(text)`), so importing it would
  execute the whole tracer as a side effect. Given the explicit constraint
  that the two existing scripts stay untouched (not just their logic — at
  all), the implementation plan should duplicate the ~40-line span-finder
  into the new canonical-escaper checker rather than refactor the tracer to
  make it importable. The duplication is small, self-contained, and the
  cost of two copies drifting is low since this function (brace/string/
  comment-aware matching) is syntactic, not security logic — unlike the
  classifier/tracer's actual classification rules, which must never be
  duplicated.
- Exact regex patterns for the four semantic substitution checks in §4 —
  needs to tolerate `'&amp;'`/`"&amp;"` quoting and `.replace(/&/g, "&amp;")`
  vs `.replace(/&/g,"&amp;")` spacing; the implementation plan should pin the
  exact patterns and show they match the real `escapeHTML` function as it
  exists today.
- Whether `g1-merge-classification.py` should recompute `function`/`target`/
  `op`/`rhs` from scratch or trust the two upstream CSVs' columns verbatim
  (recommend: trust them — re-deriving would duplicate the classifier's own
  logic, which is explicitly out of scope per Non-goals).
- CI's `git show origin/main:...` requires `origin/main` to actually be
  fetched in the checkout step; `actions/checkout@v4`'s default shallow
  checkout may not have it. The implementation plan should verify (likely:
  `fetch-depth: 0`, or fetching just that one ref) and show the real CI run
  succeeding, not just the local script.

## Links

[[project_group_g_xss_sink_audit]] — the G1/G1a initiative this closes the
loop on.
