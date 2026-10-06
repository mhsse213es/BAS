# G1 — innerHTML Sink Inventory (groupG.txt, Phase 1: classification + indirect-sink resolution)

**Date:** 2026-10-04
**Scope:** `orchestrator/wwwroot/index.html` (22,316 lines)
**Status:** Classification complete and fully resolved — every one of the 459 sinks now has a final, traced-through category. No `unclear`/`indirect_builder`/`indirect_variable` remain.

This document supersedes the first version committed in `0ad56668`. That version's classifier had real bugs (detailed below) that this version found and fixed through systematic re-validation — the numbers here are corrected, not incremental.

## Files

- `Assessment/G1_INNERHTML_SINK_INVENTORY.csv`/`.json` — the 459-sink baseline (direct classification only; 55 of these are `indirect_builder`/`indirect_variable`, meaning "needs tracing").
- `Assessment/G1_INDIRECT_SINK_TRACE.csv` — those 55 sinks, each resolved to a real category by tracing into the function/variable it actually comes from.
- `Assessment/G1_FINAL_CLASSIFICATION.csv` — **the authoritative merged result**: all 459 sinks, baseline category + final (traced-through) category side by side. Use this one for anything downstream.
- `scripts/g1-innerhtml-sink-classifier.py` — the baseline classifier (re-runnable after G1a lands, to measure progress against this document's numbers).
- `scripts/g1-trace-indirect-sinks.py` — the indirect-sink resolver (position-based lexical-scope resolution, not name-text search — see below for why that distinction mattered).

## Final result: 459 sinks, fully resolved

| Category | Count | % |
|---|---|---|
| `static` | 138 | 30.1% |
| **`unescaped_html`** | **129** | **28.1%** |
| `escaped` | 82 | 17.9% |
| `partial_escaped` | 54 | 11.8% |
| `static_empty` | 41 | 8.9% |
| `unescaped_text` | 13 | 2.8% |
| `unescaped_likely_safe` | 2 | 0.4% |

**129 confirmed unescaped dynamic-HTML sinks** — this is the real, fully-resolved G1a population. It is *higher* than the first pass's headline number (95), not lower: tracing the 55 indirect sinks surfaced more genuine findings than it resolved away (31 of the 55 turned out to be `unescaped_html` once traced to their real source — see "Indirect-sink resolution" below). Combined with `partial_escaped` (54, mixed) and `unescaped_text` (13, textContent candidates), there are 196 sinks (42.7%) with at least one unescaped interpolation point worth a human decision. 138 are genuinely static (zero risk), and 82 are already correctly escaped.

## Why the first pass's numbers were wrong — six real classifier bugs, found by validating, not assuming

The baseline classifier is a hand-rolled JS tokenizer, not a naive grep. Before trusting its output, it was validated against the actual source repeatedly, and each round of validation found a real bug that materially changed the counts. In order found:

1. **Ternary mis-split.** `.* ` string-splitting on top-level `+` doesn't understand `cond ? a : b` — the `?`/`:` characters got treated as ordinary text, producing bogus "unescaped" fragments from a ternary's own syntax.
2. **Missing `re.DOTALL`.** Python's `.` doesn't match newlines by default. Every multi-line function call (the dominant style in this file) silently failed to match the escaper/builder-call regexes, undercounting `indirect_builder`.
3. **JS regex literals.** The common `.replace(/'/g, "&#39;")` idiom contains a bare `'` inside the regex pattern. Unhandled, this derailed the whole-file scan — one sink's captured RHS ran 31KB past its real end, all the way to end-of-file, before this was caught (via an automated outlier check on `rhs_len`, not manual review) and fixed.
4. **JS comments.** An apostrophe inside an English-prose comment (`"A previously-checked agent that's now incompatible"`) was misread as a string-literal start, corrupting every subsequent depth/quote/semicolon decision. Confirmed real impact on live code in this file, not a hypothetical.
5. **Parenthesized ternaries invisible to the ternary-detector.** `(changed ? '<span>a</span>' : '<span>b</span>')` — the wrapping paren hid the `?` from ever being seen at depth 0. This single bug misclassified a *fully-escaped* function (`_diffSecretRow()`) as `partial_escaped`, and was found by manually re-deriving why one specific sink looked wrong rather than trusting the tool.
6. **Loose substring heuristic pre-empting structural checks (two instances).** `SAFE_NUMERIC_RE.search()` matches `.length`/`Math.`/etc. *anywhere* in a hole's text. This let it fire (a) on a ternary whose *condition* merely mentioned `.length`, skipping inspection of the actual rendered branches, and (b) on an unrelated local variable buried inside a `.map()` callback, before the callback's real (fully-escaped) `return` statement was ever examined. Both were fixed by checking ternary-split and nested-`return` extraction *before* the numeric heuristic, not after. A closely related bug (7th, same session) was a bare `p.steps.length`-style property chain being misrouted into "needs tracing" instead of recognized as a safe number, because it structurally matches the same bare-identifier pattern as a real pass-through variable.

Each of these was found by **validating against real source lines that looked wrong**, not by assuming the tool's first output was correct — the consistent pattern was: pick a sampled or outlier result, read the actual code, notice the mismatch, find the root cause, fix it, re-run, re-validate. The final numbers above reflect all seven fixes.

## Indirect-sink resolution: 55 sinks traced to their real source

The baseline's 55 `indirect_builder`/`indirect_variable` sinks (call a helper function, or read a bare variable, without their content visible at the call site) were resolved by:

1. Building a full map of every function body's span in the file (comment/string/regex-aware, so a "function" mentioned in a comment never creates a false span).
2. For each sink, finding its *true* innermost enclosing function by **position**, not by name — several helper names (`tile` ×5, `row` ×4, `list` ×3, `fmt` ×2) are each declared as **separate local closures inside different outer functions**. A name-text search grabbed the wrong one for several sinks before this was caught; the fix resolves every lookup by lexical-scope containment, the same way a JS engine would.
3. For `indirect_builder`, extracting the resolved function's `return` statement(s) and classifying them with the same (now-fixed) classifier.
4. For `indirect_variable`, finding every assignment to that variable inside its real enclosing function and classifying each.

**Result: 50 of 55 resolved automatically.** The remaining 5 needed one more level of manual tracing (the automated tool resolves one hop; these needed two):

| Line | What it resolves to | Verdict |
|---|---|---|
| L11243 | `loadDashboardITSM`'s local `tile(lbl,val,col)` closure returns `lbl`/`val` **unescaped**; fed from `p.provider`/`p.count` (an ITSM connector's `byProvider` API response) | **`unescaped_html`** — real finding |
| L12544 | `e.html` built via `runRowHtml(r)` or `_sweepRowHtml(payload,opts)`, both of whose real HTML-building return is `partial_escaped` | **`partial_escaped`** |
| L13533 | Module-level `_postureSummaryCache`, written with posture-catalog phase names (`catNames.join(', ')`) unescaped inside a `<strong>` tag context | **`unescaped_html`** — real finding |
| L16087 | Local `rowHtml(k,v)` closure doesn't escape internally, but **every current call site** pre-escapes `v` via `x()` or passes numeric/Date-formatted content | **`escaped`** today, but **fragile** — flag for G1a: harden `rowHtml` itself, don't rely on every future caller remembering to pre-escape |
| L18260 | `diffHtml` parameter, traced across all 5 call sites — every one passes `rows` built exclusively from `_diffRow()`/`_diffSecretRow()`, both fully escaped | **`escaped`** |

Final indirect-sink breakdown (55 total): **31 `unescaped_html`, 10 `partial_escaped`, 7 `escaped`, 6 `static`, 1 `unescaped_text`.**

## Root-cause evidence (unchanged from the first pass, still confirmed)

Four separate escaper definitions exist, with genuinely inconsistent behavior:

| Location | Escapes `&`,`<`,`>` | Escapes `"` | Escapes `'` |
|---|---|---|---|
| `function x(s)` — line 15003 | ✅ | ✅ | ❌ |
| `function x(s)` — line 15149 (scoped inside another function) | ✅ | ❌ | ❌ |
| `function x(s)` — line 17163 | ✅ | ✅ | ❌ |
| `function escHtml(s)` — line 19111 | ✅ | ❌ | ❌ |

Plus a fifth, ad-hoc attribute-context escape: `JSON.stringify(a.actorName).replace(/'/g, "&#39;")` (line ~6591), used for embedding data inside a single-quoted `onclick='...'` attribute.

## Security-oriented classification (data-source / control-type), as requested

Per the proposed second taxonomy — distinguishing "XSS sink requiring remediation" from "HTML sink requiring hardening" by *who controls the data*, not just whether it's escaped:

For the **156 directly-classified needs-attention sinks** (`unescaped_html`/`unescaped_text`/`partial_escaped`/`unescaped_likely_safe`, excluding the 55 indirect ones which are covered narratively above), keyword-tagged by data source:

| Data source | Count |
|---|---|
| `user_created_name` (`.name`/`.title`/`.description`/`.username`) | 34 |
| `agent` (hostname, agentId) | 24 |
| `api_response` (`.result`/`.data`) | 5 |
| `threat_intel` | 3 |
| `scenario` | 2 |
| `openaev` (imported data) | 1 |
| `actor` | 1 |
| `error_message` | 1 |
| `telemetry_log` | 1 |
| **(untagged / needs manual judgment — "unknown")** | **96** |

The 96 untagged sinks are an honest gap, not a hidden claim of safety: the keyword-tagger only catches variable names matching its known patterns. Resolving them to a real control-source bucket (attacker/user-controlled vs. agent-controlled vs. server/API-controlled vs. internally-generated vs. genuinely unknown) is manual-review work for the G1a pass itself, not something this classification run forced a guess on.

For the **55 traced indirect sinks**, control sources identified during tracing (narrative, not tagged — each was read manually): ITSM connector provider names and posture-catalog phase names (both **API-controlled**), run/scenario/agent result data via `runRowHtml`/`_sweepRowHtml` (**agent/scenario-controlled**), admin-config diff values via `_diffRow` (**operator-entered, already escaped**), KPI tile labels (**internally generated, mostly hardcoded**).

## Recommended next step (per the reviewed G1a remediation order) — ALL DONE

1. ✅ **Baseline committed and corrected** (this document, `a7a7eebb`).
2. ✅ **54/55 indirect sinks resolved** to real categories (one more than originally counted — `11243` was also indirect at the variable level before resolving to a builder call).
3. ✅ **Canonicalized the escaping layer** (`913df1f4`) — one `escapeHTML()`/`x()`, the 3 duplicate `x()` definitions and `escHtml()` removed. A **5th duplicate** (`xe()`, local to `renderEvidencePanel`) was missed by that pass's search and found/removed later, in `424034ce`.
4. ✅ **Converted the real `unescaped_text` sinks to `textContent`** (`e96a7b76`) — 4 of 13 flagged were real; the other 9 were a confirmed classifier blind spot (builder-chain calls the classifier can't see into).
5. ✅ **Reviewed the 54 `partial_escaped` sinks individually** (`74b91dde`) — 9 real gaps fixed, 45 confirmed false positives.
6. ✅ **Fixed the confirmed `unescaped_html` sinks + hardened `rowHtml()`** (`424034ce`) — all 129 flagged sinks read individually; 9 real gaps fixed (including the `rowHtml()` hardening from item 7 below, folded into the same commit) plus the 5th duplicate escaper from item 3.
7. ✅ **Hardened the `rowHtml()` fragile pattern** (`424034ce`, same commit as step 6) — now escapes its `v` parameter internally instead of relying on every caller to pre-escape.
8. ✅ **Re-ran both scripts, diffed against the committed baseline** — see "G1a Final Results" below.
9. G1b (regression tests, CI guard) is the next initiative, now that G1a is verifiably done by the exit criteria stated in memory (one canonical escaper, no duplicates, all textContent-convertible sinks converted, all confirmed dynamic-HTML gaps remediated, indirect sinks resolved, classifier reruns clean) — not "innerHTML reaches zero," which was explicitly never the goal.

## G1a Final Results — Before / After (2026-10-04)

Re-ran `scripts/g1-innerhtml-sink-classifier.py` + `scripts/g1-trace-indirect-sinks.py` against the fully-remediated file and re-merged into `Assessment/G1_FINAL_CLASSIFICATION.csv`, the same way the original baseline was built. All 55 indirect sinks resolved cleanly again (50 automatically, 5 by the same one-more-hop manual trace the baseline needed — same 5 line numbers, re-verified against current code, not re-copied from the old doc).

| Category | Baseline (`a7a7eebb`) | Final (post-G1a) | Δ |
|---|---|---|---|
| Total sinks | 459 | 455 | **−4** |
| `static` | 138 (30.1%) | 138 (30.3%) | 0 |
| **`unescaped_html`** | **129 (28.1%)** | **126 (27.7%)** | **−3** |
| `escaped` | 82 (17.9%) | 86 (18.9%) | **+4** |
| `partial_escaped` | 54 (11.8%) | 53 (11.6%) | −1 |
| `static_empty` | 41 (8.9%) | 41 (9.0%) | 0 |
| `unescaped_text` | 13 (2.8%) | 9 (2.0%) | **−4** |
| `unescaped_likely_safe` | 2 (0.4%) | 2 (0.4%) | 0 |
| unresolved (`indirect_*`/`unclear`) | 0 | 0 | 0 |

The −4 total is exactly the 4 `innerHTML` → `textContent` conversions from step 4 (`e96a7b76`) — those sinks no longer match the classifier's `.innerHTML =` pattern at all, which is the expected, correct effect of that fix, not data loss. The `unescaped_text` drop (13→9) is the same 4 conversions. The `escaped` increase (+4) and `partial_escaped`/`unescaped_html` decreases reflect the real fixes from steps 5-6: sinks that were genuinely unescaped or partially escaped moved into the fully-escaped bucket as each gap was closed (`initiativeStateLabel`, `vfStatusLabel`, `_apOnCollected`, `openAdvDrawer`, `openFinding`, `viewRunResults` (2 fields), `renderRunReportExtra` (6 fields), `loadAgtOverview` (2 fields), `_apRenderJobState` (2 fallbacks), `loadDashboardITSM`/`renderConnectorList`/`renderResponseConnectorList` (3 provider fallbacks), `renderModalSelection`'s `catNames`, `initComplianceTab`'s agent dropdown, and `rowHtml()`'s hardening — 23 individual escaping fixes across 14 functions, spread over commits `74b91dde` and `424034ce`).

**This is not "all unescaped_html sinks are now fixed."** 126 sinks remain classified `unescaped_html` after full remediation — this is the expected, deliberate result of G1a's stated exit criteria (never "innerHTML reaches zero"). Every one of those 126 was individually read during the step-6 review and confirmed as one of:
- A classifier false positive: numeric field, hardcoded/closed-set literal, already escaped via a helper function the classifier's `BUILDER_CALL_RE`/`SAFE_NUMERIC_RE` can't see into (the majority — same builder-chain and numeric blind spots documented in steps 4-5).
- A backend compute-on-read closed enum rendered without `x()` but never user-controlled (e.g. `campaignDisplayStatus().cls`, privilege tier, compliance control status, coverage status) — a consistency nit, not a vulnerability, left as-is per the minimal-changes principle.
- An already-documented, explicitly-accepted low-risk item (`viewRunResults`' `runId` across several `onclick` handlers — server-generated UUID, inconsistent to fix half; `href=` targets that are entity-escaped but not scheme-validated, same class as `e.url` from step 5).

The classifier's label was never trusted as ground truth at any point in this remediation — every one of the 129 (then 126) `unescaped_html`-flagged sinks got a human read of the real code and its real call sites before a decision was made, consistent with the whole G1a methodology.

**G1a is closed.** Next: G1b (CI guard / regression tests to keep this from regressing) is a separate initiative, not bundled into this one.
