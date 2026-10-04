# G1 — innerHTML Sink Inventory (groupG.txt, Phase 1: classification)

**Date:** 2026-10-04
**Scope:** `orchestrator/wwwroot/index.html` (22,316 lines)
**Method:** Automated classification per groupG.txt's own taxonomy (text-only / static HTML / dynamic-trusted / dynamic-untrusted / rich-untrusted / unclear), built from a hand-rolled JS tokenizer (handles multi-line concatenation, backtick templates, ternaries — including nested — `.map()`/`.filter()` callback bodies, JS comments, and regex literals) rather than a line-count or naive regex. Full row-level data: `Assessment/G1_INNERHTML_SINK_INVENTORY.csv` (459 rows).

This is a heuristic triage pass, not a perfect static analyzer. Where the tool can't confidently resolve a sink, it is bucketed into `indirect_builder`/`indirect_variable` (needs tracing into another function) rather than guessed at — consistent with groupG.txt's own "Unclear — manual review — do not modify automatically" category.

## Total: 459 sinks (vs. groupG.txt's reported 455 — within normal counting-method variance; multiple `grep` conventions land between 450–461 depending on whether `+=` and multi-assignment lines are counted)

| Category | Count | % | What it means |
|---|---|---|---|
| `static` | 132 | 28.8% | Pure string literal(s), no interpolation at all. Zero risk. |
| `unescaped_html` | 95 | 20.7% | **Dynamic HTML with at least one unescaped interpolation, inside a template that already contains HTML tags.** This is the real G1 attack surface. |
| `escaped` | 59 | 12.9% | Dynamic content, but every interpolated value is wrapped in a known escaper (`x()`/`escHtml()`/etc.) or is a ternary/`.map().join()` whose branches resolve to escaped/static content. |
| `partial_escaped` | 44 | 9.6% | Dynamic HTML with **some** values escaped and some not, in the same sink. Needs line-by-line attention. |
| `static_empty` | 41 | 8.9% | RHS is just `''` (a clear/reset). Zero risk. |
| `indirect_builder` | 27 | 5.9% | RHS is (partly) a call to another app-defined function (e.g. `covSegHtml(...)`, `tile(...)`, `_apStep(...)`) whose own escaping can't be verified from the call site alone — needs tracing into that function. |
| `indirect_variable` | 27 | 5.9% | RHS is a single bare variable (e.g. `sel.innerHTML = opts;`) built elsewhere — needs tracing to where that variable was assigned. |
| `unescaped_likely_safe` | 22 | 4.8% | Unescaped interpolation, but the value is clearly numeric/boolean/computed (`.length`, `Math.*`, counts) — low actual XSS risk despite being technically unescaped. |
| `unescaped_text` | 12 | 2.6% | Unescaped interpolation in a template with **no** static HTML tags — a `textContent` candidate today built as a string. |

**Needs-attention total (everything except `static`/`static_empty`/`escaped`): 227 sinks (49.5%)** — roughly half the file's sinks have *some* signal worth a human look, but only **95 (`unescaped_html`, 20.7%)** are the sharp, obviously-exploitable case groupG.txt was worried about: genuine dynamic HTML markup with an unescaped interpolation point. The 455-sink headline count was never 455 vulnerabilities, and this confirms it — but 95 is still a real, non-trivial number, not "20 sinks."

## Root-cause evidence confirmed (G1's own diagnosis)

Four separate escaper definitions exist, with genuinely inconsistent behavior — not just duplicated, but **actually different**:

| Location | Escapes `&`,`<`,`>` | Escapes `"` | Escapes `'` |
|---|---|---|---|
| `function x(s)` — line 15003 | ✅ | ✅ | ❌ |
| `function x(s)` — line 15149 (scoped inside another function) | ✅ | ❌ | ❌ |
| `function x(s)` — line 17163 | ✅ | ✅ | ❌ |
| `function escHtml(s)` — line 19111 | ✅ | ❌ | ❌ |

None of the four escape `'`. Two of the four also don't escape `"`. There is also a fifth, **different kind of escaping** in play: `JSON.stringify(a.actorName).replace(/'/g, "&#39;")` (line ~6591) — a hand-rolled, attribute-context-specific escape that only neutralizes single quotes, used for embedding data inside a single-quoted `onclick='...'` HTML attribute. That pattern is defensible *in principle* (attribute context needs different escaping than text context) but it's a fifth ad-hoc mechanism nobody has canonicalized, exactly matching groupG.txt's "no single canonical escaper" root cause.

No numeric-variable shadowing of `x` was found in this pass (groupG.txt flagged this as a risk, but a targeted grep for `var x = <number>` / coordinate-style `x`/`y` pairs found none — worth re-checking if the modularization pass (G1c) finds any at the IIFE/closure boundaries this script doesn't trace into).

## Where the risk actually concentrates (needs-attention sinks only, by data source)

| Data source signal | Count |
|---|---|
| `user_created_name` (`.name`/`.title`/`.description`/`.username`) | 42 |
| `agent` (hostname, agentId) | 26 |
| `api_response` (`.result`/`.data`) | 6 |
| `scenario` | 4 |
| `threat_intel` | 3 |
| `openaev` (imported data) | 2 |
| `actor` | 1 |
| `error_message` | 1 |
| `telemetry_log` | 1 |

This roughly matches groupG.txt's own suspect list (agent-controlled fields, scenario/actor names, imported data, error messages) — `user_created_name` and `agent` dominate, which tracks: those are the fields most often rendered directly into table rows and detail panels throughout the dashboard.

## Illustrative real examples (from the CSV, not constructed)

**`unescaped_html` (the real attack surface) — L10376, `openAdvRunModal`:**
```js
agents.map(function(a) {
  var os = a.osVersion ? ' [' + (a.osVersion.toLowerCase().indexOf('windows') !== -1 ? 'Win' : 'Other') + ']' : '';
  return '<option value="' + x(a.agentId) + '">' + x(a.agentId) + ' — ' + x(a.hostname) + os + '</option>';
}).join('')
```
Three of four interpolations are properly escaped via `x()`. The fourth, `os`, is a local variable built two lines above from a ternary over only hardcoded strings (`'Win'`/`'Other'`/`''`) — in this specific case it's actually safe, but the sink can't prove that from the call site alone, which is exactly why this is flagged rather than silently cleared.

**`escaped` (correctly defended, now confirmed rather than assumed) — L22006, `openSchedWizardForEdit`:**
```js
scenarios.map(function(s) { return '<option value="' + x(s.id) + '">' + x(s.name) + '</option>'; }).join('')
```

**`indirect_builder` (needs tracing, don't touch yet) — L8369, `c`:**
```js
covSegHtml([['all','All'],['online','Online'],...], AGENT_FILTER, 'setAgentFilter', c)
```

**`indirect_variable` (needs tracing to its own assignment) — L9370, `openCampaignLaunch`:**
```js
typeSel.innerHTML = opts;
```

## Recommended next step

Per groupG.txt's own staged plan (G1a → G1b → G1c → G1d) and the explicit instruction not to do a blind transformation: the next decision is scoping **G1a** (canonicalize the one `escapeHTML()`, eliminate the four duplicate/inconsistent escapers, convert the 12 `unescaped_text` sinks to `textContent`, and fix the 95 `unescaped_html` + relevant slice of the 44 `partial_escaped` sinks) as its own bounded implementation pass — tracing the 27 `indirect_builder` + 27 `indirect_variable` sinks first, since some of the `unescaped_html`/`partial_escaped` counts may collapse further once those are resolved (as happened during this inventory's own build — three real false-positive classes were found and fixed by tracing into builder functions and `.map().join()` chains instead of treating them as opaque).
