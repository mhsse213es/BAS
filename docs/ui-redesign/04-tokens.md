# Design tokens, step 1: zero visual change

Branch `ui-tokens`. New file `orchestrator/web/styles/tokens.css` (first in the `app` layer), plus exact-match adoption in the
existing stylesheets. **Intent: indirection only. No pixel changes.** Consolidating values (the refinement step) is separate,
so any later visual regression can be attributed to it.

## What was added

| Group | Tokens | Values |
|---|---|---|
| Type scale | `--text-xs` `--text-sm` `--text-base` `--text-md` `--text-lg` `--text-display` | 11, 12, 13, 14, 15, 24 px |
| Spacing scale | `--sp-2` `--sp-4` `--sp-6` `--sp-8` `--sp-10` `--sp-12` `--sp-14` `--sp-16` `--sp-20` `--sp-24` `--sp-32` | the same px value as the name |
| Status colours | `--status-{ok,warn,bad,info,muted}-{fg,bg,border}` and `--status-{ok,warn,bad,info,muted}` | aliases of the existing `--success*`, `--warning*`, `--danger*`, `--info-text`, `--accent*` tokens, so all four themes keep working; `muted` uses the literals already in the `.s-retired` rule |

Spacing tokens are named by value on purpose. 6, 10 and 14 px are off a 4 px grid today and keep their values; the refinement step
can remap them in one place.

The status tokens are declared on `body`, not `:root`, because they reference themed tokens and `var()` inside a custom property
resolves where it is declared (same reason `--hero-bg` is on `body`).

## What was adopted

`font-size`, `padding*`, `margin*`, `gap`, `row-gap`, `column-gap` declarations in `styles/*.css` whose px value **exactly** equals
a token value were rewritten to `var(--token)`: **1,278 replacements (268 type, 1,010 spacing)**, plus 3 status-colour literals in the
agent-state badge rules. Not touched: negative margins, `calc()/clamp()/min()/max()`, rem values, `inline-equivalent.css`
(generated), everything in JS (`style="..."` strings are governed by the inline-style ratchet, see G1e).

## Verification

29 views, rich fixtures, frozen clock, animations off, full-page screenshots, compared byte for byte (tools in `token-tools/`).

| Configuration | Result |
|---|---|
| dark 1440 | 29/29 identical to the pre-change baseline |
| cyberpunk 1440 | 29/29 identical |
| slate 1440 | 29/29 identical |
| dark 390 (phone) | 29/29 identical |
| light 1440 | 29/29 identical to a fresh rebuild of untouched `main` |

The light result needs a note. The first light baseline differed from every later light capture by 1,753 pixels in the sidebar logo
(identical on all 29 pages, 94 x 31 px). Rebuilding unmodified `main` and capturing light again also differed from that first
baseline, and matched the tokenised build exactly, so the first light capture was a different render session, not a style change.

Gates unchanged from baseline: unit tests, smoke 2/2; lint 1 error and the g1d inline-style ratchet (838 > 836) are the existing ones.

## What is deliberately NOT covered (input for the refinement step)

Font sizes still off-scale (declaration counts): 0.78rem 57, 12.5px 54, 0.8rem 53, 0.72rem 36, 11.5px 26, 0.82rem 26, 10.5px 24,
0.68rem 24, 0.85rem 18, 0.75rem 18, 0.7rem 15, 0.66rem 8, 0.9rem 7, 0.65rem 7. That is 15 distinct sizes between 10 and 15 px
where a scale would normally have about 6. Half-pixel sizes (10.5, 11.5, 12.5) and rem sizes that round to the same pixels are the
first candidates to merge.

Spacing values outside the scale: 18 px (33), 9 px (22), 3 px (22), 7 px (18), 22 px (14), 5 px (11), 28 px (7), 40 px (4).

Colours: not touched in this step. Known follow-ups: three reds (`#f85149`, `#da3633`, `#ef4444`) and three ambers in JS; none of
the status tokens above are adopted by feature CSS yet beyond the badge rules.

## Next

Refinement is a separate change with its own before/after diff: decide the final scale, remap, and review the resulting visual
differences page by page. Needs a design direction first.
