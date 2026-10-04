"""
G1 (groupG.txt) inventory builder: finds every `X.innerHTML = ...;` /
`X.innerHTML += ...;` sink in orchestrator/wwwroot/index.html, extracts the
LHS target and RHS expression with a small hand-rolled tokenizer (handles
multi-line concatenation, backtick templates, nested ternaries, .map()/
.filter() callback bodies, JS comments, and regex literals -- all four of
which corrupt a naive quote-counting scan, see the skip_comment/
skip_regex_literal docstrings below for real examples this file hit), and
classifies each sink per the categories in groupG.txt:

  static            - RHS is purely string literal(s) concatenated together,
                       no interpolation at all.
  static_empty      - special case of static: RHS is just '' or "" (a clear).
  escaped           - RHS has interpolated ("dynamic") parts and every one of
                       them is wrapped in a known escaper call (x(), escHtml(),
                       escapeHTML()-family), or is a ternary/.map().join()
                       chain whose branches resolve to escaped/static content.
  partial_escaped   - RHS has multiple dynamic parts, some escaped, some not.
  unescaped_text    - RHS has unescaped dynamic part(s) that look like free-form
                       data (message/name/description/etc) AND the surrounding
                       static template has no HTML tags -> strong textContent
                       candidate, currently built as a string instead.
  unescaped_html    - same as above but the surrounding static template DOES
                       contain HTML tags (e.g. '<div>' + x + '</div>') -> a
                       genuine dynamic-HTML sink that needs the interpolated
                       value escaped.
  unescaped_likely_safe - unescaped dynamic part(s) that are clearly numeric/
                       boolean/computed (length, Math.*, counts, ternaries
                       with fixed-string branches) - still flagged, lower
                       priority.
  indirect_builder  - RHS is (partly) a bare call to a helper function whose
                       internals this script doesn't trace (e.g. covSegHtml(),
                       tile(), _apStep()) - groupG.txt's own "Unclear - manual
                       review - do not modify automatically" bucket.
  indirect_variable - RHS is a single bare variable/property chain built
                       elsewhere (e.g. `sel.innerHTML = opts;`) - same bucket,
                       needs tracing to that variable's own assignment.
  unclear           - anything else the heuristics can't confidently place.

This is a heuristic triage tool to produce real category counts before any
code is touched, not a perfect static analyzer - "indirect_builder"/
"indirect_variable"/"unclear" are deliberately conservative buckets rather
than forced guesses. See Assessment/G1_INNERHTML_SINK_INVENTORY_SUMMARY.md
for the write-up of a run's results.

Usage: python scripts/g1-innerhtml-sink-classifier.py
Output: Assessment/G1_INNERHTML_SINK_INVENTORY.csv (+ .json), and a category
count summary printed to stdout.
"""
import csv
import json
import re
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "orchestrator" / "wwwroot" / "index.html"
OUT_CSV = REPO_ROOT / "Assessment" / "G1_INNERHTML_SINK_INVENTORY.csv"
OUT_JSON = REPO_ROOT / "Assessment" / "G1_INNERHTML_SINK_INVENTORY.json"

text = SRC.read_text(encoding="utf-8")
lines = text.split("\n")
# line_starts[i] = absolute char offset of the start of line i (0-indexed)
line_starts = [0]
for ln in lines:
    line_starts.append(line_starts[-1] + len(ln) + 1)

def line_of(pos):
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1  # 1-indexed

ESCAPER_NAMES = {"x", "escHtml", "escapeHTML", "escapeHtml", "esc"}

SINK_RE = re.compile(r"\.innerHTML\s*(\+=|=)(?!=)")

def find_lhs_start(text, match_start):
    """Scan backward from the '.innerHTML' dot to find where the LHS
    expression begins: either a statement boundary (; { } at depth 0) or
    the start of the line."""
    i = match_start
    depth = 0  # paren/bracket depth, incremented going backward on ) ]
    while i > 0:
        c = text[i - 1]
        if c in ")]":
            depth += 1
        elif c in "([":
            depth -= 1
            if depth < 0:
                break
        elif depth == 0 and c in ";{}":
            break
        elif depth == 0 and c == "\n" and (i < 2 or text[i - 2] not in ",+(&|?:="):
            break
        i -= 1
    return i

def skip_ws(text, i, forward=True):
    if forward:
        while i < len(text) and text[i] in " \t\n\r":
            i += 1
    else:
        while i > 0 and text[i - 1] in " \t\n\r":
            i -= 1
    return i

def skip_comment(text, i):
    """If text[i:] starts a '//' or '/* */' comment, return the index just
    past it; otherwise return None. MUST be checked before any quote-start
    check in every forward scanner below -- an apostrophe inside an
    English-prose comment ("doesn't", "that's") would otherwise be misread
    as the start of a real string literal and corrupt every depth/quote/
    semicolon decision for the rest of the scan. Confirmed real impact in
    this file: comments like "// A previously-checked agent that's now
    incompatible" sit directly inside innerHTML sinks' RHS spans."""
    n = len(text)
    if i + 1 < n and text[i] == "/" and text[i + 1] == "/":
        nl = text.find("\n", i)
        return n if nl == -1 else nl
    if i + 1 < n and text[i] == "/" and text[i + 1] == "*":
        end = text.find("*/", i + 2)
        return n if end == -1 else end + 2
    return None

_REGEX_PREV_OK = set("(,=:;{[!&|?+-*%<>~^")
_REGEX_PREV_KEYWORDS = {"return", "typeof", "in", "of", "new", "delete", "void",
                         "throw", "case", "instanceof", "do", "else", "yield"}

def _looks_like_regex_start(text, i):
    """Decide '/' is a regex-literal delimiter, not a division operator, by
    looking at the last significant character before it (division follows
    an identifier/number/')'/']'/'}'; a regex literal follows an operator,
    '(', ',', ';', '{', or a keyword like return/typeof/case)."""
    j = i - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return True
    pc = text[j]
    if pc in _REGEX_PREV_OK:
        return True
    if pc in ")]}" or pc.isalnum() or pc in "_$":
        k = j
        while k >= 0 and (text[k].isalnum() or text[k] in "_$"):
            k -= 1
        word = text[k + 1:j + 1]
        return word in _REGEX_PREV_KEYWORDS
    return True

def skip_regex_literal(text, i):
    """If text[i] is a regex-literal '/' (not division, not // or /* comment
    start), scan past /pattern/flags -- honoring \\-escapes and [...]
    character classes, where an unescaped '/' is NOT a terminator -- and
    return the index just past the trailing flag letters. Returns None if
    this isn't a regex literal, or if no closing '/' is found before a
    newline. Confirmed real impact: `.replace(/'/g, "&#39;")` -- a common
    quote-escaping idiom in this file -- contains a bare `'` inside the
    regex pattern that, left unhandled, derailed the whole-file scan (one
    sink's captured RHS ran all the way to EOF, 31KB past its real end,
    before this fix)."""
    n = len(text)
    if text[i] != "/" or i + 1 >= n or text[i + 1] in ("/", "*"):
        return None
    if not _looks_like_regex_start(text, i):
        return None
    j = i + 1
    in_class = False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return None
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            break
        j += 1
    else:
        return None
    while j < n and text[j].isalpha():
        j += 1
    return j

def find_rhs_end(text, rhs_start):
    """Scan forward from just after the '=' / '+=' to find the end of the
    assignment statement (top-level ';'), tracking string/backtick state and
    paren/bracket/brace depth so semicolons inside strings or nested
    function-literal bodies don't terminate early."""
    i = rhs_start
    n = len(text)
    depth = 0
    in_str = None  # None | "'" | '"' | '`'
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        nc = skip_comment(text, i)
        if nc is not None:
            i = nc
            continue
        nr = skip_regex_literal(text, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return i
        elif c == ";" and depth == 0:
            return i
        i += 1
    return i

def is_pure_string_literal(term):
    term = term.strip()
    if len(term) < 2:
        return False
    if term[0] in "'\"" and term[-1] == term[0]:
        return True
    if term[0] == "`" and term[-1] == "`" and "${" not in term:
        return True
    return False

def mask_strings_keep_templates(rhs):
    """Return (skeleton, holes) where skeleton has every plain-quoted string
    literal's content removed (quotes kept as markers) and every backtick
    template literal's static text removed, while ${...} interiors and all
    non-string code are preserved. `holes` is the list of top-level
    (paren-depth 0) '+'-separated terms that are NOT pure string literals,
    plus every ${...} interior found inside backticks."""
    n = len(rhs)
    i = 0
    skeleton_chars = []
    holes = []
    cur_term_start = 0
    depth = 0

    def flush_term(end):
        term = rhs[cur_term_start:end].strip()
        if term and not is_pure_string_literal(term):
            holes.append(term)

    while i < n:
        c = rhs[i]
        nc = skip_comment(rhs, i)
        if nc is not None:
            skeleton_chars.append(rhs[i:nc])
            i = nc
            continue
        nr = skip_regex_literal(rhs, i)
        if nr is not None:
            skeleton_chars.append(rhs[i:nr])
            i = nr
            continue
        if c in "'\"":
            q = c
            j = i + 1
            while j < n:
                if rhs[j] == "\\":
                    j += 2
                    continue
                if rhs[j] == q:
                    j += 1
                    break
                j += 1
            skeleton_chars.append(q + q)
            i = j
            continue
        if c == "`":
            j = i + 1
            while j < n and rhs[j] != "`":
                if rhs[j] == "\\":
                    j += 2
                    continue
                if rhs[j] == "$" and j + 1 < n and rhs[j + 1] == "{":
                    k = j + 2
                    bd = 1
                    while k < n and bd > 0:
                        if rhs[k] == "{":
                            bd += 1
                        elif rhs[k] == "}":
                            bd -= 1
                        k += 1
                    inner = rhs[j + 2:k - 1].strip()
                    if inner:
                        holes.append(inner)
                    skeleton_chars.append("(" + inner + ")")
                    j = k
                    continue
                j += 1
            if j < n:
                j += 1
            skeleton_chars.append("``")
            i = j
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "+" and depth == 0:
            flush_term(i)
            cur_term_start = i + 1
        skeleton_chars.append(c)
        i += 1
    flush_term(n)
    return "".join(skeleton_chars), holes

def static_literal_text(rhs):
    """Concatenate all plain quoted-string contents in rhs (used to check
    whether the STATIC parts of the template contain an HTML tag)."""
    out = []
    n = len(rhs)
    i = 0
    while i < n:
        c = rhs[i]
        nc = skip_comment(rhs, i)
        if nc is not None:
            i = nc
            continue
        nr = skip_regex_literal(rhs, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"":
            q = c
            j = i + 1
            buf = []
            while j < n:
                if rhs[j] == "\\":
                    buf.append(rhs[j:j + 2])
                    j += 2
                    continue
                if rhs[j] == q:
                    j += 1
                    break
                buf.append(rhs[j])
                j += 1
            out.append("".join(buf))
            i = j
            continue
        if c == "`":
            j = i + 1
            buf = []
            while j < n and rhs[j] != "`":
                if rhs[j] == "\\":
                    j += 2
                    continue
                if rhs[j] == "$" and j + 1 < n and rhs[j + 1] == "{":
                    k = j + 2
                    bd = 1
                    while k < n and bd > 0:
                        if rhs[k] == "{":
                            bd += 1
                        elif rhs[k] == "}":
                            bd -= 1
                        k += 1
                    j = k
                    continue
                buf.append(rhs[j])
                j += 1
            if j < n:
                j += 1
            out.append("".join(buf))
            i = j
            continue
        i += 1
    return "".join(out)

ESCAPER_CALL_RE = re.compile(r"^(?:" + "|".join(ESCAPER_NAMES) + r")\s*\(.*\)$", re.DOTALL)
SAFE_NUMERIC_RE = re.compile(
    r"\.length\b|Math\.\w+\(|\btoFixed\(|\bFloor\(|\bRound\(|\bCeil\("
    r"|^[A-Za-z_$][\w.$]*\s*[<>]=?\s*\d|^\d|^!!|^true$|^false$",
    re.IGNORECASE | re.DOTALL,
)
BUILDER_CALL_RE = re.compile(r"^[A-Za-z_$][\w$]*\s*\(.*\)$", re.DOTALL)
BARE_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])*$")

def strip_enclosing_parens(expr):
    """Strip one or more layers of fully-wrapping, redundant parens, e.g.
    `(changed ? 'a' : 'b')` -> `changed ? 'a' : 'b'`. Without this,
    find_ternary_split below hits the wrapping '(' first, raises depth to 1,
    and never sees the '?' at depth 0 -- so a ternary written with a
    (harmless, common) wrapping paren around it is invisible to the
    classifier, which then treats the whole parenthesized blob as one
    opaque unescaped hole. Confirmed real impact: `_diffSecretRow()` (fully
    escaped via x(label), both ternary branches pure static strings) was
    misclassified partial_escaped purely because of this wrapping paren."""
    e = expr.strip()
    while e.startswith("(") and e.endswith(")"):
        depth = 0
        in_str = None
        nn = len(e)
        matched_at_end = False
        i = 0
        while i < nn:
            c = e[i]
            if in_str:
                if c == "\\":
                    i += 2
                    continue
                if c == in_str:
                    in_str = None
                i += 1
                continue
            nc = skip_comment(e, i)
            if nc is not None:
                i = nc
                continue
            nr = skip_regex_literal(e, i)
            if nr is not None:
                i = nr
                continue
            if c in "'\"`":
                in_str = c
                i += 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    matched_at_end = (i == nn - 1)
                    break
            i += 1
        if not matched_at_end:
            break
        e = e[1:-1].strip()
    return e

def find_ternary_split(expr):
    """Find a top-level (depth-0, outside strings/comments/regex) `cond ? a
    : b`, after stripping any fully-wrapping redundant parens. Returns
    (cond, true_branch, false_branch) or None. Skips `?.` and `??`. Handles
    nested ternaries in the false branch (a ? b : c ? d : e) via a
    ternary-nesting counter."""
    expr = strip_enclosing_parens(expr)
    n = len(expr)
    i = 0
    depth = 0
    in_str = None
    q_pos = None
    while i < n:
        c = expr[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        nc = skip_comment(expr, i)
        if nc is not None:
            i = nc
            continue
        nr = skip_regex_literal(expr, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "?" and depth == 0:
            nxt = expr[i + 1] if i + 1 < n else ""
            if nxt not in (".", "?"):
                q_pos = i
                break
        i += 1
    if q_pos is None:
        return None
    i = q_pos + 1
    depth = 0
    tdepth = 1
    in_str = None
    c_pos = None
    while i < n:
        c = expr[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        nc = skip_comment(expr, i)
        if nc is not None:
            i = nc
            continue
        nr = skip_regex_literal(expr, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == "?":
            nxt = expr[i + 1] if i + 1 < n else ""
            if nxt not in (".", "?"):
                tdepth += 1
        elif depth == 0 and c == ":":
            tdepth -= 1
            if tdepth == 0:
                c_pos = i
                break
        i += 1
    if c_pos is None:
        return None
    return expr[:q_pos], expr[q_pos + 1:c_pos], expr[c_pos + 1:]

FUNC_DEF_RE = re.compile(
    r"^\s*function\s+([A-Za-z_$][\w$]*)\s*\("
    r"|^\s*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\("
    r"|^\s*(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
)

def enclosing_function(lineno):
    for ln in range(lineno - 1, max(lineno - 4000, -1), -1):
        m = FUNC_DEF_RE.match(lines[ln])
        if m:
            name = m.group(1) or m.group(2) or m.group(3)
            if name:
                return name
    return "(module scope)"

def extract_return_exprs(expr):
    """Find every `return <expr>;` inside expr (e.g. inside a .map/.filter
    callback literal passed as part of this hole) and return the list of
    returned expressions, so classify_hole can see through
    `arr.map(function(x){ return '<li>'+x(x.name)+'</li>'; }).join('')`
    instead of treating the whole chain as one opaque unescaped blob."""
    results = []
    i = 0
    n = len(expr)
    in_str = None
    while i < n:
        c = expr[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        nc = skip_comment(expr, i)
        if nc is not None:
            i = nc
            continue
        nr = skip_regex_literal(expr, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        if expr[i:i + 6] == "return" and (i == 0 or not (expr[i - 1].isalnum() or expr[i - 1] == "_")) \
                and (i + 6 >= n or not (expr[i + 6].isalnum() or expr[i + 6] == "_")):
            j = skip_ws(expr, i + 6)
            end = find_rhs_end(expr, j)
            ret_expr = expr[j:end].strip()
            if ret_expr:
                results.append(ret_expr)
            i = end
            continue
        i += 1
    return results

# Risk ranking for combining branches of a ternary / return-set: lower index
# = reported preferentially (more deserving of attention / more specific).
_RANK = ["unescaped_html", "unescaped_text", "partial_escaped", "unclear",
         "indirect_variable", "indirect_builder", "unescaped_likely_safe",
         "escaped", "static", "static_empty"]
_SAFE_COMBINED = {"escaped", "static", "static_empty"}
_INDIRECT_COMBINED = {"indirect_builder", "indirect_variable"}

def _combine(a, b):
    return a if _RANK.index(a) <= _RANK.index(b) else b

def classify_hole(h):
    h = h.strip()
    if ESCAPER_CALL_RE.match(h):
        return "escaped"
    # A ternary nested inside this +-term, e.g. (cond ? '<span>'+x(v)+'</span>' : ''),
    # isn't the whole RHS so classify_expr's own ternary-split never sees it -
    # recurse into just the two branches (never into h itself, to avoid
    # looping back into this same classify_hole call). This MUST run before
    # the SAFE_NUMERIC_RE check below: SAFE_NUMERIC_RE.search() matches a
    # substring anywhere in h, so a ternary whose *condition* merely
    # contains `.length` (e.g. `(tags.length ? '<div>'+riskyStuff+'</div>' :
    # '')`) would otherwise be waved through as "likely_safe" without the
    # branches -- which are what actually renders -- ever being inspected.
    # Confirmed real impact: this exact shape hid a genuine unescaped
    # dynamic-HTML branch behind a `.length` condition check.
    tern = find_ternary_split(h)
    if tern is not None:
        _, t_branch, f_branch = tern
        combined = _combine(classify_expr(t_branch), classify_expr(f_branch))
        return _hole_verdict(combined)
    # Likewise, a `return <expr>;` nested inside this hole (e.g. a .map()
    # callback literal) MUST be resolved before the SAFE_NUMERIC_RE
    # substring check below: that check scans the WHOLE hole text for
    # things like ".length" anywhere at all, so a multi-statement callback
    # whose *unrelated* local variable happens to use `.length` (e.g.
    # `var desc = s.description.length > 90 ? ... : ...;` declared before
    # a fully-escaped `return '<option>'+x(s.id)+...;`) would otherwise be
    # waved through as "likely_safe" without the actual returned/rendered
    # content ever being inspected. Confirmed real impact: exactly this
    # shape hid a fully-escaped sink behind an unrelated `.length` mention.
    rets = extract_return_exprs(h)
    if rets:
        combined = classify_expr(rets[0])
        for r in rets[1:]:
            combined = _combine(combined, classify_expr(r))
        return _hole_verdict(combined)
    if SAFE_NUMERIC_RE.search(h):
        return "likely_safe"
    # A bare top-level call (no leading `.method(` dot) with no inline
    # function literal to trace into is virtually always a call to an
    # app-defined helper, not a builtin -- naming it after "Html" is a
    # convention this codebase doesn't follow consistently (tile(),
    # _apStep(), edKpiCard() build markup too), so any such call gets the
    # same "needs tracing" verdict regardless of its name. (rets is already
    # known empty here, from the check above.)
    if BUILDER_CALL_RE.match(h):
        return "indirect_builder"
    return "unescaped"

def _hole_verdict(combined):
    """Map a full classify_expr-level category down to classify_hole's
    smaller vocabulary ({escaped, likely_safe, indirect_builder,
    unescaped}), used after resolving a hole's nested ternary or return(s)."""
    if combined in _SAFE_COMBINED:
        return "escaped"
    if combined == "unescaped_likely_safe":
        return "likely_safe"
    if combined in _INDIRECT_COMBINED:
        return "indirect_builder"
    return "unescaped"

def classify_expr(expr):
    """Classify one RHS expression (or ternary branch/return value),
    recursing into top-level ternaries so `cond ? escapedBranch : ''`
    doesn't get mis-split by the flat +-concatenation hole scan."""
    expr = expr.strip()
    tern = find_ternary_split(expr)
    if tern is not None:
        _, t_branch, f_branch = tern
        return _combine(classify_expr(t_branch), classify_expr(f_branch))

    _, holes = mask_strings_keep_templates(expr)
    if not holes:
        literal = static_literal_text(expr)
        return "static_empty" if literal.strip() == "" else "static"

    # Whole expression is a single bare identifier/property chain with no
    # string literal anywhere and no function call -> a pass-through
    # variable (e.g. `sel.innerHTML = opts;`) that needs tracing to find
    # where `opts` was built, not a textContent-vs-escape decision we can
    # make from this call site alone. EXCEPT a chain ending in a known-safe
    # accessor like `.length` (SAFE_NUMERIC_RE) -- `p.steps.length` matches
    # BARE_IDENT_RE too (it's just dotted property access), but it isn't a
    # pass-through needing tracing, it's a number. Checking this first
    # matters: without it, every bare `foo.bar.length` ternary branch in
    # the file (a very common shape) was misrouted into indirect_variable
    # instead of being recognized as safe, which cascaded into inflated
    # partial_escaped/unescaped counts for sinks that were actually fine.
    if len(holes) == 1 and holes[0].strip() == expr and BARE_IDENT_RE.match(expr) and "(" not in expr:
        if SAFE_NUMERIC_RE.search(expr):
            return "unescaped_likely_safe"
        return "indirect_variable"

    hole_classes = [classify_hole(h) for h in holes]
    static_text = static_literal_text(expr)
    has_html_tag = bool(re.search(r"<[a-zA-Z][^>]*>|<\/[a-zA-Z]+>", static_text))

    if all(hc == "escaped" for hc in hole_classes):
        return "escaped"
    if all(hc == "likely_safe" for hc in hole_classes):
        return "unescaped_likely_safe"
    if all(hc in ("escaped", "likely_safe") for hc in hole_classes):
        # a mix of properly-escaped and safely-numeric/computed holes, no
        # actually-unescaped or unresolved ones -- fully safe, not "unclear"
        return "escaped"

    escaped_n = sum(1 for hc in hole_classes if hc == "escaped")
    unescaped_n = sum(1 for hc in hole_classes if hc == "unescaped")
    builder_n = sum(1 for hc in hole_classes if hc == "indirect_builder")
    if builder_n > 0 and (escaped_n > 0 or unescaped_n > 0):
        return "partial_escaped"
    if builder_n > 0:
        return "indirect_builder"
    if escaped_n > 0 and unescaped_n > 0:
        return "partial_escaped"
    if unescaped_n > 0:
        return "unescaped_html" if has_html_tag else "unescaped_text"
    return "unclear"

DATA_SOURCE_PATTERNS = [
    ("agent", r"\bagent\w*\.|\bagentId\b|\bhostname\b"),
    ("scenario", r"\bscenario\w*\."),
    ("actor", r"\bactor\w*\."),
    ("openaev", r"openaev|OpenAEV"),
    ("error_message", r"\.message\b|\berr(?:or)?\.|\be\.message\b"),
    ("telemetry_log", r"\btelemetry\b|\blog\w*\."),
    ("api_response", r"\bres(?:ult)?\.|\bresp\.|\bdata\."),
    ("threat_intel", r"\bthreat\w*\.|\bttp\b|\bmitre\b|\bT\d{4}\b"),
    ("url_query", r"location\.|URLSearchParams|\bquery\b|\bparams\."),
    ("user_created_name", r"\.name\b|\.title\b|\.description\b|\.username\b"),
]

def tag_data_sources(rhs):
    return ",".join(name for name, pat in DATA_SOURCE_PATTERNS if re.search(pat, rhs))

def main():
    records = []
    for m in SINK_RE.finditer(text):
        op = m.group(1)
        lhs_start = find_lhs_start(text, m.start())
        lhs = text[lhs_start:m.start()].strip()
        rhs_start = skip_ws(text, m.end())
        rhs_end = find_rhs_end(text, rhs_start)
        rhs = text[rhs_start:rhs_end].strip()
        lineno = line_of(m.start())
        func = enclosing_function(lineno)
        category = classify_expr(rhs)
        tags = tag_data_sources(rhs)
        records.append({
            "line": lineno,
            "function": func,
            "target": lhs,
            "op": op,
            "rhs": rhs[:400],
            "rhs_len": len(rhs),
            "category": category,
            "data_source_tags": tags,
        })

    records.sort(key=lambda r: r["line"])

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["line", "function", "target", "op", "category", "data_source_tags", "rhs_len", "rhs"])
        w.writeheader()
        for r in records:
            w.writerow(r)

    OUT_JSON.write_text(json.dumps(records, indent=1), encoding="utf-8")

    cat_counts = Counter(r["category"] for r in records)
    print(f"TOTAL SINKS: {len(records)}")
    for cat, n in cat_counts.most_common():
        print(f"  {cat}: {n}")

if __name__ == "__main__":
    main()
