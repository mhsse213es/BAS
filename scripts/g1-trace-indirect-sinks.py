"""
G1 phase 2: resolve the 54 indirect_builder/indirect_variable sinks from the
baseline inventory (security/g1/G1_INNERHTML_SINK_INVENTORY.csv) by tracing
each to its actual value construction, then reclassifying using the same
tokenizer/classifier as the baseline script.

Correctness note this script exists to handle: several helper names used
across this file (`tile`, `row`, `list`, `fmt`, ...) are declared multiple
times as *separate local closures* inside different outer functions (e.g.
`tile` has 5 distinct `var tile = function(...)` declarations in 5
different enclosing functions). A naive "search the whole file for the
first declaration with this name" resolver picks the wrong one whenever a
name is reused. This script instead builds the full tree of function body
spans in one pass (comment/string/regex-aware, so a "function" mentioned
in a comment never creates a false span) and resolves every lookup by
*lexical scope containment* -- walking from the sink's own innermost
enclosing function outward through its ancestors, exactly how a JS engine
would resolve the name -- rather than by text proximity.

For indirect_builder (e.g. `tile('x', n, color)`): resolve `tile` by scope
chain from the sink's position, extract the resolved function's body,
find every top-level `return <expr>;` inside it, classify each.

For indirect_variable (e.g. `sel.innerHTML = opts;`): find the sink's own
innermost enclosing function span by position (not by name), find every
assignment to that variable name within that exact body, classify each
RHS. If no assignment is found, the variable is very likely a function
parameter -- flagged for a caller-level trace rather than guessed at.

Usage: python scripts/g1-trace-indirect-sinks.py
Output: security/g1/G1_INDIRECT_SINK_TRACE.csv + prints a summary.
"""
import csv
import importlib.util
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_CSV = REPO_ROOT / "security" / "g1" / "G1_INNERHTML_SINK_INVENTORY.csv"
OUT_CSV = REPO_ROOT / "security" / "g1" / "G1_INDIRECT_SINK_TRACE.csv"

spec = importlib.util.spec_from_file_location(
    "g1_classifier", REPO_ROOT / "scripts" / "g1-innerhtml-sink-classifier.py"
)
clf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clf)

text = clf.text
N = len(text)

def skip_string(text, i):
    q = text[i]
    j = i + 1
    nn = len(text)
    while j < nn:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == q:
            j += 1
            break
        j += 1
    return j

def find_matching_paren(text, open_pos):
    i = open_pos
    nn = len(text)
    depth = 0
    while i < nn:
        c = text[i]
        nc = clf.skip_comment(text, i)
        if nc is not None:
            i = nc
            continue
        nr = clf.skip_regex_literal(text, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            i = skip_string(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return nn

def find_matching_brace(text, open_pos):
    i = open_pos
    nn = len(text)
    depth = 0
    while i < nn:
        c = text[i]
        nc = clf.skip_comment(text, i)
        if nc is not None:
            i = nc
            continue
        nr = clf.skip_regex_literal(text, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            i = skip_string(text, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return nn

FN_START_RE = re.compile(
    r"function\s+([A-Za-z_$][\w$]*)\s*\("
    r"|(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\("
    r"|(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*function\s*\("
)

def scan_function_spans(text):
    """One comment/string/regex-aware pass over the whole file: every
    function declaration's (decl_start, body_start, body_end, name),
    including nested ones. A span's body_start/body_end bound the '{'..'}'
    (body_start is just past the '{', body_end is the index of the '}')."""
    spans = []
    i = 0
    nn = len(text)
    in_str = None
    while i < nn:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        nc = clf.skip_comment(text, i)
        if nc is not None:
            i = nc
            continue
        nr = clf.skip_regex_literal(text, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        m = FN_START_RE.match(text, i)
        if m:
            name = m.group(1) or m.group(2) or m.group(3)
            paren_start = m.end() - 1  # the '(' the pattern just consumed
            paren_end = find_matching_paren(text, paren_start)
            brace_start = clf.skip_ws(text, paren_end)
            if brace_start < nn and text[brace_start] == "{":
                brace_end = find_matching_brace(text, brace_start)
                spans.append((m.start(), brace_start + 1, brace_end, name))
                i = brace_start + 1
                continue
        i += 1
    return spans

SPANS = scan_function_spans(text)

def ancestor_chain(pos):
    """Spans containing pos, innermost first."""
    containing = [s for s in SPANS if s[1] <= pos <= s[2]]
    return sorted(containing, key=lambda s: s[2] - s[1])

def innermost_enclosing(pos):
    chain = ancestor_chain(pos)
    return chain[0] if chain else None

def resolve_call_target(pos, name):
    """Resolve which declaration of `name` a call at `pos` refers to, by
    walking pos's ancestor scopes from innermost to outermost and
    preferring a declaration of `name` found inside that ancestor's own
    body (this mirrors JS scope-chain lookup: a local `var tile =
    function(){}` inside the directly-enclosing function shadows any
    same-named declaration in an outer or sibling scope)."""
    candidates = [s for s in SPANS if s[3] == name]
    if not candidates:
        return None
    for anc in ancestor_chain(pos):
        for cand in candidates:
            if anc[1] <= cand[0] <= anc[2]:
                return cand
    # no ancestor has a local declaration -- prefer a module/top-level one
    # (a candidate with no enclosing span of its own)
    for cand in candidates:
        if not ancestor_chain(cand[0]):
            return cand
    return candidates[0]

_JS_BUILTINS = {
    "if", "for", "while", "function", "return", "switch", "catch", "else",
    "Math", "JSON", "Array", "Object", "Promise", "parseInt", "parseFloat",
    "String", "Number", "Boolean", "isNaN", "encodeURIComponent",
    "decodeURIComponent", "document", "window", "console", "setTimeout",
    "setInterval", "Date", "RegExp", "Map", "Set",
}

def extract_call_names(expr):
    names = set()
    for m in re.finditer(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(", expr):
        name = m.group(1)
        if name not in _JS_BUILTINS and name not in clf.ESCAPER_NAMES:
            names.add(name)
    return names

def trace_builder(sink_pos, rhs):
    names = extract_call_names(rhs)
    if not names:
        return "unclear", "no callable name found in rhs"
    results = []
    notes = []
    for name in sorted(names):
        target = resolve_call_target(sink_pos, name)
        if target is None:
            notes.append(f"{name}(): no declaration found anywhere in file")
            results.append("unclear")
            continue
        decl_start, body_start, body_end, _ = target
        body = text[body_start:body_end]
        def_line = clf.line_of(decl_start)
        rets = clf.extract_return_exprs(body)
        if not rets:
            notes.append(f"{name}() @L{def_line} (scope-resolved): no return statement found")
            results.append("unclear")
            continue
        sub_cats = [clf.classify_expr(r) for r in rets]
        combined = sub_cats[0]
        for sc in sub_cats[1:]:
            combined = clf._combine(combined, sc)
        notes.append(f"{name}() @L{def_line} (scope-resolved): {len(rets)} return(s) -> {combined}")
        results.append(combined)
    final = results[0]
    for r in results[1:]:
        final = clf._combine(final, r)
    return final, "; ".join(notes)

def trace_variable(sink_pos, varname):
    enclosing = innermost_enclosing(sink_pos)
    if enclosing is None:
        return "unclear", "sink is at module scope; not traced by this pass"
    decl_start, body_start, body_end, fn_name = enclosing
    body = text[body_start:body_end]
    def_line = clf.line_of(decl_start)
    assign_re = re.compile(r"(?<![.\w$])" + re.escape(varname) + r"\s*(\+=|=)(?!=)")
    assigns = []
    i = 0
    in_str = None
    while i < len(body):
        c = body[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        nc = clf.skip_comment(body, i)
        if nc is not None:
            i = nc
            continue
        nr = clf.skip_regex_literal(body, i)
        if nr is not None:
            i = nr
            continue
        if c in "'\"`":
            in_str = c
            i += 1
            continue
        m = assign_re.match(body, i)
        if m:
            rhs_start = clf.skip_ws(body, m.end())
            rhs_end = clf.find_rhs_end(body, rhs_start)
            rhs = body[rhs_start:rhs_end].strip()
            if rhs:
                assigns.append(rhs)
            i = rhs_end
            continue
        i += 1
    if not assigns:
        return "unclear", (f"no assignment to '{varname}' found inside its real enclosing "
                            f"function ({fn_name}() @L{def_line}, scope-resolved by position) -- "
                            f"likely a function parameter, needs a caller-level trace")
    sub_cats = [clf.classify_expr(a) for a in assigns]
    combined = sub_cats[0]
    for sc in sub_cats[1:]:
        combined = clf._combine(combined, sc)
    return combined, f"{len(assigns)} assignment(s) to '{varname}' inside {fn_name}() @L{def_line} (scope-resolved) -> {combined}"

def find_sink_position(lineno, target, op):
    """Re-locate the exact absolute position of a baseline-CSV sink (it
    only stores a line number) by re-running SINK_RE and matching on line
    + LHS text, so tracing works from the real position, not an
    approximation from the line start."""
    for m in clf.SINK_RE.finditer(text):
        if clf.line_of(m.start()) == lineno and m.group(1) == op:
            lhs_start = clf.find_lhs_start(text, m.start())
            lhs = text[lhs_start:m.start()].strip()
            if lhs == target:
                return m.start()
    return None

def main():
    rows = list(csv.DictReader(BASELINE_CSV.open(encoding="utf-8")))
    out_rows = []
    unresolved_positions = 0
    for r in rows:
        if r["category"] not in ("indirect_builder", "indirect_variable"):
            continue
        lineno = int(r["line"])
        pos = find_sink_position(lineno, r["target"], r["op"])
        if pos is None:
            unresolved_positions += 1
            out_rows.append({
                "line": r["line"], "function": r["function"],
                "original_category": r["category"], "resolved_category": "unclear",
                "notes": "could not re-locate this sink's exact position in the file (CSV/source drift?)",
                "rhs": r["rhs"][:200],
            })
            continue
        if r["category"] == "indirect_builder":
            resolved, notes = trace_builder(pos, r["rhs"])
        else:
            varname = r["rhs"].strip()
            resolved, notes = trace_variable(pos, varname)
        out_rows.append({
            "line": r["line"],
            "function": r["function"],
            "original_category": r["category"],
            "resolved_category": resolved,
            "notes": notes,
            "rhs": r["rhs"][:200],
        })

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["line", "function", "original_category", "resolved_category", "notes", "rhs"])
        w.writeheader()
        for row in out_rows:
            w.writerow(row)

    from collections import Counter
    print(f"TRACED {len(out_rows)} indirect sinks ({unresolved_positions} position-lookup failures)")
    for cat, cnt in Counter(r["resolved_category"] for r in out_rows).most_common():
        print(f"  {cat}: {cnt}")

if __name__ == "__main__":
    main()
