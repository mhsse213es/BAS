#!/usr/bin/env python3
"""CI regression guard for G1's XSS-sink classification.

Compares the current security/g1/G1_FINAL_CLASSIFICATION.json against a
--against baseline JSON (the base branch's committed version, or the
literal content "{}" if none exists yet) and fails when a
(function, target, op) "slot" that existed in the baseline has gotten
more dangerous. A slot that disappears is OK (sink eliminated). A slot
that's brand new is reported, never auto-failed -- G1a's own finding was
that unescaped_html is sometimes fine once a human reads it (126 of 455
sinks are exactly that, already accepted), so failing every new sink at
a tier 126 existing ones already sit at would repeat that mistake.

Also runs the canonical-escaper check: exactly one function in
orchestrator/wwwroot/index.html must implement the &/</>/" substitutions,
and that one function must not also escape a bare '.
"""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CURRENT_JSON = REPO_ROOT / "security" / "g1" / "G1_FINAL_CLASSIFICATION.json"


def load_json(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if data:
            raise ValueError(f"{path}: expected a JSON array of sinks or {{}}, got a non-empty object")
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of sinks or {{}}")
    return data


def slot_key(sink):
    return (sink["function"], sink["target"], sink["op"])


def _group_by_slot(sinks):
    out = {}
    for s in sinks:
        out.setdefault(slot_key(s), []).append(s)
    return out


def compare_slots(old_sinks, new_sinks):
    """Returns (regressions, eliminated, new_sinks):
      regressions: [(slot, old_tier, new_tier), ...] -- a changed sink got worse
      eliminated:  [(slot, old_max_tier), ...] -- the slot no longer exists
      new_sinks:   [(slot, tier, final_category, sink_id), ...] -- added sinks,
                   in new or existing slots; reported, never failed

    Within a slot, sinks with the same sink_id and tier are matched and ignored.
    The remaining (changed) sinks are paired charitably -- the highest old
    tiers against the lowest new tiers -- so an edit that keeps or lowers
    severity never fails, while a sink rewritten to something worse does,
    even when a sibling already holds the slot's top tier. New sinks beyond
    the pairing count are additions, which the spec reports but never fails.
    """
    old_by_slot = _group_by_slot(old_sinks)
    new_by_slot = _group_by_slot(new_sinks)

    regressions = []
    eliminated = []
    added = []

    for slot, olds in old_by_slot.items():
        if slot not in new_by_slot:
            eliminated.append((slot, max(s["severity_tier"] for s in olds)))

    for slot, news in new_by_slot.items():
        olds = list(old_by_slot.get(slot, []))
        changed_new = []
        for s in news:
            match = next(
                (o for o in olds
                 if o["sink_id"] == s["sink_id"] and o["severity_tier"] == s["severity_tier"]),
                None,
            )
            if match is not None:
                olds.remove(match)
            else:
                changed_new.append(s)

        old_tiers = sorted((o["severity_tier"] for o in olds), reverse=True)
        changed_new.sort(key=lambda s: (s["severity_tier"], s["sink_id"]))
        k = min(len(old_tiers), len(changed_new))

        paired_new = sorted((s["severity_tier"] for s in changed_new[:k]), reverse=True)
        for old_tier, new_tier in zip(old_tiers[:k], paired_new):
            if new_tier > old_tier:
                regressions.append((slot, old_tier, new_tier))

        for s in changed_new[k:]:
            added.append((slot, s["severity_tier"], s["final_category"], s["sink_id"]))

    return regressions, eliminated, added


def find_rhs_changes(old_sinks, new_sinks):
    """Same slot, RHS changed, tier unchanged: never a failure, always shown.
    A changed RHS can change data provenance (e.g. an internal value becoming
    user-controlled state) without changing the tier, so a reviewer must see
    it (G1c spec section 8). Pairs the unmatched sinks of each slot exactly
    like compare_slots does and reports the pairs whose tiers are equal."""
    out = []
    old_by_slot = _group_by_slot(old_sinks)
    for slot, news in _group_by_slot(new_sinks).items():
        olds = list(old_by_slot.get(slot, []))
        changed_new = []
        for s in news:
            match = next((o for o in olds if o["sink_id"] == s["sink_id"] and o["severity_tier"] == s["severity_tier"]), None)
            if match is not None:
                olds.remove(match)
            else:
                changed_new.append(s)
        olds.sort(key=lambda o: (-o["severity_tier"], o["sink_id"]))
        changed_new.sort(key=lambda s: (s["severity_tier"], s["sink_id"]))
        for o, n in zip(olds, changed_new):
            if o["severity_tier"] == n["severity_tier"] and o["sink_id"] != n["sink_id"]:
                out.append((slot, n["severity_tier"], o["sink_id"], n["sink_id"]))
    return sorted(out)


# --- Canonical-escaper check -------------------------------------------
# Duplicated from g1-trace-indirect-sinks.py's scan_function_spans() and
# its helpers, not imported: that module runs
# SPANS = scan_function_spans(text) at true module scope (unguarded by
# if __name__ == "__main__"), so importing it for reuse would re-run the
# whole scan as an unwanted side effect of import. See
# docs/superpowers/specs/2026-10-04-g1b-xss-ci-regression-guard-design.md,
# Architecture section 4.

AMP = re.compile(r"""\.replace\(\s*/&/g\s*,\s*['"]&amp;['"]\s*\)""")
LT = re.compile(r"""\.replace\(\s*/</g\s*,\s*['"]&lt;['"]\s*\)""")
GT = re.compile(r"""\.replace\(\s*/>/g\s*,\s*['"]&gt;['"]\s*\)""")
QUOT = re.compile(r"""\.replace\(\s*/"/g\s*,\s*['"]&quot;['"]\s*\)""")
APOS = re.compile(
    r"""\.replace\(\s*/'/g\s*,\s*['"](&#39;|&apos;|&#x27;)['"]\s*\)""",
    re.IGNORECASE,
)

FN_START_RE = re.compile(
    r"function\s+([A-Za-z_$][\w$]*)\s*\("
    r"|(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\("
    r"|(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*function\s*\("
)


def _skip_string(text, i):
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


def _find_matching_paren(text, open_pos, clf):
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
            i = _skip_string(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return nn


def _find_matching_brace(text, open_pos, clf):
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
            i = _skip_string(text, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return nn


def scan_function_spans(text, clf):
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
            paren_start = m.end() - 1
            paren_end = _find_matching_paren(text, paren_start, clf)
            brace_start = clf.skip_ws(text, paren_end)
            if brace_start < nn and text[brace_start] == "{":
                brace_end = _find_matching_brace(text, brace_start, clf)
                spans.append((m.start(), brace_start + 1, brace_end, name))
                i = brace_start + 1
                continue
        i += 1
    return spans


CANONICAL_ESCAPER = "escapeHTML"
# A replace() over a character class containing both & and < -- the
# map-lookup style of escaper, e.g. s.replace(/[&<>"]/g, fn).
CHAR_CLASS_ESCAPE = re.compile(r"""\.replace\(\s*/\[(?=[^\]\n]*&)(?=[^\]\n]*<)[^\]\n]*\]/g""")
DUPLICATE_WINDOW = 600

_PARAM = r"\(\s*([A-Za-z_$][\w$]*)\s*\)"
_CALL = CANONICAL_ESCAPER + r"\(\s*\1\s*\)"
_BLOCK = r"\{\s*return\s+" + _CALL + r"\s*;?\s*\}"
_EXPR_END = r"(?=[ \t]*(?:[;,})\r\n]|$))"
_DELEGATE_FORMS = [
    re.compile(r"function\s+[\w$]+\s*" + _PARAM + r"\s*" + _BLOCK),
    re.compile(r"[\w$]+\s*[:=]\s*function\s*[\w$]*\s*" + _PARAM + r"\s*" + _BLOCK),
    re.compile(r"[\w$]+\s*[:=]\s*" + _PARAM + r"\s*=>\s*(?:" + _BLOCK + "|" + _CALL + _EXPR_END + ")"),
    re.compile(r"[\w$]+\s*[:=]\s*([A-Za-z_$][\w$]*)\s*=>\s*(?:" + _BLOCK + "|" + _CALL + _EXPR_END + ")"),
    re.compile(r"[\w$]+\s*" + _PARAM + r"\s*" + _BLOCK),
]


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def find_escaper_candidates(text, clf):
    """(name, line, escapes_apostrophe, decl_start, body_start, body_end) for
    every function whose body implements all four canonical substitutions."""
    out = []
    for decl_start, body_start, body_end, name in scan_function_spans(text, clf):
        body = text[body_start:body_end]
        if AMP.search(body) and LT.search(body) and GT.search(body) and QUOT.search(body):
            out.append((name, _line_of(text, decl_start), bool(APOS.search(body)),
                        decl_start, body_start, body_end))
    return out


def _escaper_name_definitions(text, names):
    """(name, start) for each definition of a trusted escaper name: function
    declarations, function/arrow assignments and properties, shorthand
    methods."""
    out = []
    for name in sorted(names):
        n = re.escape(name)
        pat = re.compile(
            r"function\s+" + n + r"\s*\("
            r"|(?<![\w$.])" + n + r"\s*[:=]\s*(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"
            r"|(?<![\w$.])" + n + r"\s*\([^()]*\)\s*\{"
        )
        for m in pat.finditer(text):
            if re.search(r"function\s+$", text[max(0, m.start() - 20):m.start()]):
                continue
            out.append((name, m.start()))
    return out


def _is_delegate(text, start):
    snippet = text[start:start + 300]
    return any(p.match(snippet) for p in _DELEGATE_FORMS)


def check_canonical_escaper(text, clf):
    candidates = find_escaper_candidates(text, clf)
    if len(candidates) == 0:
        return [
            "No function implements all four canonical HTML-escaping "
            "substitutions (& -> &amp;, < -> &lt;, > -> &gt;, \" -> &quot;)."
        ]
    if len(candidates) > 1:
        names = ", ".join(f"{c[0]} (line {c[1]})" for c in candidates)
        return [
            f"{len(candidates)} functions implement the full escaper "
            f"substitution set -- expected exactly one canonical escaper: {names}"
        ]

    name, line, has_apos, decl_start, body_start, body_end = candidates[0]
    if name != CANONICAL_ESCAPER:
        return [
            f"The only function implementing the escaper substitutions is "
            f"{name!r} (line {line}), not {CANONICAL_ESCAPER!r}. The classifier "
            f"counts calls to {sorted(clf.ESCAPER_NAMES)} as escaped, so "
            f"{CANONICAL_ESCAPER} itself must do the escaping."
        ]

    errors = []
    if has_apos:
        errors.append(
            f"Canonical escaper {name!r} (line {line}) now also escapes "
            "a bare ' -- this breaks callers that apply their own "
            "quote-context escaping afterward."
        )

    # Every other definition of a name the classifier trusts must be a pure
    # delegate; otherwise e.g. function x(s){return s;} would turn every
    # x()-escaped sink into real XSS while its classification stays "escaped".
    for alias, start in _escaper_name_definitions(text, clf.ESCAPER_NAMES):
        if alias == CANONICAL_ESCAPER and decl_start <= start < body_start:
            continue
        if not _is_delegate(text, start):
            errors.append(
                f"{alias!r} (line {_line_of(text, start)}) is a trusted escaper "
                f"name but is not a pure `return {CANONICAL_ESCAPER}(arg)` delegate."
            )

    # Duplicate escapers in any syntax (arrow, object method, char-class map)
    # that the function-span scan can't see.
    masked = text[:body_start] + " " * (body_end - body_start) + text[body_end:]
    for m in AMP.finditer(masked):
        window = masked[max(0, m.start() - DUPLICATE_WINDOW):m.start() + DUPLICATE_WINDOW]
        if LT.search(window) and GT.search(window) and QUOT.search(window):
            errors.append(
                f"Possible duplicate escaper at line {_line_of(text, m.start())}: all four "
                f"substitutions appear outside {CANONICAL_ESCAPER}."
            )
    for m in CHAR_CLASS_ESCAPE.finditer(masked):
        errors.append(
            f"Possible duplicate escaper at line {_line_of(text, m.start())}: "
            f"character-class HTML-escape replace() outside {CANONICAL_ESCAPER}."
        )
    return errors


def load_classifier_module():
    spec = importlib.util.spec_from_file_location(
        "g1_classifier", REPO_ROOT / "scripts" / "g1-innerhtml-sink-classifier.py"
    )
    clf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(clf)
    return clf


def format_slot(slot):
    function, target, op = slot
    return f"{function}():{target} {op}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--against", required=True,
        help="Path to the baseline JSON to compare against (file content '{}' means no prior baseline).",
    )
    parser.add_argument(
        "--current", default=str(CURRENT_JSON),
        help="Path to the current classification JSON (default: %(default)s).",
    )
    args = parser.parse_args()

    old_sinks = load_json(args.against)
    new_sinks = load_json(args.current)
    regressions, eliminated, added = compare_slots(old_sinks, new_sinks)

    clf = load_classifier_module()
    escaper_errors = check_canonical_escaper(clf.text, clf)

    ok = True

    print(f"G1 XSS sink regression guard: {len(new_sinks)} current sinks, {len(old_sinks)} baseline sinks")
    print(f"  {len(eliminated)} slot(s) eliminated (OK)")

    if added:
        print(f"  {len(added)} new sink(s) (reported, not auto-failed -- review manually):")
        for slot, tier, category, sid in sorted(added):
            print(f"    NEW   severity={tier} {category}  {format_slot(slot)}  [{sid}]")
    rhs_changes = find_rhs_changes(old_sinks, new_sinks)
    if rhs_changes:
        print(f"  {len(rhs_changes)} sink(s) with a changed RHS at the same tier (REVIEW, not failed):")
        for slot, tier, old_id, new_id in rhs_changes:
            print(f"    REVIEW severity={tier}  {format_slot(slot)}  [{old_id} -> {new_id}]")

    if regressions:
        ok = False
        print(f"  {len(regressions)} slot(s) REGRESSED:")
        for slot, old_tier, new_tier in sorted(regressions):
            print(f"    FAIL  severity {old_tier} -> {new_tier}  {format_slot(slot)}")

    if escaper_errors:
        ok = False
        print("  canonical escaper check FAILED:")
        for e in escaper_errors:
            print(f"    FAIL  {e}")
    else:
        print("  canonical escaper check OK (exactly one escaper, apostrophe not escaped)")

    if not ok:
        print("\nG1 regression guard: FAIL")
        return 1
    print("\nG1 regression guard: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
