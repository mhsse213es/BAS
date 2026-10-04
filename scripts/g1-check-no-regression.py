#!/usr/bin/env python3
"""CI regression guard for G1's XSS-sink classification.

Compares the current Assessment/G1_FINAL_CLASSIFICATION.json against a
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
CURRENT_JSON = REPO_ROOT / "Assessment" / "G1_FINAL_CLASSIFICATION.json"


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


def max_severity_by_slot(sinks):
    out = {}
    for s in sinks:
        k = slot_key(s)
        tier = s["severity_tier"]
        if k not in out or tier > out[k]:
            out[k] = tier
    return out


def compare_slots(old_sinks, new_sinks):
    """Returns (regressions, eliminated, new_slots):
      regressions: [(slot, old_max_tier, new_max_tier), ...] where new > old
      eliminated:  [(slot, old_max_tier), ...] where the slot no longer exists
      new_slots:   [(slot, new_max_tier), ...] where the slot didn't exist before
    """
    old_by_slot = max_severity_by_slot(old_sinks)
    new_by_slot = max_severity_by_slot(new_sinks)

    regressions = []
    eliminated = []
    new_slots = []

    for slot, old_tier in old_by_slot.items():
        if slot not in new_by_slot:
            eliminated.append((slot, old_tier))
        else:
            new_tier = new_by_slot[slot]
            if new_tier > old_tier:
                regressions.append((slot, old_tier, new_tier))

    for slot, new_tier in new_by_slot.items():
        if slot not in old_by_slot:
            new_slots.append((slot, new_tier))

    return regressions, eliminated, new_slots


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


def find_escaper_candidates(text, clf):
    spans = scan_function_spans(text, clf)
    out = []
    for decl_start, body_start, body_end, name in spans:
        body = text[body_start:body_end]
        if AMP.search(body) and LT.search(body) and GT.search(body) and QUOT.search(body):
            line = text.count("\n", 0, decl_start) + 1
            out.append((name, line, bool(APOS.search(body))))
    return out


def check_canonical_escaper(text, clf):
    candidates = find_escaper_candidates(text, clf)
    errors = []
    if len(candidates) == 0:
        errors.append(
            "No function implements all four canonical HTML-escaping "
            "substitutions (& -> &amp;, < -> &lt;, > -> &gt;, \" -> &quot;)."
        )
    elif len(candidates) > 1:
        names = ", ".join(f"{n} (line {l})" for n, l, _ in candidates)
        errors.append(
            f"{len(candidates)} functions implement the full escaper "
            f"substitution set -- expected exactly one canonical escaper: {names}"
        )
    else:
        name, line, has_apos = candidates[0]
        if has_apos:
            errors.append(
                f"Canonical escaper {name!r} (line {line}) now also escapes "
                "a bare ' -- this breaks callers that apply their own "
                "quote-context escaping afterward."
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
    regressions, eliminated, new_slots = compare_slots(old_sinks, new_sinks)

    clf = load_classifier_module()
    escaper_errors = check_canonical_escaper(clf.text, clf)

    ok = True

    print(f"G1 XSS sink regression guard: {len(new_sinks)} current sinks, {len(old_sinks)} baseline sinks")
    print(f"  {len(eliminated)} slot(s) eliminated (OK)")

    if new_slots:
        print(f"  {len(new_slots)} brand-new slot(s) (reported, not auto-failed -- review manually):")
        for slot, tier in sorted(new_slots):
            print(f"    NEW   severity={tier}  {format_slot(slot)}")

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
