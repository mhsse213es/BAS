"""G1c registry check: keeps web/src/globals.js the honest, complete list of
app names reachable from inline handlers and window (G1c spec section 6).
Stdlib only. Usage: python3 scripts/g1c-check-globals.py [web_dir]"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WEB = REPO_ROOT / "orchestrator" / "web"

HANDLER_ATTR = re.compile(r"""\son[a-z]+=\\?"(.*?)\\?\"""")
# Single-quoted handlers (onclick='viewRunResults(' + JSON + ')', used when the
# argument is JSON) -- missed until the G1c final review's drawer smoke test.
HANDLER_ATTR_SQ = re.compile(r"""\son[a-z]+=\\?'(.*?)\\?'""")
CALL = re.compile(r"(?<![.\w$'\"])([A-Za-z_$][\w$]*)\s*\(")
ASSIGN = re.compile(r"(?<![.\w$'\"])([A-Za-z_$][\w$]*)\s*(?:\[[^\]]*\])?\s*(?:=(?!=)|\+\+|--|\+=|-=)")
WINDOW_WRITE = re.compile(r"(?<![\w$.])window\.([A-Za-z_$][\w$]*)\s*=(?!=)")
BUILTINS = {
    "if", "function", "return", "typeof", "var", "new", "event", "this",
    "encodeURIComponent", "decodeURIComponent", "setTimeout", "clearTimeout",
    "parseInt", "parseFloat", "String", "Number", "JSON", "Math", "Date",
    "alert", "confirm", "prompt", "rgba", "rgb",
}
# Handler fragments built at runtime: '_x[' + id + ']=' leaves "]=" after a
# quote, so the variable name is the identifier right before the opening quote.
DYN_INDEX_ASSIGN = re.compile(r"([A-Za-z_$][\w$]*)\[\s*'\s*\+")
# Prose inside a handler's string arguments ('… breakdown (Windows)') is not a
# call. Blanked only for the "missing" direction: the generator registers every
# raw match (a superset), so "stale" keeps comparing against the raw scan.
STRING_LIT = re.compile(r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*\"""")
# Reads (G1c final review I4): a handler identifier that names a module's
# top-level declaration but is not on window is a click-time ReferenceError.
# Only top-level names are compared, so template locals spliced into a
# JS-built handler (' + x(a.id) + ') can never match by accident.
TOP_LEVEL = re.compile(r"(?m)^(?:export )?(?:async )?(?:var|let|const|function\*?) +([A-Za-z_$][\w$]*)")
CONCAT = re.compile(r"(?<!\\)'\s*\+(?:[^+]|\+(?!\s*'))*\+\s*'")
REGEX_LIT = re.compile(r"/(?:[^/\\\n]|\\.)+/[gimsuy]*")
IDENT = re.compile(r"(?<![.\w$])([A-Za-z_$][\w$]*)(?!\s*:(?!:))")


def _list(globals_js, const):
    m = re.search(r"export const " + const + r" = [\[{](.*?)[\]}];", globals_js, re.S)
    if not m:
        raise ValueError(f"globals.js has no {const}")
    return {t.strip().strip("',") for t in m.group(1).split("\n") if t.strip().strip("',")}


def check(web_dir):
    web_dir = Path(web_dir)
    globals_js = (web_dir / "src" / "globals.js").read_text(encoding="utf-8")
    fns = _list(globals_js, "HANDLER_FUNCTIONS")
    dynamic = _list(globals_js, "DYNAMIC_HANDLERS")
    state_globals = _list(globals_js, "STATE_GLOBALS")
    window_writes = _list(globals_js, "WINDOW_WRITES")

    sources = [(web_dir / "index.html").read_text(encoding="utf-8")]
    js_files = sorted(p for p in (web_dir / "src").rglob("*.js") if p.name != "globals.js")
    js_texts = [p.read_text(encoding="utf-8") for p in js_files]
    sources += js_texts

    top_level = set()
    for text in js_texts:
        top_level |= set(TOP_LEVEL.findall(text))

    called, called_code, assigned, read = set(), set(), set(), set()
    for i, text in enumerate(sources):
        for m in [*HANDLER_ATTR.finditer(text), *HANDLER_ATTR_SQ.finditer(text)]:
            called |= set(CALL.findall(m.group(1)))
            called_code |= set(CALL.findall(STRING_LIT.sub("''", m.group(1))))
            assigned |= set(ASSIGN.findall(m.group(1)))
            assigned |= set(DYN_INDEX_ASSIGN.findall(m.group(1)))
            body = CONCAT.sub("''", m.group(1)) if i > 0 else m.group(1)
            body = REGEX_LIT.sub("''", STRING_LIT.sub("''", body.replace("\\'", "'")))
            read |= set(IDENT.findall(body)) & top_level
    errors = []
    for n in sorted(called_code - fns - window_writes - BUILTINS):
        errors.append(f"missing: {n}")
    for n in sorted(fns - called - dynamic):
        errors.append(f"stale: {n}")
    for n in sorted(assigned - state_globals - BUILTINS):
        errors.append(f"assign: {n}")
    for n in sorted(read - fns - state_globals - window_writes - BUILTINS):
        errors.append(f"read: {n}")
    writes = set()
    for text in js_texts:
        writes |= set(WINDOW_WRITE.findall(text))
    for n in sorted(writes - window_writes - state_globals):
        errors.append(f"window-write not registered: {n}")
    for n in sorted(window_writes - writes):
        errors.append(f"window-write registered but absent: {n}")
    return errors


def main():
    web = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WEB
    errors = check(web)
    if errors:
        print("G1c globals registry check: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    print("G1c globals registry check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
