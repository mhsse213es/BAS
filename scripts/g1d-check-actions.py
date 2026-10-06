"""G1d action registry + inline-handler ratchet (G1d spec section 6.1).
Stdlib only. Usage: python3 scripts/g1d-check-actions.py [web_dir] [--update-baseline]"""
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WEB = REPO_ROOT / "orchestrator" / "web"
DEFAULT_BASELINE = REPO_ROOT / "scripts" / "g1d-inline-baseline.json"

# on<event>= as an attribute (markup or inside a JS string); data-on-click= is
# excluded because "on" there follows "-".
INLINE_HANDLER = re.compile(r"""(?<![\w-])on[a-z]{3,}=\\?["']""")
JS_URL = re.compile(r"javascript:", re.I)
DATA_ON = re.compile(r'data-on-([a-z]+)="([^"]*)"')
ON_CALL = re.compile(r"""(?<![\w$.])on\(\s*['"]([a-z]+)['"]\s*,\s*['"]([A-Za-z_$][\w$]*)['"]""")
STRING_NAME = re.compile(r"""['"]([A-Za-z_$][\w$]*)['"]""")
EXPORTED_FN = re.compile(r"(?m)^export (?:async )?function\*? +([A-Za-z_$][\w$]*)")


def _block(js, const):
    m = re.search(r"export const " + const + r" = [\[{](.*?)[\]}];", js, re.S)
    if not m:
        raise ValueError(f"no {const}")
    items = (t.strip().strip("'\" \t") for t in re.split(r"[,\n]", m.group(1)))
    return [t for t in items if t]


def _sources(web_dir):
    web_dir = Path(web_dir)
    html = (web_dir / "index.html").read_text(encoding="utf-8")
    js = {p: p.read_text(encoding="utf-8") for p in sorted((web_dir / "src").rglob("*.js"))}
    return web_dir, html, js


def counts(web_dir):
    _, html, js = _sources(web_dir)
    texts = [html, *js.values()]
    return {
        "inline_handlers": sum(len(INLINE_HANDLER.findall(t)) for t in texts),
        "javascript_urls": sum(len(JS_URL.findall(t)) for t in texts),
    }


def check(web_dir, baseline_path=DEFAULT_BASELINE):
    web_dir, html, js = _sources(web_dir)
    globals_js = js[web_dir / "src" / "globals.js"]
    actions_js = js[web_dir / "src" / "core" / "actions.js"]
    event_types = set(_block(actions_js, "EVENT_TYPES"))
    builtins = set(EXPORTED_FN.findall(actions_js))
    entries = _block(globals_js, "ACTIONS")
    explicit = {e for e in entries if not e.startswith("...")}
    registered = set(explicit)
    for e in entries:
        if e.startswith("..."):
            registered |= set(_block(globals_js, e[3:]))

    errors, used = [], set()
    # globals.js is the registry; core/actions.js is the dispatcher whose doc
    # comments carry example on() calls -- neither is a use site.
    skip = {web_dir / "src" / "globals.js", web_dir / "src" / "core" / "actions.js"}
    app_js = [t for p, t in js.items() if p not in skip]
    for text in [html, *app_js]:
        for ev, name in DATA_ON.findall(text) + ON_CALL.findall(text):
            used.add(name)
            if ev not in event_types:
                errors.append(f"unknown event type: {ev}")
            if name not in registered:
                errors.append(f"unregistered action: {name}")
    for text in app_js:
        used |= set(STRING_NAME.findall(text))
    # Built-in actions (functions exported by core/actions.js) are available to
    # markup whether or not anything uses them yet.
    for name in sorted(explicit - used - builtins):
        errors.append(f"unused action: {name}")

    window_writes = set(_block(globals_js, "WINDOW_WRITES")) if "WINDOW_WRITES" in globals_js else set()
    for p, text in js.items():
        if p.name == "globals.js":
            continue
        for name in re.findall(r"(?<![\w$.])window\.([A-Za-z_$][\w$]*)\s*=(?!=)", text):
            if name not in window_writes:
                errors.append(f"window write not in WINDOW_WRITES: {name}")
        if re.search(r"(?<![\w$.])window\[", text):
            errors.append(f"window[...] lookup in {p.relative_to(web_dir).as_posix()}")

    now = counts(web_dir)
    base = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    for key, label in (("inline_handlers", "inline handlers"), ("javascript_urls", "javascript: URLs")):
        if now[key] > base[key]:
            errors.append(f"{label}: {now[key]} > baseline {base[key]}")
        elif now[key] < base[key]:
            errors.append(f"{label}: {now[key]} < baseline {base[key]} -- run with --update-baseline")
    return sorted(set(errors))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    web = Path(args[0]) if args else DEFAULT_WEB
    if "--update-baseline" in sys.argv:
        DEFAULT_BASELINE.write_text(json.dumps(counts(web), indent=2) + "\n", encoding="utf-8")
        print(f"baseline updated: {counts(web)}")
    errors = check(web)
    if errors:
        print("G1d action check: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    print(f"G1d action check: OK {counts(web)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
