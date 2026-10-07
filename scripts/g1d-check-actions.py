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
INLINE_STYLE = re.compile(r"""(?<![\w.-])style=\\?["']""")
STYLE_TAG = re.compile(r"<style\b", re.I)
GEN_USE = re.compile(r"\b(g1-[sv]-[0-9a-f]{8}|g1-display-[a-z-]+)\b")
GEN_RULE = re.compile(r"(?m)^\.(is-hidden|g1-[sv]-[0-9a-f]{8}|g1-display-[a-z-]+)\b")
RULE_KEY = re.compile(r"""(?m)^\s*['"](g1-v-[0-9a-f]{8})['"]\s*:""")
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
        "inline_styles": sum(len(INLINE_STYLE.findall(t)) + len(STYLE_TAG.findall(t)) for t in texts),
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
    # Keys of the shared state object used to be mirrored onto window; a
    # window.<key> read is now silently undefined.
    state_js = js.get(web_dir / "src" / "core" / "state.js", "")
    m = re.search(r"export const state = \{(.*?)\n\};", state_js, re.S)
    state_keys = set(re.findall(r"^\s+([A-Za-z_$][\w$]*):", m.group(1), re.M)) if m else set()
    for p, text in js.items():
        if p.name == "globals.js":
            continue
        for name in sorted(set(re.findall(r"(?<![\w$.])window\.([A-Za-z_$][\w$]*)", text)) & state_keys):
            errors.append(f"window read of shared state: {name} in {p.relative_to(web_dir).as_posix()} (use state.{name})")
        for name in re.findall(r"(?<![\w$.])window\.([A-Za-z_$][\w$]*)\s*=(?!=)", text):
            if name not in window_writes:
                errors.append(f"window write not in WINDOW_WRITES: {name}")
        if re.search(r"(?<![\w$.])window\[", text):
            errors.append(f"window[...] lookup in {p.relative_to(web_dir).as_posix()}")

    css_path = web_dir / "styles" / "inline-equivalent.css"
    if css_path.exists():
        defined = set(GEN_RULE.findall(css_path.read_text(encoding="utf-8")))
        rules_path = web_dir / "src" / "core" / "css-var-rules.js"
        registered_rules = set(RULE_KEY.findall(rules_path.read_text(encoding="utf-8"))) if rules_path.exists() else set()
        used_gen = set()
        for p, text in [(web_dir / "index.html", html), *js.items()]:
            found = set(GEN_USE.findall(text))
            if p != rules_path:
                for r in {c for c in found if c.startswith("g1-v-")} - registered_rules:
                    errors.append(f"unregistered css-vars rule: {r}")
            used_gen |= found
            if "data-css-vars" in text and p.name != "css-vars.js":
                errors.append(f"data-css-vars outside core/css-vars.js: {p.relative_to(web_dir).as_posix()}")
        for c in sorted(used_gen - defined):
            errors.append(f"undefined generated class: {c}")
        for c in sorted(defined - used_gen - {"is-hidden"}):
            errors.append(f"orphan generated rule: {c}")

    now = counts(web_dir)
    base = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    for key, label in (("inline_handlers", "inline handlers"), ("javascript_urls", "javascript: URLs"),
                       ("inline_styles", "inline styles")):
        if now[key] > base.get(key, 0):
            errors.append(f"{label}: {now[key]} > baseline {base.get(key, 0)}")
        elif now[key] < base.get(key, 0):
            errors.append(f"{label}: {now[key]} < baseline {base.get(key, 0)} -- run with --update-baseline")
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
