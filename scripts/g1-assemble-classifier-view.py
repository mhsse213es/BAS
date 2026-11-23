"""Assembles the G1 classifier view: web/index.html with every web/src/**/*.js
inlined (sorted by POSIX path) in place of the bundle <script> tag, LF only.
This is a CI analysis artifact, never application build output: the proven G1
scripts read a hard-coded orchestrator/wwwroot/index.html, so the view is
written there for them (G1c spec sections 2 and 8). Stdlib only."""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB = REPO_ROOT / "orchestrator" / "web"
OUT = REPO_ROOT / "orchestrator" / "wwwroot" / "index.html"
TAG = '<script src="/assets/%%APP_JS%%"></script>'


def _lf(text):
    return text.replace("\r\n", "\n")


# Module syntax the proven G1 scripts predate: they find functions with
# ^\s*function NAME(, so an exported declaration would hand its sinks to the
# previous function. Top-level (column 0) import lines and export keywords
# are dropped; the view is classifier input, never executed.
IMPORT_LINE = re.compile(r"^import [^\n]*;\n", re.M)
EXPORT_KW = re.compile(r"^export (?=(?:async\s+)?function\b|var\b|let\b|const\b)", re.M)


# on() (core/actions.js) returns only x()-escaped attribute text; the proven
# classifier does not know the name, so the view presents it as the escaper.
# Calls only: on()'s own definition must keep its name, or the view gets a
# second, impure `function x` and the canonical-escaper check fails.
ON_CALL = re.compile(r"(?<![\w$.])(?<!function )on\(")


# Helpers from core/kit.js, by what they do with their arguments. SAFE_KIT helpers escape every text argument
# (empty, pill, chip, hbars, kv), take numbers (bar), or look up a constant table (icon), so a call is presented to the
# classifier as g1safe(...). card() is safe only when its body argument is (its title and sub are escaped, but the body,
# options.actions and options.cls are not), so it is presented as g1card(...) and the classifier inspects the body.
# Only a name the module really imports from core/kit.js is rewritten: a module that defines its own pill() (the
# agent-drawer one interpolates its tone unescaped) or imports from elsewhere keeps the name and stays unproven.
SAFE_KIT = {"empty", "pill", "chip", "hbars", "kv", "bar", "icon"}
CARD_KIT = {"card"}
KIT_IMPORT = re.compile(r"^import\s*\{([^}]*)\}\s*from\s*['\"]([^'\"]+)['\"]\s*;?[ 	]*$", re.M)


def _imports_kit(spec, rel_path):
    """True when the import specifier, written in the file at rel_path (posix, relative to src/), is core/kit.js."""
    if not spec.startswith("."):
        return False
    parts = (Path(rel_path).parent.as_posix() + "/" + spec).split("/")
    out = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not out:
                return False
            out.pop()
        else:
            out.append(part)
    return "/".join(out) == "core/kit.js"


def _kit_aliases(js, rel_path):
    """{local name: 'g1safe' | 'g1card'} for the kit helpers this module imports from core/kit.js."""
    aliases = {}
    for m in KIT_IMPORT.finditer(js):
        if not _imports_kit(m.group(2), rel_path):
            continue
        for item in m.group(1).split(","):
            bits = item.split()
            if not bits:
                continue
            exported = bits[0]
            local = bits[2] if len(bits) == 3 and bits[1] == "as" else exported
            if exported in SAFE_KIT:
                aliases[local] = "g1safe"
            elif exported in CARD_KIT:
                aliases[local] = "g1card"
    return aliases


def _rewrite_kit_calls(js, rel_path):
    aliases = _kit_aliases(js, rel_path)
    if not aliases:
        return js
    names = "|".join(re.escape(n) for n in sorted(aliases, key=len, reverse=True))
    call = re.compile(r"(?<![\w$.])(?<!function )(" + names + r")\(")
    return call.sub(lambda m: aliases[m.group(1)] + "(", js)


def _as_script(js, rel_path=""):
    return ON_CALL.sub("x(", EXPORT_KW.sub("", IMPORT_LINE.sub("", _rewrite_kit_calls(js, rel_path))))


def assemble(web_dir):
    web_dir = Path(web_dir)
    html = _lf((web_dir / "index.html").read_text(encoding="utf-8"))
    if TAG not in html:
        raise ValueError(f"{web_dir / 'index.html'} has no {TAG}")
    files = sorted((web_dir / "src").rglob("*.js"), key=lambda p: p.relative_to(web_dir).as_posix())
    js = "".join(_as_script(_lf(p.read_text(encoding="utf-8")), p.relative_to(web_dir / "src").as_posix()) for p in files)
    if js and not js.endswith("\n"):
        js += "\n"
    return html.replace(TAG, "<script>\n" + js + "</script>", 1)


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(assemble(WEB).encode("utf-8"))
    print(f"G1 classifier view written to {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
