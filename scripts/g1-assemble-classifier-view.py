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


def _as_script(js):
    return EXPORT_KW.sub("", IMPORT_LINE.sub("", js))


def assemble(web_dir):
    web_dir = Path(web_dir)
    html = _lf((web_dir / "index.html").read_text(encoding="utf-8"))
    if TAG not in html:
        raise ValueError(f"{web_dir / 'index.html'} has no {TAG}")
    files = sorted((web_dir / "src").rglob("*.js"), key=lambda p: p.relative_to(web_dir).as_posix())
    js = "".join(_as_script(_lf(p.read_text(encoding="utf-8"))) for p in files)
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
