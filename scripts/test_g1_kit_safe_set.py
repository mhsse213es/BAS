"""The set of core/kit.js helpers the G1 view trusts, and the pins that keep that trust honest.

A helper in SAFE_KIT is presented to the classifier as g1safe(...) ("escapes every argument"), so its sinks are not
inspected further. That claim is only as good as kit.js, so each trusted helper's reviewed source (and the small
private helpers it relies on) is pinned by hash: editing one fails this test until a person re-reads it and updates
the pin. seg/tabs/kpi/searchBox were reviewed on 2026-11-23: every text value goes through x(), tone() is a constant
lookup, actionAttrs() escapes the action and its arguments, and chart data goes to a registry, not into markup.
"""
import hashlib
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KIT_JS = REPO_ROOT / "orchestrator" / "web" / "src" / "core" / "kit.js"

_spec = importlib.util.spec_from_file_location("g1_view", REPO_ROOT / "scripts" / "g1-assemble-classifier-view.py")
v = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v)

BASE = {"index.html": '<html>\n<body>\n<script src="/assets/%%APP_JS%%"></script>\n</body>\n</html>\n'}
KIT = {"src/core/kit.js": "export const empty = (i, t) => '<b>' + x(t) + '</b>';\n"}


def assembled(src, rel="src/features/a.js"):
    d = Path(tempfile.mkdtemp())
    for r, text in {**BASE, **KIT, rel: src}.items():
        p = d / r
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
    return v.assemble(d)


NEW_TRUSTED = ["seg", "tabs", "kpi", "searchBox"]


class TestNewHelpersAreTrustedOnlyWhenImportedFromKit(unittest.TestCase):
    def test_imported_helpers_become_g1safe(self):
        out = assembled("import { seg, tabs, kpi, searchBox } from '../core/kit.js';\n"
                        "function r() { el.innerHTML = seg(o, a, 'f') + tabs(o, a, 'f') + kpi({ label: l }) + searchBox('i', 'p', 'a'); }\n")
        for name in NEW_TRUSTED:
            self.assertIn("g1safe(", out)
            self.assertNotIn(" " + name + "(", out.split("function r()")[1], name)

    def test_a_locally_defined_helper_with_the_same_name_stays_untrusted(self):
        out = assembled("function seg(o) { return '<i>' + o + '</i>'; }\nfunction r() { el.innerHTML = seg(a); }\n")
        self.assertIn("seg(a)", out)
        self.assertNotIn("g1safe", out.split("function r()")[1])

    def test_a_same_named_import_from_elsewhere_stays_untrusted(self):
        out = assembled("import { kpi } from './other.js';\nfunction r() { el.innerHTML = kpi({ label: l }); }\n")
        self.assertIn("kpi({ label: l })", out)

    def test_composition_helpers_are_not_trusted(self):
        # grid, filterBar and checkRow splice caller-supplied HTML, so they are only as safe as their arguments.
        self.assertEqual({"grid", "filterBar", "checkRow"} & v.SAFE_KIT, set())


def _normalised(src):
    return "\n".join(ln.strip() for ln in src.split("\n") if ln.strip() and not ln.strip().startswith("//"))


def helper_source(js, name):
    """Source text of an exported helper (to the next export) or a private one-line const."""
    m = re.search(r"^export (?:const|function) " + re.escape(name) + r"\b.*?(?=^export |\Z)", js, re.S | re.M)
    if not m:
        m = re.search(r"^const " + re.escape(name) + r"\b[^\n]*", js, re.M)
    if not m:
        raise AssertionError("kit.js no longer defines %s" % name)
    return _normalised(m.group(0))


def fingerprint(js, name):
    return hashlib.sha256(helper_source(js, name).encode("utf-8")).hexdigest()[:16]


# Private helpers the trusted ones rely on are pinned too: a change to x-wrapping, tone() or actionAttrs() changes
# what "escapes every argument" means.
PINS = {
    "bar": "ecea2869d3cbbc38",
    "chip": "78613d1fc24f4efa",
    "empty": "6b8acb56509347f0",
    "hbars": "aaddee8de6cc3fad",
    "icon": "ca976444cbccbfba",
    "kpi": "654b2b9fdb9b5594",
    "kv": "d549978bcff9c010",
    "pill": "8ba9ddf57d841f8e",
    "searchBox": "96e01665f7b8b8e6",
    "seg": "2a9e6f7e2d047a36",
    "tabs": "2d94f00ef94d716f",
    "tone": "8a3721f61ae70907",
    "TONES": "e693038d26382c2d",
    "actionAttrs": "7813141b4e11cf7a",
    "ON": "6d42025948b759a1",
}


class TestTrustedKitHelpersArePinned(unittest.TestCase):
    def test_every_trusted_helper_and_its_private_dependencies_match_the_reviewed_source(self):
        js = KIT_JS.read_text(encoding="utf-8").replace("\r\n", "\n")
        names = sorted(v.SAFE_KIT) + ["tone", "TONES", "actionAttrs", "ON"]
        got = {n: fingerprint(js, n) for n in names}
        self.assertEqual(set(PINS), set(names), "pin set differs from the trusted set")
        changed = sorted(n for n in names if PINS.get(n) != got[n])
        self.assertEqual(changed, [], "kit.js helper changed since it was reviewed; re-read it, then update PINS: %s" % {n: got[n] for n in changed})


if __name__ == "__main__":
    unittest.main()
