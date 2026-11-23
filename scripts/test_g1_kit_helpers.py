"""Tests for teaching the G1 classifier about the core/kit.js helpers.

The console is split into modules, so helpers such as empty() and pill() moved out of the single file the classifier
used to read. The assemble step knows which names each module imports from core/kit.js and presents those calls to the
classifier as g1safe(...) (escapes every argument) or g1card(...) (safe only when its body argument is). Names a module
defines itself, or imports from anywhere else, must NOT be trusted.
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("g1_view", REPO_ROOT / "scripts" / "g1-assemble-classifier-view.py")
v = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v)


def web(files):
    d = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
    return d


BASE = {"index.html": '<html>\n<body>\n<script src="/assets/%%APP_JS%%"></script>\n</body>\n</html>\n'}
KIT = {"src/core/kit.js": "export const empty = (i, t) => '<b>' + x(t) + '</b>';\nexport function card(t, b) { return b; }\n"}


def assembled(src, rel="src/features/a.js", extra=None):
    return v.assemble(web({**BASE, **KIT, rel: src, **(extra or {})}))


class TestAssembleRewritesOnlyImportedKitHelpers(unittest.TestCase):
    def test_imported_helpers_become_g1safe_and_card_becomes_g1card(self):
        out = assembled("import { empty, pill, chip, hbars, kv, bar, icon, card } from '../core/kit.js';\n"
                        "function r() { el.innerHTML = card('', empty('ok', 'Done')) + pill('a', 'ok') + chip('b') + hbars([]) + kv([]) + bar(5) + icon('x'); }\n")
        self.assertIn("g1card('', g1safe('ok', 'Done')) + g1safe('a', 'ok') + g1safe('b') + g1safe([]) + g1safe([]) + g1safe(5) + g1safe('x')", out)

    def test_alias_is_followed(self):
        out = assembled("import { empty as kitEmpty, icon as kitIcon } from '../core/kit.js';\nfunction r() { return kitEmpty('a', 'b') + kitIcon('c'); }\n")
        self.assertIn("g1safe('a', 'b') + g1safe('c')", out)

    def test_multiline_import_is_read(self):
        out = assembled("import {\n  empty,\n  pill,\n} from '../core/kit.js';\nfunction r() { return empty('a', 'b') + pill('c'); }\n")
        self.assertIn("g1safe('a', 'b') + g1safe('c')", out)

    def test_a_module_that_defines_its_own_helper_is_not_trusted(self):
        # agent-drawer.js really does this: its own pill() interpolates the tone unescaped.
        out = assembled("function pill(text, tone) { return '<i class=' + tone + '>' + x(text) + '</i>'; }\nfunction r() { return pill('a', t); }\n")
        self.assertIn("return pill('a', t);", out)
        self.assertNotIn("g1safe", out)

    def test_a_name_imported_from_elsewhere_is_not_trusted(self):
        out = assembled("import { empty } from './not-the-kit.js';\nfunction r() { return empty('a', b); }\n")
        self.assertIn("return empty('a', b);", out)
        self.assertNotIn("g1safe", out)

    def test_an_unimported_name_in_a_module_that_imports_others_is_not_trusted(self):
        out = assembled("import { chip } from '../core/kit.js';\nfunction r() { return pill('a', t) + chip('b'); }\n")
        self.assertIn("return pill('a', t) + g1safe('b');", out)

    def test_helpers_that_take_raw_html_are_never_marked_safe(self):
        out = assembled("import { grid, kpi, seg } from '../core/kit.js';\nfunction r() { return grid(2, items) + kpi(o) + seg(a, b, c); }\n")
        self.assertIn("grid(2, items) + kpi(o) + seg(a, b, c)", out)
        self.assertNotIn("g1safe", out)
        self.assertNotIn("g1card", out)

    def test_method_calls_and_longer_names_are_untouched(self):
        out = assembled("import { empty } from '../core/kit.js';\nfunction r() { return thing.empty(a) + isempty(b) + emptyList(c); }\n")
        self.assertIn("thing.empty(a) + isempty(b) + emptyList(c)", out)

    def test_kit_itself_keeps_its_own_definitions(self):
        out = assembled("function r() {}\n")
        self.assertIn("export const empty".replace("export ", ""), out)
        self.assertNotIn("g1safe", out)


def load_classifier(view_text):
    """Load scripts/g1-innerhtml-sink-classifier.py reading view_text instead of the real wwwroot file."""
    tmp = Path(tempfile.mkdtemp()) / "index.html"
    tmp.write_text(view_text, encoding="utf-8")
    src = (REPO_ROOT / "scripts" / "g1-innerhtml-sink-classifier.py").read_text(encoding="utf-8")
    needle = 'SRC = REPO_ROOT / "orchestrator" / "wwwroot" / "index.html"'
    assert needle in src
    ns = {"__name__": "g1_clf_under_test", "__file__": str(REPO_ROOT / "scripts" / "g1-innerhtml-sink-classifier.py")}
    exec(compile(src.replace(needle, "SRC = Path(%r)" % str(tmp)), "g1-classifier", "exec"), ns)
    return ns


CLF = load_classifier("<script>\nfunction f() {}\n</script>\n")
classify = CLF["classify_expr"]


class TestClassifierTrustsKitHelpers(unittest.TestCase):
    def test_safe_helper_calls_are_escaped(self):
        self.assertEqual(classify("g1safe('alert', 'Error loading', e.message)"), "escaped")
        self.assertEqual(classify("'<td>' + g1safe(a, b) + '</td>'"), "escaped")

    def test_card_is_as_safe_as_its_body(self):
        self.assertEqual(classify("g1card('', g1safe('ok', 'Done', 'Nothing to fix'))"), "escaped")
        self.assertEqual(classify("g1card('Title', '<div>' + x(v.name) + '</div>')"), "escaped")
        self.assertEqual(classify("g1card('Title', '<div>' + r.html + '</div>')"), "unescaped_html")

    def test_card_with_an_unsafe_body_is_not_laundered(self):
        got = classify("g1card('', rawHtml)")
        self.assertNotEqual(got, "escaped")

    def test_card_options_that_inject_raw_text_are_refused(self):
        self.assertNotEqual(classify("g1card('T', g1safe(a, b), { actions: btns })"), "escaped")
        self.assertNotEqual(classify("g1card('T', g1safe(a, b), { cls: userClass })"), "escaped")
        self.assertEqual(classify("g1card('T', g1safe(a, b), { flush: true })"), "escaped")

    def test_card_with_odd_shapes_fails_closed(self):
        for expr in ("g1card()", "g1card('only title')", "g1card(`a, ${b}`, g1safe(c))", "g1card('a', g1safe(c)"):
            self.assertNotEqual(classify(expr), "escaped", expr)

    def test_card_commas_inside_nested_calls_and_strings_do_not_split_wrongly(self):
        self.assertEqual(classify("g1card('a, b', g1safe(f(1, 2), 'x, y'))"), "escaped")
        self.assertNotEqual(classify("g1card('a', 'b, ' + r.html)"), "escaped")

    def test_unrelated_helper_calls_stay_indirect(self):
        self.assertEqual(classify("overviewHtml(a)"), "indirect_builder")


if __name__ == "__main__":
    unittest.main()
