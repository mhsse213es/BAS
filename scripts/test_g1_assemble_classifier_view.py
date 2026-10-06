import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("g1_view", REPO_ROOT / "scripts" / "g1-assemble-classifier-view.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def web(files):
    d = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
    return d


BASE = {"index.html": "<html>\n<body>\n<script src=\"/assets/%%APP_JS%%\"></script>\n</body>\n</html>\n"}


class TestAssemble(unittest.TestCase):
    def test_on_helper_calls_are_presented_as_escaper_calls(self):
        d = web({**BASE, "src/a.js": "function r(i) { return '<b' + on('click', 'f', i) + '>'; }\nconst moon(1);\n"})
        out = v.assemble(d)
        self.assertIn("'<b' + x('click', 'f', i) + '>'", out)
        self.assertIn("const moon(1);", out)

    def test_on_helper_definition_is_not_renamed_to_the_escaper(self):
        # A second `function x` would fail the canonical-escaper check.
        d = web({**BASE, "src/core/actions.js": "export function on(t, n) { return ' a'; }\n"})
        out = v.assemble(d)
        self.assertIn("function on(t, n)", out)
        self.assertNotIn("function x(t, n)", out)

    def test_inlines_sources_in_sorted_path_order(self):
        d = web({**BASE, "src/b.js": "function b() {}\n", "src/a.js": "function a() {}\n", "src/core/z.js": "function z() {}\n"})
        out = v.assemble(d)
        self.assertIn("<script>\nfunction a() {}\nfunction b() {}\nfunction z() {}\n</script>", out)
        self.assertNotIn("%%APP_JS%%", out)

    def test_is_byte_identical_across_runs_and_uses_lf(self):
        d = web({**BASE, "src/a.js": "function a() {}\r\n"})
        self.assertEqual(v.assemble(d), v.assemble(d))
        self.assertNotIn("\r", v.assemble(d))

    def test_export_keyword_is_dropped_so_the_classifier_sees_each_function(self):
        # The proven classifier finds functions with ^\s*function NAME( -- an
        # exported declaration would hand its sinks to the previous function.
        d = web({**BASE, "src/a.js": "import { x } from './b.js';\nexport function a() {}\nexport async function b() {}\nexport var c = 1;\nconst s = 'export function no() {}';\n"})
        out = v.assemble(d)
        self.assertIn("\nfunction a() {}\nasync function b() {}\nvar c = 1;\n", out)
        self.assertIn("'export function no() {}'", out)
        self.assertNotIn("import {", out)

    def test_missing_script_tag_fails(self):
        d = web({"index.html": "<html></html>\n", "src/a.js": ""})
        with self.assertRaises(ValueError):
            v.assemble(d)


if __name__ == "__main__":
    unittest.main()
