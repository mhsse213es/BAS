"""The G1 classifier must see every API that parses a string as HTML, not only `.innerHTML =`.

It used to match a single regex (`.innerHTML =` / `+=`), so `el.insertAdjacentHTML(pos, html)` was invisible: the guard
reported success while four such sites sat outside its view. A call is a sink; its HTML is the SECOND argument (the first
is only the position). A call whose arguments cannot be read with certainty fails closed as `unclear`, never as safe.
"""
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLF_PATH = REPO_ROOT / "scripts" / "g1-innerhtml-sink-classifier.py"


def load_classifier(view_text):
    """Load the classifier reading view_text instead of the real wwwroot file."""
    tmp = Path(tempfile.mkdtemp()) / "index.html"
    tmp.write_text(view_text, encoding="utf-8")
    src = CLF_PATH.read_text(encoding="utf-8")
    needle = 'SRC = REPO_ROOT / "orchestrator" / "wwwroot" / "index.html"'
    assert needle in src
    ns = {"__name__": "g1_clf_under_test", "__file__": str(CLF_PATH)}
    exec(compile(src.replace(needle, "SRC = Path(%r)" % str(tmp)), "g1-classifier", "exec"), ns)
    return ns


def sinks(body):
    """Records the classifier produces for a script made of the given function bodies."""
    return load_classifier("<script>\n" + body + "\n</script>\n")["find_sinks"]()


class TestInsertAdjacentHtmlIsASink(unittest.TestCase):
    def test_variable_html_is_recorded_and_not_trusted(self):
        r = sinks("function f(btn, html) {\n  btn.insertAdjacentHTML('afterend', html);\n}")
        self.assertEqual(len(r), 1)
        self.assertEqual((r[0]["function"], r[0]["target"], r[0]["op"], r[0]["rhs"]), ("f", "btn", "insertAdjacentHTML", "html"))
        self.assertNotIn(r[0]["category"], ("static", "static_empty", "escaped"))

    def test_the_position_argument_is_not_part_of_the_html(self):
        r = sinks("function f(el, a) {\n  el.insertAdjacentHTML('beforebegin', '<div>' + a + '</div>');\n}")
        self.assertEqual(r[0]["rhs"], "'<div>' + a + '</div>'")
        self.assertEqual(r[0]["category"], "unescaped_html")

    def test_escaped_html_is_escaped(self):
        r = sinks("function f(el, t) {\n  el.insertAdjacentHTML('afterbegin', '<b>' + x(t) + '</b>');\n}")
        self.assertEqual(r[0]["category"], "escaped")

    def test_a_literal_is_static(self):
        r = sinks("function f(el) {\n  el.insertAdjacentHTML('beforeend', '<hr>');\n}")
        self.assertEqual(r[0]["category"], "static")

    def test_commas_inside_a_nested_call_do_not_split_the_html_argument(self):
        r = sinks("function f(el, a, b) {\n  el.insertAdjacentHTML('afterend', build(a, b));\n}")
        self.assertEqual(r[0]["rhs"], "build(a, b)")

    def test_a_string_containing_commas_and_parens_is_one_argument(self):
        r = sinks("function f(el) {\n  el.insertAdjacentHTML('afterend', '<a title=\"x, (y)\">hi</a>');\n}")
        self.assertEqual(r[0]["rhs"], "'<a title=\"x, (y)\">hi</a>'")
        self.assertEqual(r[0]["category"], "static")

    def test_a_template_literal_fails_closed(self):
        r = sinks("function f(el, a) {\n  el.insertAdjacentHTML('afterend', `<i>${a}</i>`);\n}")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["category"], "unclear")

    def test_a_call_with_the_wrong_argument_count_fails_closed(self):
        r = sinks("function f(el, a) {\n  el.insertAdjacentHTML(a);\n}")
        self.assertEqual(r[0]["category"], "unclear")

    def test_a_multiline_call_is_read(self):
        r = sinks("function f(el, a) {\n  el.insertAdjacentHTML(\n    'afterend',\n    '<p>' + x(a) + '</p>'\n  );\n}")
        self.assertEqual(r[0]["category"], "escaped")


class TestOtherApisAndExistingBehaviour(unittest.TestCase):
    def test_insertAdjacentText_is_not_a_sink(self):
        self.assertEqual(sinks("function f(el, a) {\n  el.insertAdjacentText('afterend', a);\n}"), [])

    def test_innerHTML_is_still_found_and_records_are_in_source_order(self):
        r = sinks("function f(el, a) {\n  el.innerHTML = x(a);\n  el.insertAdjacentHTML('afterend', a);\n  el.innerHTML += '<i></i>';\n}")
        self.assertEqual([(s["op"], s["line"]) for s in r], [("=", 3), ("insertAdjacentHTML", 4), ("+=", 5)])

    def test_two_calls_on_one_line_are_both_recorded(self):
        r = sinks("function f(a, b, h) {\n  a.insertAdjacentHTML('afterend', h); b.insertAdjacentHTML('afterend', h);\n}")
        self.assertEqual([s["target"] for s in r], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
