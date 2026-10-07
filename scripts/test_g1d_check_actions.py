import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("g1d", REPO_ROOT / "scripts" / "g1d-check-actions.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

ACTIONS_JS = "export const EVENT_TYPES = ['click', 'change'];\n"
GLOBALS = """export const HANDLER_FUNCTIONS = {
  legacyFn,
};
export const ACTIONS = {
  ...HANDLER_FUNCTIONS,
  openRun,
  stopEvent,
};
"""


def make(html, js="", globals_js=GLOBALS, baseline=None, actions_js=ACTIONS_JS, css=None, rules_js=None):
    d = Path(tempfile.mkdtemp())
    (d / "src" / "core").mkdir(parents=True)
    (d / "index.html").write_text(html, encoding="utf-8")
    (d / "src" / "core" / "actions.js").write_text(actions_js, encoding="utf-8")
    (d / "src" / "globals.js").write_text(globals_js, encoding="utf-8")
    (d / "src" / "a.js").write_text(js, encoding="utf-8")
    if css is not None:
        (d / "styles").mkdir()
        (d / "styles" / "inline-equivalent.css").write_text(css, encoding="utf-8")
    if rules_js is not None:
        (d / "src" / "core" / "css-var-rules.js").write_text(rules_js, encoding="utf-8")
        (d / "src" / "core" / "css-vars.js").write_text(
            "export function cssVars(...e) { return ' data-css-vars=' }\n", encoding="utf-8")
    b = d / "baseline.json"
    b.write_text(json.dumps(baseline if baseline is not None else g.counts(d)), encoding="utf-8")
    return d, b


CLEAN_HTML = '<a data-on-click="openRun" data-args="[1]"></a><b data-on-change="stopEvent"></b>'


class TestStyles(unittest.TestCase):
    def test_inline_styles_counted_in_markup_and_js(self):
        d, _ = make('<p style="color:red"></p>', js="h += '<b style=\"x\"></b>' + '<i style=\\'y\\'></i>'; el.style.color = 'red';")
        self.assertEqual(g.counts(d)["inline_styles"], 3)

    def test_style_tag_in_js_counted(self):
        d, _ = make("<p></p>", js="h = '<style>p{}</style>';")
        self.assertEqual(g.counts(d)["inline_styles"], 1)

    def test_inline_styles_ratchet(self):
        d, b = make('<p style="a"></p>', baseline={"inline_handlers": 0, "javascript_urls": 0, "inline_styles": 0})
        self.assertIn("inline styles: 1 > baseline 0", g.check(d, b))

    def test_undefined_and_orphan_generated_classes(self):
        css = ".is-hidden { display: none; }\n.g1-s-0000000a { color:red }\n"
        d, b = make('<p class="g1-s-0000000b"></p>', css=css)
        errs = g.check(d, b)
        self.assertIn("undefined generated class: g1-s-0000000b", errs)
        self.assertIn("orphan generated rule: g1-s-0000000a", errs)

    def test_consistent_classes_pass(self):
        css = ".is-hidden { display: none; }\n.g1-display-flex { display: flex; }\n.g1-s-0000000a { color:red }\n.g1-v-0000000c.g1-v-0000000c { width: var(--g1-v-0000000c); }\n"
        rules = "export const CSS_VAR_RULES = {\n  'g1-v-0000000c': { prop: 'width', value: '{0}%', types: ['number'] },\n};\n"
        d, b = make('<p class="g1-s-0000000a g1-display-flex"></p>', js="h = '<i' + cssVars(['g1-v-0000000c', 5]) + '>';", css=css, rules_js=rules)
        self.assertEqual([e for e in g.check(d, b) if "generated" in e or "css-vars" in e], [])

    def test_unregistered_css_vars_rule(self):
        css = ".is-hidden { display: none; }\n"
        rules = "export const CSS_VAR_RULES = {\n};\n"
        d, b = make("<p></p>", js="h = '<i' + cssVars(['g1-v-0000000d', 5]) + '>';", css=css, rules_js=rules)
        self.assertIn("unregistered css-vars rule: g1-v-0000000d", g.check(d, b))

    def test_data_css_vars_only_in_css_vars_module(self):
        d, b = make("<p></p>", js="h = '<i data-css-vars=\"[]\">';", css=".is-hidden { display: none; }\n")
        self.assertTrue(any(e.startswith("data-css-vars outside core/css-vars.js") for e in g.check(d, b)))


class TestActions(unittest.TestCase):
    def test_clean_tree_passes(self):
        d, b = make(CLEAN_HTML)
        self.assertEqual(g.check(d, b), [])

    def test_unregistered_markup_action_fails(self):
        d, b = make(CLEAN_HTML + '<i data-on-click="ghost"></i>')
        self.assertIn("unregistered action: ghost", g.check(d, b))

    def test_unregistered_on_call_fails(self):
        d, b = make(CLEAN_HTML, "x = '<b' + on('click', 'ghost', 1) + '>';\n")
        self.assertIn("unregistered action: ghost", g.check(d, b))

    def test_unknown_event_type_fails(self):
        d, b = make(CLEAN_HTML + '<i data-on-dblclick="openRun"></i>')
        self.assertIn("unknown event type: dblclick", g.check(d, b))

    def test_unused_explicit_action_fails_but_spread_entries_are_exempt(self):
        d, b = make('<a data-on-click="openRun"></a>', actions_js=ACTIONS_JS + "export function other() {}\n")
        errs = g.check(d, b)
        self.assertNotIn("unused action: legacyFn", errs)
        g2 = GLOBALS.replace("  stopEvent,\n", "  stopEvent,\n  orphan,\n")
        d, b = make('<a data-on-click="openRun"></a>', globals_js=g2)
        self.assertIn("unused action: orphan", g.check(d, b))

    def test_builtin_actions_exported_by_actions_js_are_exempt_from_unused(self):
        d, b = make('<a data-on-click="openRun"></a>',
                    actions_js=ACTIONS_JS + "export function stopEvent(e) {}\n")
        self.assertEqual(g.check(d, b), [])
        # without the export, stopEvent is a plain unused explicit action
        d, b = make('<a data-on-click="openRun"></a>')
        self.assertIn("unused action: stopEvent", g.check(d, b))

    def test_example_calls_in_actions_js_comments_are_not_use_sites(self):
        d, b = make(CLEAN_HTML, actions_js=ACTIONS_JS + "// on('click', 'ghost', id)\n")
        self.assertEqual(g.check(d, b), [])

    def test_multiline_event_types_parse(self):
        d, b = make('<a data-on-click="openRun"></a><b data-on-change="stopEvent"></b>',
                    actions_js="export const EVENT_TYPES = [\n  'click',\n  'change',\n];\n")
        self.assertEqual(g.check(d, b), [])

    def test_name_passed_as_a_string_literal_counts_as_used(self):
        d, b = make('<a data-on-click="openRun"></a>', "covSegHtml(items, v, 'stopEvent');\n")
        self.assertEqual(g.check(d, b), [])

    def test_inline_count_may_not_grow(self):
        d, b = make(CLEAN_HTML, baseline={"inline_handlers": 0, "javascript_urls": 0})
        (d / "src" / "a.js").write_text("s = '<b onclick=\"f()\">';\n", encoding="utf-8")
        self.assertIn("inline handlers: 1 > baseline 0", g.check(d, b))

    def test_inline_count_drop_requires_baseline_update(self):
        d, b = make(CLEAN_HTML, baseline={"inline_handlers": 5, "javascript_urls": 1})
        errs = g.check(d, b)
        self.assertIn("inline handlers: 0 < baseline 5 -- run with --update-baseline", errs)
        self.assertIn("javascript: URLs: 0 < baseline 1 -- run with --update-baseline", errs)

    def test_data_on_attribute_is_not_counted_as_inline(self):
        self.assertEqual(g.counts(make(CLEAN_HTML)[0]), {"inline_handlers": 0, "javascript_urls": 0, "inline_styles": 0})

    def test_counts_markup_and_template_handlers_and_js_urls(self):
        d, _ = make('<a href="javascript:void(0)" onclick="f()"></a>', "s = '<b onchange=\\\"g()\\\">';\n")
        self.assertEqual(g.counts(d), {"inline_handlers": 2, "javascript_urls": 1, "inline_styles": 0})

    def test_window_write_outside_allowlist_fails(self):
        g_js = GLOBALS + "export const WINDOW_WRITES = [\n  'onRunEvent',\n];\n"
        d, b = make(CLEAN_HTML, "window.onRunEvent = f;\nwindow.sneaky = 1;\n", globals_js=g_js)
        self.assertIn("window write not in WINDOW_WRITES: sneaky", g.check(d, b))

    def test_window_read_of_shared_state_key_fails(self):
        # installGlobals used to mirror these keys onto window; after G1d a
        # window.<key> read is silently undefined.
        d, b = make(CLEAN_HTML, "if (window.scenarios) go();\nvar w = window.innerWidth;\n")
        (d / "src" / "core" / "state.js").write_text("export const state = {\n  scenarios: [],\n  _covSt: undefined,\n};\n", encoding="utf-8")
        errors = g.check(d, b)
        self.assertIn("window read of shared state: scenarios in src/a.js (use state.scenarios)", errors)
        self.assertFalse(any("innerWidth" in e for e in errors))

    def test_window_bracket_lookup_fails(self):
        d, b = make(CLEAN_HTML, "var sel = window[name];\n")
        self.assertIn("window[...] lookup in src/a.js", g.check(d, b))


if __name__ == "__main__":
    unittest.main()
