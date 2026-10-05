import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("g1c_globals", REPO_ROOT / "scripts" / "g1c-check-globals.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

GLOBALS = """export const HANDLER_FUNCTIONS = {
  doLogin,
  showTab,
};
export const DYNAMIC_HANDLERS = [
  'renderRunMode',
];
export const STATE_GLOBALS = [
  'scenarioView',
];
export const WINDOW_WRITES = [
  'openRunPanel',
];
"""


def make(index_html, extra_js="", globals_js=GLOBALS):
    d = Path(tempfile.mkdtemp())
    (d / "src").mkdir()
    (d / "index.html").write_text(index_html, encoding="utf-8")
    (d / "src" / "globals.js").write_text(globals_js, encoding="utf-8")
    (d / "src" / "legacy.js").write_text(extra_js, encoding="utf-8")
    return d


class TestRegistry(unittest.TestCase):
    def test_clean_registry_passes(self):
        d = make('<a onclick="showTab(\'x\')"></a><b onclick="doLogin()"></b>',
                 "export function renderRunMode(){}\n(function(){ window.openRunPanel = function(){}; })();\n"
                 "var h = '<i onchange=\"scenarioView=1;openRunPanel()\">';\n")
        self.assertEqual(g.check(d), [])

    def test_missing_handler_function_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin();vanished()"></a>')
        self.assertIn("missing: vanished", g.check(d))

    def test_stale_registry_entry_fails(self):
        d = make('<a onclick="showTab(\'x\')"></a>', "window.openRunPanel = 1;\n")
        self.assertIn("stale: doLogin", g.check(d))

    def test_dynamic_handler_is_not_stale(self):
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>', "window.openRunPanel = 1;\n")
        self.assertFalse([e for e in g.check(d) if "renderRunMode" in e])

    def test_handler_assignment_to_unregistered_variable_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin()" onchange="INIT_ATTACH_SELECTED=this.value"></a>', "window.openRunPanel = 1;\n")
        self.assertIn("assign: INIT_ATTACH_SELECTED", g.check(d))

    def test_handler_indexed_assignment_in_js_string_fails_when_unregistered(self):
        js = "window.openRunPanel = 1;\nvar s = ' onchange=\"' + n + '_other[' + id + ']=this.checked;\"';\nvar t = '<i onchange=\"_sel[1]=this.checked\">';\n"
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>', js)
        self.assertIn("assign: _sel", g.check(d))

    def test_unregistered_window_write_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>', "window.openRunPanel = 1;\nwindow.sneaky = 2;\n")
        self.assertIn("window-write not registered: sneaky", g.check(d))

    def test_registered_window_write_never_made_fails(self):
        d = make('<a onclick="showTab(\'x\');doLogin()"></a>')
        self.assertIn("window-write registered but absent: openRunPanel", g.check(d))


    def test_text_inside_handler_string_arguments_is_not_a_call(self):
        d = make('<a onclick="showTab(\'per-platform breakdown (Windows)\');doLogin()"></a>', "window.openRunPanel = 1;\n")
        self.assertEqual(g.check(d), [])

    def test_handler_read_of_unexposed_module_variable_fails(self):
        # A module-private top-level variable read by a handler is a click-time
        # ReferenceError (G1c final review I4).
        js = "window.openRunPanel = 1;\nvar _pending = 3;\nvar s = '<i onclick=\"doLogin(_pending)\">';\n"
        d = make('<a onclick="showTab(\'x\')"></a>', js)
        self.assertIn("read: _pending", g.check(d))

    def test_template_locals_spliced_into_handlers_are_not_reads(self):
        js = ("window.openRunPanel = 1;\nvar a = 1;\n"
              "function r(a) { return '<i onclick=\"doLogin(\\'' + x(a.id) + '\\')\">'; }\n")
        d = make('<a onclick="showTab(\'x\')"></a>', js)
        self.assertEqual([e for e in g.check(d) if e.startswith("read:")], [])

    def test_exposed_state_read_is_allowed(self):
        js = "window.openRunPanel = 1;\nvar s = '<i onclick=\"doLogin(scenarioView)\">';\n"
        d = make('<a onclick="showTab(\'x\')"></a>', js)
        self.assertEqual(g.check(d), [])


if __name__ == "__main__":
    unittest.main()
