import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, REPO_ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


guard = _load("g1_check_no_regression", "g1-check-no-regression.py")
clf = _load("g1_classifier_for_tests", "g1-innerhtml-sink-classifier.py")


def _sink(function, target, op, severity_tier, sink_id=None):
    return {
        "sink_id": sink_id or f"{function}:{target}:{op}:deadbeefcafe",
        "line": 1,
        "function": function,
        "target": target,
        "op": op,
        "baseline_category": "unescaped_html",
        "final_category": "unescaped_html",
        "severity_tier": severity_tier,
        "data_source_tags": "",
        "trace_notes": "",
        "rhs": "x",
    }


class TestLoadJson(unittest.TestCase):
    def test_empty_object_baseline_means_no_prior_sinks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("{}")
            path = f.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        self.assertEqual(guard.load_json(path), [])

    def test_array_baseline_loads_sinks(self):
        rows = [_sink("f", "t", "=", 1)]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(rows, f)
            path = f.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        self.assertEqual(guard.load_json(path), rows)


class TestCompareSlots(unittest.TestCase):
    def test_slot_eliminated_is_ok(self):
        old = [_sink("f", "t", "=", 4)]
        new = []
        regressions, eliminated, new_slots = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])
        self.assertEqual(len(eliminated), 1)
        self.assertEqual(new_slots, [])

    def test_slot_severity_increase_is_regression(self):
        old = [_sink("f", "t", "=", 1)]
        new = [_sink("f", "t", "=", 4)]
        regressions, _, _ = guard.compare_slots(old, new)
        self.assertEqual(regressions, [(("f", "t", "="), 1, 4)])

    def test_slot_severity_same_or_decrease_is_ok(self):
        old = [_sink("f", "t", "=", 4)]
        new = [_sink("f", "t", "=", 1)]
        regressions, _, _ = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])

        same = [_sink("g", "u", "+=", 2)]
        regressions2, _, _ = guard.compare_slots(same, same)
        self.assertEqual(regressions2, [])

    def test_brand_new_slot_is_reported_not_failed(self):
        old = []
        new = [_sink("f", "t", "=", 4)]
        regressions, _, new_sinks = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])
        self.assertEqual(new_sinks, [(("f", "t", "="), 4, "unescaped_html", "f:t:=:deadbeefcafe")])

    def test_multiple_sinks_per_slot_compares_the_max(self):
        old = [_sink("f", "t", "=", 0, sink_id="a"), _sink("f", "t", "=", 1, sink_id="b")]
        new = [_sink("f", "t", "=", 0, sink_id="a"), _sink("f", "t", "=", 4, sink_id="c")]
        regressions, _, _ = guard.compare_slots(old, new)
        self.assertEqual(regressions, [(("f", "t", "="), 1, 4)])

    def test_in_place_worsening_hidden_by_max_is_regression(self):
        # Slot already has a tier-4 sink; its static sibling is rewritten
        # to tier 4. The slot max is unchanged, but a sink got worse.
        old = [_sink("f", "t", "=", 4, sink_id="a"), _sink("f", "t", "=", 0, sink_id="b")]
        new = [_sink("f", "t", "=", 4, sink_id="a"), _sink("f", "t", "=", 4, sink_id="c")]
        regressions, _, new_sinks = guard.compare_slots(old, new)
        self.assertEqual(regressions, [(("f", "t", "="), 0, 4)])
        self.assertEqual(new_sinks, [])

    def test_new_sink_added_to_existing_slot_is_reported_not_failed(self):
        old = [_sink("f", "t", "=", 4, sink_id="a")]
        new = [_sink("f", "t", "=", 4, sink_id="a"), _sink("f", "t", "=", 4, sink_id="c")]
        regressions, _, new_sinks = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])
        self.assertEqual(new_sinks, [(("f", "t", "="), 4, "unescaped_html", "c")])

    def test_rhs_edit_at_same_tier_is_ok(self):
        old = [_sink("f", "t", "=", 1, sink_id="a")]
        new = [_sink("f", "t", "=", 1, sink_id="b")]
        regressions, _, new_sinks = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])
        self.assertEqual(new_sinks, [])


class TestCanonicalEscaperCheck(unittest.TestCase):
    GOOD = (
        "function escapeHTML(s) {\n"
        "  return String(s == null ? '' : s)\n"
        "    .replace(/&/g,'&amp;').replace(/</g,'&lt;')"
        ".replace(/>/g,'&gt;').replace(/\"/g,'&quot;');\n"
        "}\n"
    )

    def test_canonical_escaper_passes(self):
        self.assertEqual(guard.check_canonical_escaper(self.GOOD, clf), [])

    def test_missing_substitution_fails(self):
        broken = self.GOOD.replace(".replace(/\"/g,'&quot;')", "")
        errors = guard.check_canonical_escaper(broken, clf)
        self.assertEqual(len(errors), 1)
        self.assertIn("No function", errors[0])

    def test_duplicate_escaper_fails(self):
        dup = self.GOOD + self.GOOD.replace("escapeHTML", "xe")
        errors = guard.check_canonical_escaper(dup, clf)
        self.assertEqual(len(errors), 1)
        self.assertIn("functions implement", errors[0])

    def test_escaper_that_also_escapes_apostrophe_fails(self):
        over_escaping = self.GOOD.replace(
            ".replace(/\"/g,'&quot;');",
            ".replace(/\"/g,'&quot;').replace(/'/g,'&#39;');",
        )
        errors = guard.check_canonical_escaper(over_escaping, clf)
        self.assertEqual(len(errors), 1)
        self.assertIn("also escapes a bare", errors[0])

    SUBS = (".replace(/&/g,'&amp;').replace(/</g,'&lt;')"
            ".replace(/>/g,'&gt;').replace(/\"/g,'&quot;')")

    def _assert_fails(self, text, fragment):
        errors = guard.check_canonical_escaper(text, clf)
        self.assertTrue(errors, "expected a failure, got none")
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_alias_delegating_to_canonical_passes(self):
        text = self.GOOD + "function x(s) { return escapeHTML(s); }\n"
        self.assertEqual(guard.check_canonical_escaper(text, clf), [])

    def test_alias_passthrough_fails(self):
        self._assert_fails(self.GOOD + "function x(s) { return s; }\n", "'x'")

    def test_arrow_alias_passthrough_fails(self):
        self._assert_fails(self.GOOD + "var esc = s => s;\n", "'esc'")

    def test_decoy_escaper_with_gutted_canonical_fails(self):
        gutted = "function escapeHTML(s) { return s; }\n"
        decoy = "function enc(s) { return String(s)" + self.SUBS + "; }\n"
        self._assert_fails(gutted + decoy, "escapeHTML")

    def test_arrow_duplicate_escaper_fails(self):
        dup = "var enc = s => String(s)" + self.SUBS + ";\n"
        self._assert_fails(self.GOOD + dup, "duplicate")

    def test_object_method_duplicate_escaper_fails(self):
        dup = "var U = { enc: function(s) { return String(s)" + self.SUBS + "; } };\n"
        self._assert_fails(self.GOOD + dup, "duplicate")

    def test_char_class_escaper_fails(self):
        dup = ("var e2 = function(s) { return String(s).replace(/[&<>\"]/g, "
               "function(c) { return M[c]; }); };\n")
        self._assert_fails(self.GOOD + dup, "duplicate")

    def test_real_index_html_passes(self):
        real_clf = _load("g1_classifier_real", "g1-innerhtml-sink-classifier.py")
        errors = guard.check_canonical_escaper(real_clf.text, real_clf)
        self.assertEqual(errors, [])



class TestRhsChanges(unittest.TestCase):
    def test_same_slot_changed_rhs_same_tier_is_reported(self):
        old = [_sink("f", "el", "=", 4, sink_id="f:el:=:aaaaaaaaaaaa")]
        new = [_sink("f", "el", "=", 4, sink_id="f:el:=:bbbbbbbbbbbb")]
        self.assertEqual(guard.find_rhs_changes(old, new),
                         [(("f", "el", "="), 4, "f:el:=:aaaaaaaaaaaa", "f:el:=:bbbbbbbbbbbb")])
        self.assertEqual(guard.compare_slots(old, new)[0], [])  # still not a failure

    def test_identical_sink_is_not_reported(self):
        s = [_sink("f", "el", "=", 4)]
        self.assertEqual(guard.find_rhs_changes(s, list(s)), [])

    def test_tier_change_is_not_a_review_item(self):
        old = [_sink("f", "el", "=", 1, sink_id="f:el:=:aaaaaaaaaaaa")]
        new = [_sink("f", "el", "=", 4, sink_id="f:el:=:bbbbbbbbbbbb")]
        self.assertEqual(guard.find_rhs_changes(old, new), [])

if __name__ == "__main__":
    unittest.main()
