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
        regressions, _, new_slots = guard.compare_slots(old, new)
        self.assertEqual(regressions, [])
        self.assertEqual(new_slots, [(("f", "t", "="), 4)])

    def test_multiple_sinks_per_slot_compares_the_max(self):
        old = [_sink("f", "t", "=", 0, sink_id="a"), _sink("f", "t", "=", 1, sink_id="b")]
        new = [_sink("f", "t", "=", 0, sink_id="a"), _sink("f", "t", "=", 4, sink_id="c")]
        regressions, _, _ = guard.compare_slots(old, new)
        self.assertEqual(regressions, [(("f", "t", "="), 1, 4)])


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

    def test_real_index_html_passes(self):
        real_clf = _load("g1_classifier_real", "g1-innerhtml-sink-classifier.py")
        errors = guard.check_canonical_escaper(real_clf.text, real_clf)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
