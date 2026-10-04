import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "g1_merge_classification", REPO_ROOT / "scripts" / "g1-merge-classification.py"
)
merge_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(merge_mod)


def _write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


class TestMerge(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.inv_path = Path(self.tmpdir.name) / "inv.csv"
        self.trace_path = Path(self.tmpdir.name) / "trace.csv"

    def _write_inventory(self, rows):
        _write_csv(
            self.inv_path,
            ["line", "function", "target", "op", "category", "data_source_tags", "rhs_len", "rhs"],
            rows,
        )

    def _write_trace(self, rows):
        _write_csv(
            self.trace_path,
            ["line", "function", "original_category", "resolved_category", "notes", "rhs"],
            rows,
        )

    def test_static_sink_passes_through_unchanged(self):
        self._write_inventory([{
            "line": "10", "function": "f", "target": "el", "op": "=",
            "category": "static", "data_source_tags": "", "rhs_len": "4", "rhs": "'hi'",
        }])
        self._write_trace([])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["final_category"], "static")
        self.assertEqual(rows[0]["severity_tier"], 0)
        self.assertTrue(rows[0]["sink_id"].startswith("f:el:=:"))

    def test_indirect_sink_resolves_via_trace(self):
        self._write_inventory([{
            "line": "20", "function": "g", "target": "box", "op": "=",
            "category": "indirect_variable", "data_source_tags": "", "rhs_len": "4", "rhs": "html",
        }])
        self._write_trace([{
            "line": "20", "function": "g", "original_category": "indirect_variable",
            "resolved_category": "escaped", "notes": "resolved via trace", "rhs": "html",
        }])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(rows[0]["final_category"], "escaped")
        self.assertEqual(rows[0]["trace_notes"], "resolved via trace")

    def test_manual_resolution_applies_when_trace_is_unresolved(self):
        # Real sink from the committed baseline (line 11243, tile()'s write
        # to the dash-itsm-tiles target, rhs "html"): the automated tracer's
        # single scope-hop can't follow it further and leaves it
        # indirect_builder. The manual table supplies the real second-hop
        # answer a human already traced for this exact sink.
        self._write_inventory([{
            "line": "11243", "function": "tile",
            "target": "document.getElementById('dash-itsm-tiles')", "op": "=",
            "category": "indirect_variable", "data_source_tags": "", "rhs_len": "4", "rhs": "html",
        }])
        self._write_trace([{
            "line": "11243", "function": "tile", "original_category": "indirect_variable",
            "resolved_category": "indirect_builder", "notes": "unresolved by automated trace",
            "rhs": "html",
        }])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(rows[0]["final_category"], "escaped")

    def test_rhs_whitespace_does_not_affect_sink_id(self):
        self._write_inventory([
            {"line": "1", "function": "f", "target": "t", "op": "=", "category": "static",
             "data_source_tags": "", "rhs_len": "5", "rhs": "a + b"},
            {"line": "2", "function": "f2", "target": "t2", "op": "=", "category": "static",
             "data_source_tags": "", "rhs_len": "5", "rhs": "a +\n   b"},
        ])
        self._write_trace([])
        rows = merge_mod.merge(self.inv_path, self.trace_path)
        hash1 = rows[0]["sink_id"].rsplit(":", 1)[-1]
        hash2 = rows[1]["sink_id"].rsplit(":", 1)[-1]
        self.assertEqual(hash1, hash2)

    def test_deterministic_across_repeated_runs(self):
        self._write_inventory([
            {"line": "1", "function": "b", "target": "x", "op": "=", "category": "static",
             "data_source_tags": "", "rhs_len": "3", "rhs": "'a'"},
            {"line": "2", "function": "a", "target": "y", "op": "+=", "category": "unescaped_html",
             "data_source_tags": "user", "rhs_len": "1", "rhs": "v"},
        ])
        self._write_trace([])
        rows1 = merge_mod.merge(self.inv_path, self.trace_path)
        rows2 = merge_mod.merge(self.inv_path, self.trace_path)
        self.assertEqual(json.dumps(rows1), json.dumps(rows2))
        # Pins the row-ordering contract: sorted by (function, target, op, sink_id).
        self.assertEqual(rows1[0]["function"], "a")
        self.assertEqual(rows1[1]["function"], "b")

    def test_unresolvable_category_raises(self):
        self._write_inventory([{
            "line": "99", "function": "h", "target": "z", "op": "=",
            "category": "indirect_variable", "data_source_tags": "", "rhs_len": "1", "rhs": "w",
        }])
        self._write_trace([{
            "line": "99", "function": "h", "original_category": "indirect_variable",
            "resolved_category": "unclear", "notes": "no callable name found in rhs", "rhs": "w",
        }])
        with self.assertRaises(ValueError):
            merge_mod.merge(self.inv_path, self.trace_path)


if __name__ == "__main__":
    unittest.main()
