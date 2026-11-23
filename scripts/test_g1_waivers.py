"""Reviewed-regression waivers for the G1 XSS-sink guard.

A waiver records that a human or reviewer read a specific sink that the guard rates worse than the baseline and found it
acceptable. It is pinned to the slot, the tier change AND the sink's content-hash id, so editing the sink, or adding a
second sink at the same tier, makes the guard fail again.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("g1_guard_w", REPO_ROOT / "scripts" / "g1-check-no-regression.py")
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def sink(function, tier, sid, target="el", op="="):
    return {"sink_id": sid, "line": 1, "function": function, "target": target, "op": op, "baseline_category": "x",
            "final_category": "escaped", "severity_tier": tier, "data_source_tags": "", "trace_notes": "", "rhs": "x"}


def waiver(function="f", from_tier=0, to_tier=1, sink_ids=("f:el:=:aaa",), target="el", op="=", **over):
    w = {"function": function, "target": target, "op": op, "from_tier": from_tier, "to_tier": to_tier,
         "sink_ids": list(sink_ids), "reason": "read the sink; every value is escaped",
         "reviewed_by": "someone", "reviewed_on": "2026-11-23"}
    w.update(over)
    return w


def regression(function="f", old=0, new=1):
    return ((function, "el", "="), old, new)


class TestApplyWaivers(unittest.TestCase):
    def test_a_matching_waiver_clears_the_regression_and_reports_it(self):
        remaining, waived, stale = guard.apply_waivers([regression()], [sink("f", 1, "f:el:=:aaa")], [waiver()])
        self.assertEqual(remaining, [])
        self.assertEqual(len(waived), 1)
        self.assertEqual(stale, [])

    def test_an_edited_sink_is_no_longer_waived(self):
        # the sink's source changed, so its content-hash id changed
        remaining, waived, _ = guard.apply_waivers([regression()], [sink("f", 1, "f:el:=:bbb")], [waiver()])
        self.assertEqual(remaining, [regression()])
        self.assertEqual(waived, [])

    def test_an_extra_sink_at_the_same_tier_is_not_covered(self):
        sinks = [sink("f", 1, "f:el:=:aaa"), sink("f", 1, "f:el:=:ccc")]
        remaining, _, _ = guard.apply_waivers([regression()], sinks, [waiver()])
        self.assertEqual(remaining, [regression()])

    def test_the_tier_change_must_match_exactly(self):
        for w in (waiver(from_tier=1, to_tier=2), waiver(from_tier=0, to_tier=2)):
            remaining, _, _ = guard.apply_waivers([regression(old=0, new=1)], [sink("f", 1, "f:el:=:aaa")], [w])
            self.assertEqual(remaining, [regression(old=0, new=1)])

    def test_a_waiver_for_a_worse_tier_does_not_excuse_a_better_one_or_the_reverse(self):
        # waived 0 -> 1, but the sink is now tier 4: that is a different, unreviewed regression
        remaining, _, _ = guard.apply_waivers([regression(old=0, new=4)], [sink("f", 4, "f:el:=:aaa")], [waiver()])
        self.assertEqual(remaining, [regression(old=0, new=4)])

    def test_other_slots_are_unaffected(self):
        remaining, _, _ = guard.apply_waivers([regression("g")], [sink("g", 1, "g:el:=:aaa")], [waiver("f")])
        self.assertEqual(remaining, [regression("g")])

    def test_two_regressions_in_the_same_slot_are_both_covered_by_one_waiver(self):
        sinks = [sink("f", 1, "f:el:=:aaa"), sink("f", 1, "f:el:=:bbb")]
        w = waiver(sink_ids=("f:el:=:aaa", "f:el:=:bbb"))
        remaining, waived, _ = guard.apply_waivers([regression(), regression()], sinks, [w])
        self.assertEqual(remaining, [])
        self.assertEqual(len(waived), 2)

    def test_a_waiver_matching_no_regression_is_reported_stale_not_failed(self):
        remaining, waived, stale = guard.apply_waivers([], [sink("f", 0, "f:el:=:aaa")], [waiver()])
        self.assertEqual((remaining, waived), ([], []))
        self.assertEqual(len(stale), 1)


class TestLoadWaivers(unittest.TestCase):
    def write(self, data):
        p = Path(tempfile.mkdtemp()) / "w.json"
        p.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return p

    def test_missing_file_means_no_waivers(self):
        self.assertEqual(guard.load_waivers(Path(tempfile.mkdtemp()) / "nope.json"), [])

    def test_valid_file_loads(self):
        self.assertEqual(len(guard.load_waivers(self.write({"version": 1, "waivers": [waiver()]}))), 1)

    def test_malformed_files_are_errors_not_silently_ignored(self):
        bad = [
            "not json",
            {"version": 2, "waivers": []},
            {"version": 1},
            {"version": 1, "waivers": [waiver(reason="")]},
            {"version": 1, "waivers": [waiver(reviewed_by="  ")]},
            {"version": 1, "waivers": [waiver(reviewed_on="yesterday")]},
            {"version": 1, "waivers": [waiver(sink_ids=())]},
            {"version": 1, "waivers": [waiver(from_tier=2, to_tier=1)]},
            {"version": 1, "waivers": [waiver(from_tier="0")]},
            {"version": 1, "waivers": [waiver(), waiver()]},
            {"version": 1, "waivers": [{"function": "f"}]},
        ]
        for data in bad:
            with self.assertRaises(ValueError, msg=str(data)):
                guard.load_waivers(self.write(data))


if __name__ == "__main__":
    unittest.main()
