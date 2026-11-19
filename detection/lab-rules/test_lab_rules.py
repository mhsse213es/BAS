"""Tests for the lab detection rules.

Each rule must (1) parse with pySigma, (2) match every positive fixture event and
(3) match no negative event. The matcher here implements only the Sigma subset these
rules use: plain field lists (OR), case-insensitive equality, and a condition that is a
single selection or two selections joined by `and`. A rule that needs anything else
fails the test loudly instead of being matched wrongly.

Run: python -m pytest detection/lab-rules -q
"""
import glob
import json
import os
import re

import pytest
import yaml
from sigma.collection import SigmaCollection

HERE = os.path.dirname(__file__)
RULES = sorted(glob.glob(os.path.join(HERE, "rules", "*.yml")))


def _load(path):
    with open(path, encoding="utf-8") as f:
        return SigmaCollection.from_yaml(f.read()).rules


def _fixture(rule_path):
    name = os.path.splitext(os.path.basename(rule_path))[0]
    with open(os.path.join(HERE, "fixtures", name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def _selection_matches(selection, event):
    for field, expected in selection.items():
        values = expected if isinstance(expected, list) else [expected]
        actual = str(event.get(field, ""))
        if not any(actual.lower() == str(v).lower() for v in values):
            return False
    return True


def _matches(detection, event):
    condition = detection["condition"].strip()
    names = [n for n in re.split(r"\s+and\s+", condition)]
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n) for n in names):
        raise ValueError(f"unsupported condition for this matcher: {condition!r}")
    return all(_selection_matches(detection[n], event) for n in names)


@pytest.mark.parametrize("path", RULES, ids=lambda p: os.path.basename(p))
def test_rule_parses_with_pysigma(path):
    rules = _load(path)
    assert len(rules) == 1


@pytest.mark.parametrize("path", RULES, ids=lambda p: os.path.basename(p))
def test_rule_matches_positive_and_not_negative(path):
    with open(path, encoding="utf-8") as f:
        detection = yaml.safe_load(f)["detection"]
    fx = _fixture(path)
    assert fx["positive"], "every rule needs at least one positive fixture"
    assert fx["negative"], "every rule needs at least one negative fixture"
    for ev in fx["positive"]:
        assert _matches(detection, ev), f"positive event did not match: {ev}"
    for ev in fx["negative"]:
        assert not _matches(detection, ev), f"negative event matched: {ev}"
