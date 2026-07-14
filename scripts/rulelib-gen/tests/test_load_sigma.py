import os

from load_sigma import load_rules, rule_technique_ids

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_seed")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def test_load_rules_filters_to_requested_techniques():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    assert len(rules) == 1
    assert rules[0].title == "Suspicious PowerShell Encoded Command"


def test_load_rules_returns_empty_for_unmatched_technique():
    rules = load_rules(SEED_DIR, technique_ids={"T9999.999"})
    assert rules == []


def test_load_rules_loads_multiple_matching_files():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001", "T1558.003"})
    assert len(rules) == 2


def test_rule_technique_ids_extracts_uppercase_technique_ids():
    rules = load_rules(SEED_DIR, technique_ids={"T1558.003"})
    assert rule_technique_ids(rules[0]) == {"T1558.003"}
