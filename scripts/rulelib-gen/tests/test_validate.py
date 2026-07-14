import pytest

from validate import ValidationError, validate_build


def _rule(rule_id="AUDRULE-000001", sigma_id="sig-1", techniques=("T1059.001",), translations=None, failures=None):
    return {
        "id": rule_id,
        "sigmaId": sigma_id,
        "techniqueIds": list(techniques),
        "translations": translations if translations is not None else [{"backend": "splunk"}],
        "failures": failures if failures is not None else [],
    }


def test_validate_build_passes_on_healthy_input():
    validate_build([_rule()], known_technique_ids={"T1059.001"})  # should not raise


def test_validate_build_fails_on_zero_translation_rule():
    rule = _rule(translations=[], failures=[{"backend": "splunk", "reason": "x"}])
    with pytest.raises(ValidationError, match="zero successful translations"):
        validate_build([rule], known_technique_ids={"T1059.001"})


def test_validate_build_fails_on_unknown_technique_id():
    rule = _rule(techniques=("T9999.999",))
    with pytest.raises(ValidationError, match="unrecognized ATT&CK technique"):
        validate_build([rule], known_technique_ids={"T1059.001"})


def test_validate_build_fails_on_duplicate_rule_id():
    rules = [_rule(rule_id="AUDRULE-000001"), _rule(rule_id="AUDRULE-000001", sigma_id="sig-2")]
    with pytest.raises(ValidationError, match="duplicate rule id"):
        validate_build(rules, known_technique_ids={"T1059.001"})


def test_validate_build_fails_on_duplicate_sigma_id():
    rules = [_rule(rule_id="AUDRULE-000001", sigma_id="sig-1"), _rule(rule_id="AUDRULE-000002", sigma_id="sig-1")]
    with pytest.raises(ValidationError, match="duplicate sigma id"):
        validate_build(rules, known_technique_ids={"T1059.001"})


def test_validate_build_passes_below_failure_threshold():
    # 2 of 10 rules fail on "splunk" = 20%, below the 25% threshold — warn, don't fail.
    rules = [_rule(rule_id=f"AUDRULE-{i:06d}", sigma_id=f"sig-{i}") for i in range(8)]
    rules += [
        _rule(rule_id="AUDRULE-000008", sigma_id="sig-8", translations=[{"backend": "elastic"}],
              failures=[{"backend": "splunk", "reason": "x"}]),
        _rule(rule_id="AUDRULE-000009", sigma_id="sig-9", translations=[{"backend": "elastic"}],
              failures=[{"backend": "splunk", "reason": "x"}]),
    ]
    validate_build(rules, known_technique_ids={"T1059.001"})  # should not raise


def test_validate_build_fails_above_failure_threshold():
    # 3 of 10 rules fail on "splunk" = 30%, above the 25% threshold — systemic regression guard.
    rules = [_rule(rule_id=f"AUDRULE-{i:06d}", sigma_id=f"sig-{i}") for i in range(7)]
    rules += [
        _rule(rule_id=f"AUDRULE-{i:06d}", sigma_id=f"sig-{i}", translations=[{"backend": "elastic"}],
              failures=[{"backend": "splunk", "reason": "x"}])
        for i in range(7, 10)
    ]
    with pytest.raises(ValidationError, match="backend .* failure rate"):
        validate_build(rules, known_technique_ids={"T1059.001"})
