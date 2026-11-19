import pytest

from build import qradar_policy


def test_a_full_run_must_choose_qradar_or_opt_out_explicitly():
    with pytest.raises(SystemExit):
        qradar_policy(full=True, qradar_python="", no_qradar=False)


def test_a_full_run_can_use_the_isolated_environment_or_opt_out():
    assert qradar_policy(full=True, qradar_python="py", no_qradar=False) == "py"
    assert qradar_policy(full=True, qradar_python="", no_qradar=True) is None


def test_the_curated_seed_run_never_needs_qradar():
    assert qradar_policy(full=False, qradar_python="", no_qradar=False) is None


def test_both_flags_together_is_a_mistake():
    with pytest.raises(SystemExit):
        qradar_policy(full=True, qradar_python="py", no_qradar=True)
