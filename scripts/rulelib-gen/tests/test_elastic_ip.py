"""Elasticsearch rejects (strict) or silently never matches (lenient) a wildcard on an `ip`-typed field; only CIDR
and exact values work there. Verified against Elasticsearch 8.15 on staging. These pin the rewrite."""
from elastic_ip import fix_ip_wildcards


def test_prefix_wildcard_becomes_cidr():
    q = r"destination.ip:(127.* OR \:\:1)"
    assert fix_ip_wildcards(q) == r'destination.ip:("127.0.0.0/8" OR \:\:1)'


def test_longer_prefixes():
    assert fix_ip_wildcards("source.ip:192.168.*") == 'source.ip:"192.168.0.0/16"'
    assert fix_ip_wildcards("source.ip:10.1.2.*") == 'source.ip:"10.1.2.0/24"'


def test_branch_that_can_never_be_an_ip_is_dropped():
    q = r"(source.ip:*\-* OR (source.ip:10.0.0.0\/8 OR source.ip:127.0.0.0\/8))"
    assert fix_ip_wildcards(q) == r"((source.ip:10.0.0.0\/8 OR source.ip:127.0.0.0\/8))"
    q2 = r"(source.ip:10.0.0.0\/8 OR source.ip:*\-*)"
    assert fix_ip_wildcards(q2) == r"(source.ip:10.0.0.0\/8)"


def test_other_fields_and_exact_ips_untouched():
    q = r"process.executable:*\cmd.exe AND source.ip:10.0.0.1 AND message:127.*"
    assert fix_ip_wildcards(q) == q


def test_unexpressible_sole_condition_is_reported_not_guessed():
    import pytest
    from elastic_ip import UnexpressibleOnIpField
    with pytest.raises(UnexpressibleOnIpField):
        fix_ip_wildcards(r"source.ip:*\-*")
