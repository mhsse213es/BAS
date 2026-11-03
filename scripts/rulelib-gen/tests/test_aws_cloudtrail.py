"""AWS CloudTrail rules are field-mapped for Sentinel (AWSCloudTrail), Splunk and Elastic. Defender XDR and CrowdStrike
have no CloudTrail source and stay generic. A field with no equivalent column/field in a backend is a recorded failure,
never a raw Sigma name."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


AWS = """
    title: Console Login Failure
    id: 12121212-1212-1212-1212-121212121212
    status: test
    logsource:
        product: aws
        service: cloudtrail
    detection:
        selection:
            eventSource: 'signin.amazonaws.com'
            eventName: 'ConsoleLogin'
            errorCode: 'Failed authentication'
        condition: selection
    level: medium
"""

NESTED = AWS.replace("errorCode: 'Failed authentication'", "requestParameters.attribute: 'x'")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_aws_cloudtrail():
    assert log_source_family(_rule(AWS)) == "aws_cloudtrail"
    assert log_source_family(_rule(AWS.replace("service: cloudtrail", "service: guardduty"))) == ""
    assert log_source_family(_rule(AWS.replace("product: aws", "product: gcp"))) == ""


def test_sentinel_uses_the_awscloudtrail_table_and_its_column_names():
    t = by_backend(translate_rule(_rule(AWS))[0])["microsoft_sentinel"]
    assert t["mapping"] == "pipeline" and t["pipeline"] and "AWSCloudTrail" in t["dataSource"]
    assert t["query"].startswith("AWSCloudTrail")
    for col in ("EventSource", "EventName", "ErrorCode"):
        assert col in t["query"], col
    assert "eventName" not in t["query"]


def test_splunk_is_pinned_to_the_cloudtrail_sourcetype_and_keeps_the_json_field_names():
    t = by_backend(translate_rule(_rule(AWS))[0])["splunk"]
    assert t["mapping"] == "pipeline" and t["pipeline"] and t["dataSource"]
    assert 'sourcetype="aws:cloudtrail"' in t["query"] and 'eventName="ConsoleLogin"' in t["query"]


def test_elastic_uses_filebeat_aws_cloudtrail_fields_and_dataset():
    t = by_backend(translate_rule(_rule(AWS))[0])["elastic"]
    assert t["mapping"] == "pipeline" and t["pipeline"] and t["dataSource"]
    q = t["query"]
    for field in ("event.action", "event.provider", "aws.cloudtrail.error_code", "event.dataset:aws.cloudtrail"):
        assert field in q, field
    assert "eventName" not in q


def test_a_nested_field_with_no_equivalent_is_a_recorded_failure_on_sentinel_and_elastic():
    ts, failures = translate_rule(_rule(NESTED))
    t = by_backend(ts)
    reasons = {f["backend"]: f["reason"] for f in failures}
    assert "microsoft_sentinel" not in t and "elastic" not in t
    assert "requestParameters.attribute" in reasons["elastic"]
    assert t["splunk"]["mapping"] == "pipeline"  # Splunk keeps the CloudTrail JSON path as is


def test_defender_and_crowdstrike_stay_generic():
    t = by_backend(translate_rule(_rule(AWS))[0])
    for b in ("microsoft_defender", "crowdstrike"):
        if b in t:
            assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", b
