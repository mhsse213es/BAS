"""Windows Security-log rules (service: security) are field-mapped for Sentinel (SecurityEvent), Splunk and Elastic.
Defender XDR and CrowdStrike have no Security-event source, so they stay generic and say so. A rule a mapped backend
cannot express is a recorded failure, never a silent generic query."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


SEC = """
    title: Scheduled Task Created
    id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
    status: test
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 4698
            TargetUserName|contains: 'evil'
        condition: selection
    level: medium
"""

NOT_IN_TABLE = SEC.replace("TargetUserName|contains: 'evil'", "AttributeLDAPDisplayName: 'x'")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_the_windows_security_service():
    assert log_source_family(_rule(SEC)) == "windows_security"
    assert log_source_family(_rule(SEC.replace("service: security", "service: system"))) == ""
    assert log_source_family(_rule(SEC.replace("product: windows", "product: linux"))) == ""


def test_mapped_backends_name_their_table_channel_and_data_source():
    t = by_backend(translate_rule(_rule(SEC))[0])
    for b in ("microsoft_sentinel", "splunk", "elastic"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert t["microsoft_sentinel"]["query"].startswith("SecurityEvent")
    assert "EventID == 4698" in t["microsoft_sentinel"]["query"]
    assert 'source="WinEventLog:Security"' in t["splunk"]["query"] and "EventCode=4698" in t["splunk"]["query"]
    assert "winlog.channel:Security" in t["elastic"]["query"]


def test_defender_and_crowdstrike_stay_generic_not_guessed():
    t = by_backend(translate_rule(_rule(SEC))[0])
    for b in ("microsoft_defender", "crowdstrike"):
        if b in t:
            assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", b


def test_a_field_the_securityevent_table_lacks_is_a_recorded_failure():
    ts, failures = translate_rule(_rule(NOT_IN_TABLE))
    t = by_backend(ts)
    reasons = {f["backend"]: f["reason"] for f in failures}
    assert "microsoft_sentinel" not in t and "AttributeLDAPDisplayName" in reasons["microsoft_sentinel"]
    assert t["splunk"]["mapping"] == "pipeline"
