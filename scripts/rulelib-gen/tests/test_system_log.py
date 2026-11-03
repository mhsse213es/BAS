"""Windows System-log rules (service: system) are field-mapped for Splunk and Elastic only. Sentinel's pipelines would
put them in SecurityEvent, the wrong table (the System log is in Event with different fields), and Defender XDR and
CrowdStrike have no System-event source, so those stay generic and say so."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


SYS = """
    title: Service Installed
    id: cccccccc-cccc-cccc-cccc-cccccccccccc
    status: test
    logsource:
        product: windows
        service: system
    detection:
        selection:
            Provider_Name: 'Service Control Manager'
            EventID: 7045
        condition: selection
    level: medium
"""


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_the_windows_system_service():
    assert log_source_family(_rule(SYS)) == "windows_system"
    assert log_source_family(_rule(SYS.replace("service: system", "service: security"))) == "windows_security"
    assert log_source_family(_rule(SYS.replace("product: windows", "product: linux"))) == ""


def test_splunk_and_elastic_are_mapped_with_their_channel_and_data_source():
    t = by_backend(translate_rule(_rule(SYS))[0])
    for b in ("splunk", "elastic"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert 'source="WinEventLog:System"' in t["splunk"]["query"] and "EventCode=7045" in t["splunk"]["query"]
    assert "winlog.channel:System" in t["elastic"]["query"]


def test_sentinel_defender_and_crowdstrike_stay_generic_never_pointed_at_the_wrong_table():
    ts, _ = translate_rule(_rule(SYS))
    t = by_backend(ts)
    for b in ("microsoft_sentinel", "microsoft_defender", "crowdstrike"):
        if b in t:
            assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", b
            assert "SecurityEvent" not in t[b]["query"], b
