"""Windows file_event rules are field-mapped for Sentinel, Defender, Splunk and Elastic. CrowdStrike stays generic: its
pipeline emits Sysmon field names with no event type, so labelling it mapped would be false. A rule a mapped backend
cannot express is a recorded failure, never a silent generic query."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


FILE = """
    title: Script Drops File In Temp
    id: 88888888-8888-8888-8888-888888888888
    status: test
    logsource:
        category: file_event
        product: windows
    detection:
        selection:
            Image|endswith: '\\wscript.exe'
            TargetFilename|contains: '\\Temp\\'
        condition: selection
    level: medium
"""


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_windows_file_event():
    assert log_source_family(_rule(FILE)) == "windows_file_event"
    assert log_source_family(_rule(FILE.replace("product: windows", "product: linux"))) == ""


def test_mapped_backends_name_their_table_event_and_data_source():
    t = by_backend(translate_rule(_rule(FILE))[0])
    for b in ("microsoft_sentinel", "microsoft_defender", "splunk", "elastic"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert t["microsoft_sentinel"]["query"].startswith("DeviceFileEvents")
    assert t["microsoft_defender"]["query"].startswith("DeviceFileEvents")
    assert "EventCode=11" in t["splunk"]["query"] and "Sysmon" in t["splunk"]["query"]
    assert "file.path" in t["elastic"]["query"]


def test_crowdstrike_stays_generic_not_falsely_mapped():
    t = by_backend(translate_rule(_rule(FILE))[0])
    if "crowdstrike" in t:
        assert t["crowdstrike"]["mapping"] == "generic" and t["crowdstrike"]["dataSource"] == ""
