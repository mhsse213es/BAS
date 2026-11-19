"""Windows registry_set rules are field-mapped for Sentinel, Defender, Splunk and Elastic. CrowdStrike stays generic:
its pipeline emits Sysmon field names with no event type, so labelling it mapped would be false."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


REG = """
    title: Run Key Persistence
    id: 77777777-7777-7777-7777-777777777777
    status: test
    logsource:
        category: registry_set
        product: windows
    detection:
        selection:
            TargetObject|contains: '\\CurrentVersion\\Run'
            Details|contains: '\\Temp\\'
        condition: selection
    level: medium
"""


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_windows_registry_set():
    assert log_source_family(_rule(REG)) == "windows_registry_set"
    assert log_source_family(_rule(REG.replace("product: windows", "product: linux"))) == ""


def test_mapped_backends_name_their_table_event_and_data_source():
    t = by_backend(translate_rule(_rule(REG))[0])
    for b in ("microsoft_sentinel", "microsoft_defender", "splunk", "elastic"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert t["microsoft_sentinel"]["query"].startswith("DeviceRegistryEvents")
    assert t["microsoft_defender"]["query"].startswith("DeviceRegistryEvents")
    assert "EventCode=13" in t["splunk"]["query"] and "Sysmon" in t["splunk"]["query"]
    assert "registry.path" in t["elastic"]["query"]


def test_crowdstrike_stays_generic_not_falsely_mapped():
    t = by_backend(translate_rule(_rule(REG))[0])
    if "crowdstrike" in t:
        assert t["crowdstrike"]["mapping"] == "generic" and t["crowdstrike"]["dataSource"] == ""
