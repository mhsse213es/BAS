"""macOS process_creation rules are field-mapped for Sentinel, Defender, CrowdStrike (stock pipelines) and Elastic (our
ECS pipeline, shared with Linux). Splunk stays generic: no source/sourcetype this generator can state truthfully."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


MAC = """
    title: Osascript From Browser
    id: ffffffff-ffff-ffff-ffff-ffffffffffff
    status: test
    logsource:
        category: process_creation
        product: macos
    detection:
        selection:
            ParentImage|contains: 'Safari'
            Image|endswith: '/osascript'
            CommandLine|contains: 'display dialog'
        condition: selection
    level: medium
"""

LOGONID = MAC.replace("CommandLine|contains: 'display dialog'", "LogonId: '0'")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_macos_process_creation():
    assert log_source_family(_rule(MAC)) == "macos_process_creation"
    assert log_source_family(_rule(MAC.replace("product: macos", "product: linux"))) == "linux_process_creation"


def test_stock_pipelines_map_sentinel_defender_and_crowdstrike():
    t = by_backend(translate_rule(_rule(MAC))[0])
    for b in ("microsoft_sentinel", "microsoft_defender", "crowdstrike"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert t["microsoft_sentinel"]["query"].startswith("DeviceProcessEvents")
    assert "macOS" in t["microsoft_sentinel"]["dataSource"]
    assert "event_platform=/^Mac$/i" in t["crowdstrike"]["query"]


def test_elastic_uses_ecs_process_fields_and_a_process_start_condition():
    t = by_backend(translate_rule(_rule(MAC))[0])["elastic"]
    assert t["mapping"] == "pipeline" and t["pipeline"] and "macOS" in t["dataSource"]
    q = t["query"]
    for field in ("process.executable", "process.command_line", "process.parent.executable"):
        assert field in q, field
    assert "event.type:start" in q and "Image" not in q


def test_a_field_with_no_ecs_equivalent_is_a_recorded_failure_naming_it():
    ts, failures = translate_rule(_rule(LOGONID))
    assert "elastic" not in by_backend(ts)
    assert "LogonId" in {f["backend"]: f["reason"] for f in failures}["elastic"]


def test_splunk_stays_generic_not_guessed():
    t = by_backend(translate_rule(_rule(MAC))[0])["splunk"]
    assert t["mapping"] == "generic" and t["dataSource"] == ""
