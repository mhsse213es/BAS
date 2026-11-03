"""Linux process_creation rules are field-mapped for Sentinel, Defender, CrowdStrike (stock pipelines) and Elastic (our ECS
pipeline). Splunk stays generic: Sigma's Linux field names are Sysmon for Linux's and the Splunk source/sourcetype for it
is not something this generator can state truthfully. A field with no ECS equivalent is a recorded failure."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


LIN = """
    title: Curl Upload
    id: eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee
    status: test
    logsource:
        category: process_creation
        product: linux
    detection:
        selection:
            Image|endswith: '/curl'
            CommandLine|contains: ' --upload-file '
            ParentImage|endswith: '/bash'
            User: 'root'
        condition: selection
    level: medium
"""

LOGONID = LIN.replace("User: 'root'", "LogonId: '0'")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_linux_process_creation():
    assert log_source_family(_rule(LIN)) == "linux_process_creation"
    assert log_source_family(_rule(LIN.replace("product: linux", "product: macos"))) == ""
    assert log_source_family(_rule(LIN.replace("product: linux", "product: windows"))) == "windows_process_creation"


def test_stock_pipelines_map_sentinel_defender_and_crowdstrike():
    t = by_backend(translate_rule(_rule(LIN))[0])
    for b in ("microsoft_sentinel", "microsoft_defender", "crowdstrike"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert t["microsoft_sentinel"]["query"].startswith("DeviceProcessEvents")
    assert "Linux" in t["microsoft_sentinel"]["dataSource"]
    assert "event_platform=/^Lin$/i" in t["crowdstrike"]["query"]


def test_elastic_uses_ecs_process_fields_and_a_process_start_condition():
    t = by_backend(translate_rule(_rule(LIN))[0])["elastic"]
    assert t["mapping"] == "pipeline" and t["pipeline"] and t["dataSource"]
    q = t["query"]
    for field in ("process.executable", "process.command_line", "process.parent.executable", "user.name"):
        assert field in q, field
    assert "event.category:process" in q and "event.type:start" in q
    assert "Image" not in q and "CommandLine" not in q


def test_a_field_with_no_ecs_equivalent_is_a_recorded_failure_not_a_raw_name():
    ts, failures = translate_rule(_rule(LOGONID))
    assert "elastic" not in by_backend(ts)
    assert "LogonId" in {f["backend"]: f["reason"] for f in failures}["elastic"]


def test_splunk_stays_generic_not_guessed():
    t = by_backend(translate_rule(_rule(LIN))[0])["splunk"]
    assert t["mapping"] == "generic" and t["dataSource"] == ""
