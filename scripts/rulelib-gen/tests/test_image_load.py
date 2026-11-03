"""Windows image_load rules are field-mapped for Sentinel, Defender, Splunk, Elastic and CrowdStrike. A rule a mapped
backend cannot express (for example the Signed field) is a recorded failure, never a silent generic query."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


IMG = """
    title: Wmic Loads Script Engine
    id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    status: test
    logsource:
        category: image_load
        product: windows
    detection:
        selection:
            Image|endswith: '\\wmic.exe'
            ImageLoaded|endswith: '\\jscript.dll'
        condition: selection
    level: medium
"""

SIGNED = IMG.replace("ImageLoaded|endswith: '\\jscript.dll'", "Signed: 'false'")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_windows_image_load():
    assert log_source_family(_rule(IMG)) == "windows_image_load"
    assert log_source_family(_rule(IMG.replace("product: windows", "product: linux"))) == ""


def test_every_backend_is_mapped_and_names_its_data_source():
    t = by_backend(translate_rule(_rule(IMG))[0])
    for b in ("microsoft_sentinel", "microsoft_defender", "splunk", "elastic", "crowdstrike"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert t["microsoft_sentinel"]["query"].startswith("DeviceImageLoadEvents")
    assert t["microsoft_defender"]["query"].startswith("DeviceImageLoadEvents")
    assert "EventCode=7" in t["splunk"]["query"] and "Sysmon" in t["splunk"]["query"]
    assert "ClassifiedModuleLoad" in t["crowdstrike"]["query"]
    assert "ImageLoaded" not in t["elastic"]["query"]  # renamed to an ECS field


def test_a_field_a_backend_lacks_is_a_recorded_failure_not_a_generic_fallback():
    ts, failures = translate_rule(_rule(SIGNED))
    t = by_backend(ts)
    reasons = {f["backend"]: f["reason"] for f in failures}
    for b in ("microsoft_sentinel", "microsoft_defender", "crowdstrike"):
        assert b not in t and "Signed" in reasons[b], b
    assert t["splunk"]["mapping"] == "pipeline" and t["elastic"]["mapping"] == "pipeline"
