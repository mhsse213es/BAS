"""Windows process-creation rules get a per-SIEM field-mapping pipeline: the query names the real table / index /
event type and the real field names. Rules in any other log source stay generic and say so. A rule a mapped backend
cannot express is a recorded failure, never a silent fall back to a generic query."""
import copy
import os
import textwrap

from sigma.collection import SigmaCollection

from translate import BACKENDS, translate_rule

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_seed")


def _rule(yaml_text):
    return SigmaCollection.from_yaml(textwrap.dedent(yaml_text)).rules[0]


PROC = """
    title: Mimikatz Command Line
    id: 22222222-2222-2222-2222-222222222222
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            Image|endswith: '\\mimikatz.exe'
            CommandLine|contains: 'sekurlsa'
        condition: selection
    level: high
"""

PROC_UNSUPPORTED_BY_CROWDSTRIKE = PROC.replace("CommandLine|contains: 'sekurlsa'", "Description|contains: 'Mimikatz'")

NOT_PROC = """
    title: Registry Thing
    id: 33333333-3333-3333-3333-333333333333
    status: test
    logsource:
        category: webserver
        product: windows
    detection:
        selection:
            QueryName|contains: "evil"
        condition: selection
    level: low
"""


def by_backend(translations):
    return {t["backend"]: t for t in translations}


def test_process_creation_is_mapped_for_every_backend():
    translations, failures = translate_rule(_rule(PROC))
    assert failures == []
    t = by_backend(translations)
    assert t["microsoft_sentinel"]["query"].startswith("DeviceProcessEvents")
    assert t["microsoft_defender"]["query"].startswith("DeviceProcessEvents")
    assert "ProcessCommandLine" in t["microsoft_defender"]["query"]
    assert 'EventCode=1' in t["splunk"]["query"] and "Sysmon" in t["splunk"]["query"]
    assert "process.command_line" in t["elastic"]["query"]
    assert "ProcessRollup2" in t["crowdstrike"]["query"]
    for b, tr in t.items():
        assert tr["mapping"] == "pipeline", b
        assert tr["pipeline"], b
        assert tr["dataSource"], b  # what the customer must collect for this query to match anything


def test_other_log_sources_stay_generic_and_say_so():
    translations, _ = translate_rule(_rule(NOT_PROC))
    for tr in translations:
        assert tr["mapping"] == "generic"
        assert tr["pipeline"] == ""
        assert tr["dataSource"] == ""


def test_unmappable_field_is_a_failure_not_a_generic_fallback():
    translations, failures = translate_rule(_rule(PROC_UNSUPPORTED_BY_CROWDSTRIKE))
    assert "crowdstrike" not in by_backend(translations)
    assert [f["backend"] for f in failures] == ["crowdstrike"]
    assert "Description" in failures[0]["reason"]
    assert len(translations) == 4


def test_translating_does_not_alter_the_callers_rule():
    rule = _rule(PROC)
    before = copy.deepcopy(rule.to_dict())
    first, _ = translate_rule(rule)
    second, _ = translate_rule(rule)
    assert rule.to_dict() == before
    assert [t["query"] for t in first] == [t["query"] for t in second]


def test_backend_registry_is_extensible():
    # QRadar (or any later backend) is one more registry entry: it brings a key, a class, a language and mappings.
    for spec in BACKENDS.values():
        assert spec.language and spec.backend_cls and isinstance(spec.mappings, dict)
        assert "windows_process_creation" in spec.mappings
