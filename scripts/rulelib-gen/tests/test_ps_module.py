"""Windows PowerShell module-logging rules (ps_module, event 4103) are field-mapped for Splunk only. Elastic's stock
pipeline renames Payload to the script-block field (event 4104), so mapping it would be wrong; Sentinel and Defender
have no table and CrowdStrike no event type. Those stay generic and say so."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


MOD = """
    title: Mshta In Module Log
    id: dddddddd-dddd-dddd-dddd-dddddddddddd
    status: test
    logsource:
        category: ps_module
        product: windows
    detection:
        selection:
            Payload|contains: 'mshta'
        condition: selection
    level: medium
"""


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_windows_ps_module():
    assert log_source_family(_rule(MOD)) == "windows_ps_module"
    assert log_source_family(_rule(MOD.replace("product: windows", "product: linux"))) == ""


def test_splunk_is_pinned_to_event_4103_in_the_powershell_log():
    t = by_backend(translate_rule(_rule(MOD))[0])["splunk"]
    assert t["mapping"] == "pipeline" and t["pipeline"] and t["dataSource"]
    assert "EventCode=4103" in t["query"] and "PowerShell/Operational" in t["query"]
    assert "module logging" in t["dataSource"].lower()


def test_every_other_backend_stays_generic():
    t = by_backend(translate_rule(_rule(MOD))[0])
    for b in ("microsoft_sentinel", "microsoft_defender", "elastic", "crowdstrike"):
        if b in t:
            assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", b
    # Elastic's pipeline would have called this a script block (event 4104): it must not be labelled mapped.
    assert "script_block_text" not in t["elastic"]["query"] or t["elastic"]["mapping"] == "generic"
