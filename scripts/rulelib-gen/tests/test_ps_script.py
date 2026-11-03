"""Windows PowerShell script-block rules (ps_script) are field-mapped where a pipeline can express them. Sentinel and
Defender have no table for script-block text, so they stay generic and say so: nothing is guessed."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


PS = """
    title: Troubleshooting Pack Abuse
    id: 66666666-6666-6666-6666-666666666666
    status: test
    logsource:
        category: ps_script
        product: windows
    detection:
        selection:
            ScriptBlockText|contains|all:
                - 'Invoke-TroubleshootingPack'
                - '-AnswerFile'
        condition: selection
    level: medium
"""


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_family_recognised_only_for_windows_ps_script():
    assert log_source_family(_rule(PS)) == "windows_ps_script"
    assert log_source_family(_rule(PS.replace("product: windows", "product: linux"))) == ""


def test_mapped_where_a_pipeline_can_express_it_and_named_with_its_data_source():
    t = by_backend(translate_rule(_rule(PS))[0])
    for b in ("splunk", "elastic", "crowdstrike"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert "4104" in t["splunk"]["query"] and "PowerShell/Operational" in t["splunk"]["query"]
    assert "4104" in t["splunk"]["dataSource"]
    assert "powershell.file.script_block_text" in t["elastic"]["query"]
    assert "script block" in t["elastic"]["dataSource"].lower()


def test_sentinel_and_defender_stay_generic_not_guessed():
    t = by_backend(translate_rule(_rule(PS))[0])
    for b in ("microsoft_sentinel", "microsoft_defender"):
        if b in t:
            assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", b
