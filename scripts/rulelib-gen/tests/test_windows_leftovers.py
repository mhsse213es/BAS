"""Last Sysmon / classic PowerShell categories: WMI events, Sysmon service status and errors, executable detected,
process tampering, PowerShell provider lifecycle."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def run(category, selection="Image|endswith: '\\\\x.exe'"):
    rule = SigmaCollection.from_yaml(textwrap.dedent(f"""
    title: Leftover
    id: 16161616-1616-1616-1616-161616161616
    status: test
    logsource:
        category: {category}
        product: windows
    detection:
        selection:
            {selection}
        condition: selection
    level: medium
""")).rules[0]
    return {t["backend"]: t for t in translate_rule(rule)[0]}


def test_each_category_is_a_family_and_maps_for_splunk_with_its_event_codes():
    cases = {
        "wmi_event": ("EventCode", (19, 20, 21)), "sysmon_status": ("EventCode", (4, 16)), "sysmon_error": ("EventCode", (255,)),
        "file_executable_detected": ("EventCode", (29,)), "process_tampering": ("EventCode", (25,)),
    }
    for cat, (_, codes) in cases.items():
        t = run(cat)["splunk"]
        assert t["mapping"] == "pipeline" and "Sysmon" in t["query"] and all(str(c) in t["query"] for c in codes), (cat, t["query"])


def test_classic_powershell_provider_start_is_event_600():
    t = run("ps_classic_provider_start", "Data|contains: 'Provider'")
    assert 'source="WinEventLog:Windows PowerShell"' in t["splunk"]["query"] and "EventCode=600" in t["splunk"]["query"]
    assert t["elastic"]["mapping"] == "pipeline" and "event.code:600" in t["elastic"]["query"]


def test_file_rename_is_still_generic_because_sysmon_has_no_rename_event():
    t = run("file_rename")
    assert all(x["mapping"] == "generic" for x in t.values())
