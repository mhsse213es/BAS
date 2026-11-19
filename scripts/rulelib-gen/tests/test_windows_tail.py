"""The long tail of Windows log sources: event-log services (mapped only where the pipeline's output carries the source or
channel), Sysmon categories (our Splunk pipelines, stock pipelines elsewhere where they are correct) and the integrity
gate that turns a leaked pySigma object into a recorded failure."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, looks_corrupt, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


def rule_for(logsource, selection):
    ls = "\n".join(f"        {k}: {v}" for k, v in logsource.items())
    return _rule(f"""
    title: Tail Rule
    id: 14141414-1414-1414-1414-141414141414
    status: test
    logsource:
{ls}
    detection:
        selection:
            {selection}
        condition: selection
    level: medium
""")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_the_integrity_gate_catches_leaked_pysigma_objects():
    assert looks_corrupt("winlog.event_data.CallTrace:SigmaRegularExpression(regexp=SigmaString(['^C']))")
    assert looks_corrupt("x:SigmaString(['a'])") and looks_corrupt("x:SigmaNumber(5)")
    assert not looks_corrupt('Image="*\\\\cmd.exe" CommandLine="*Sigma*"')


# ── event-log services ────────────────────────────────────────────────────────────────────────────────────────
def test_event_log_services_are_a_family_but_security_and_system_keep_theirs():
    assert log_source_family(rule_for({"product": "windows", "service": "windefend"}, "EventID: 5007")) == "windows_eventlog"
    assert log_source_family(rule_for({"product": "windows", "service": "security"}, "EventID: 1")) == "windows_security"
    assert log_source_family(rule_for({"product": "windows", "service": "system"}, "EventID: 1")) == "windows_system"
    assert log_source_family(rule_for({"product": "linux", "service": "windefend"}, "EventID: 1")) == ""


def test_a_recognised_service_maps_for_splunk_and_elastic_with_its_source_and_channel():
    t = by_backend(translate_rule(rule_for({"product": "windows", "service": "windefend"}, "EventID: 5007"))[0])
    assert t["splunk"]["mapping"] == "pipeline" and t["splunk"]["dataSource"] and 'source="' in t["splunk"]["query"]
    assert t["elastic"]["mapping"] == "pipeline" and t["elastic"]["dataSource"] and "winlog.channel" in t["elastic"]["query"]
    for b in ("microsoft_sentinel", "microsoft_defender", "crowdstrike"):
        if b in t:
            assert t[b]["mapping"] == "generic", b


def test_a_service_the_pipelines_do_not_know_stays_generic_not_falsely_mapped():
    t = by_backend(translate_rule(rule_for({"product": "windows", "service": "iis-configuration"}, "EventID: 29"))[0])
    for b in ("splunk", "elastic"):
        assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", b


# ── Sysmon and other categories ───────────────────────────────────────────────────────────────────────────────
def test_splunk_gets_the_sysmon_event_codes_for_each_category():
    cases = {
        "process_access": "EventCode=10", "dns_query": "EventCode=22", "driver_load": "EventCode=6",
        "create_remote_thread": "EventCode=8", "registry_delete": "EventCode=12",
    }
    for cat, code in cases.items():
        t = by_backend(translate_rule(rule_for({"category": cat, "product": "windows"}, "Image|endswith: '\\\\x.exe'"))[0])["splunk"]
        assert t["mapping"] == "pipeline" and t["dataSource"] and "Sysmon" in t["query"] and code in t["query"], (cat, t["query"])


def test_categories_with_several_sysmon_events_list_them_all():
    for cat, codes in (("registry_event", (12, 13, 14)), ("pipe_created", (17, 18)), ("file_delete", (23, 26))):
        q = by_backend(translate_rule(rule_for({"category": cat, "product": "windows"}, "Image|endswith: '\\\\x.exe'"))[0])["splunk"]["query"]
        assert all(str(c) in q for c in codes), (cat, q)


def test_classic_powershell_start_is_event_400_in_the_windows_powershell_log():
    t = by_backend(translate_rule(rule_for({"category": "ps_classic_start", "product": "windows"}, "Data|contains: 'HostName=ConsoleHost'"))[0])
    assert 'source="WinEventLog:Windows PowerShell"' in t["splunk"]["query"] and "EventCode=400" in t["splunk"]["query"]
    assert t["elastic"]["mapping"] == "pipeline" and "winlog.channel:Windows" in t["elastic"]["query"] and "event.code:400" in t["elastic"]["query"]


def test_elastic_maps_dns_and_registry_but_not_process_access_whose_regex_output_is_corrupt():
    dns = by_backend(translate_rule(rule_for({"category": "dns_query", "product": "windows"}, "QueryName|endswith: '.evil.com'"))[0])
    assert dns["elastic"]["mapping"] == "pipeline" and "dns.question.name" in dns["elastic"]["query"]
    pa = by_backend(translate_rule(rule_for({"category": "process_access", "product": "windows"}, "CallTrace|re: '^C:.*'"))[0])
    assert pa["elastic"]["mapping"] == "generic"
    assert not looks_corrupt(pa["elastic"]["query"])


def test_sentinel_maps_registry_and_file_delete_and_crowdstrike_maps_dns():
    reg = by_backend(translate_rule(rule_for({"category": "registry_delete", "product": "windows"}, "TargetObject|endswith: 'Run'"))[0])
    assert reg["microsoft_sentinel"]["mapping"] == "pipeline" and reg["microsoft_sentinel"]["query"].startswith("DeviceRegistryEvents")
    fd = by_backend(translate_rule(rule_for({"category": "file_delete", "product": "windows"}, "TargetFilename|endswith: '.bak'"))[0])
    assert fd["microsoft_sentinel"]["query"].startswith("DeviceFileEvents")
    dns = by_backend(translate_rule(rule_for({"category": "dns_query", "product": "windows"}, "QueryName|endswith: '.evil.com'"))[0])
    assert dns["crowdstrike"]["mapping"] == "pipeline" and "DnsRequest" in dns["crowdstrike"]["query"]


def test_file_access_is_not_mapped_for_sentinel_because_file_events_are_not_read_access():
    t = by_backend(translate_rule(rule_for({"category": "file_access", "product": "windows"}, "FileName|endswith: 'SAM'"))[0])
    for b in ("microsoft_sentinel", "microsoft_defender"):
        if b in t:
            assert t[b]["mapping"] == "generic", b
