"""Windows network-connection rules get a per-SIEM field-mapping pipeline, like process creation. Every mapped
translation names its pipeline and the data source the customer must collect; a rule a backend cannot express is a
recorded failure, never a silent generic query."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


NET = """
    title: Regasm Outbound
    id: 44444444-4444-4444-4444-444444444444
    status: test
    logsource:
        category: network_connection
        product: windows
    detection:
        selection:
            Image|endswith: '\\regasm.exe'
            Initiated: 'true'
            DestinationPort: 443
        condition: selection
    level: medium
"""

NET_IPV6 = NET.replace("DestinationPort: 443", "SourceIsIpv6: 'true'")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_the_family_is_recognised_and_only_for_windows_network_connection():
    assert log_source_family(_rule(NET)) == "windows_network_connection"
    linux = NET.replace("product: windows", "product: linux")
    assert log_source_family(_rule(linux)) == ""


def test_every_backend_is_mapped_and_names_its_data_source():
    ts, failures = translate_rule(_rule(NET))
    t = by_backend(ts)
    for b in ("microsoft_sentinel", "microsoft_defender", "splunk", "elastic", "crowdstrike"):
        assert t[b]["mapping"] == "pipeline" and t[b]["pipeline"] and t[b]["dataSource"], b
    assert t["microsoft_sentinel"]["query"].startswith("DeviceNetworkEvents")
    assert t["microsoft_defender"]["query"].startswith("DeviceNetworkEvents")
    assert "NetworkConnectIP4" in t["crowdstrike"]["query"]
    assert not [f for f in failures if f["backend"] != "crowdstrike"]


def test_splunk_is_pinned_to_sysmon_event_3_so_the_query_has_a_source():
    q = by_backend(translate_rule(_rule(NET))[0])["splunk"]["query"]
    assert "EventCode=3" in q and "Sysmon" in q
    assert "Sysmon" in by_backend(translate_rule(_rule(NET))[0])["splunk"]["dataSource"]


def test_elastic_initiated_becomes_egress_not_a_boolean():
    """pySigma's ecs_windows writes network.direction:true, which no ECS data contains. ECS (and Winlogbeat's Sysmon
    module) use egress/ingress, so the pipeline corrects the value."""
    q = by_backend(translate_rule(_rule(NET))[0])["elastic"]["query"]
    assert "network.direction:egress" in q
    assert "network.direction:true" not in q
    q_in = by_backend(translate_rule(_rule(NET.replace("Initiated: 'true'", "Initiated: 'false'")))[0])["elastic"]["query"]
    assert "network.direction:ingress" in q_in


def test_a_field_the_xdr_tables_lack_is_a_recorded_failure_not_a_generic_fallback():
    ts, failures = translate_rule(_rule(NET_IPV6))
    t = by_backend(ts)
    assert "microsoft_sentinel" not in t and "microsoft_defender" not in t
    reasons = {f["backend"]: f["reason"] for f in failures}
    assert "SourceIsIpv6" in reasons["microsoft_sentinel"] and "SourceIsIpv6" in reasons["microsoft_defender"]
    assert t["splunk"]["mapping"] == "pipeline"  # the other SIEMs are unaffected


def test_other_log_sources_are_still_generic():
    registry = """
        title: Run Key
        id: 55555555-5555-5555-5555-555555555555
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            selection:
                TargetObject|contains: 'Run'
            condition: selection
        level: low
    """
    for tr in translate_rule(_rule(registry))[0]:
        assert tr["mapping"] == "generic" and tr["pipeline"] == "" and tr["dataSource"] == ""
