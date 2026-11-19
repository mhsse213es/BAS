"""Every translation says how much is known about it: none (generic), documented, assumed. 'validated' is reserved for
mappings that have matched a positive and a negative sample event, which the generator never sets on its own."""
import textwrap

from sigma.collection import SigmaCollection

from translate import translate_rule


def translations(logsource, selection):
    ls = "\n".join(f"        {k}: {v}" for k, v in logsource.items())
    rule = SigmaCollection.from_yaml(textwrap.dedent(f"""
    title: V
    id: 17171717-1717-1717-1717-171717171717
    status: test
    logsource:
{ls}
    detection:
        selection:
            {selection}
        condition: selection
    level: low
""")).rules[0]
    return {t["backend"]: t for t in translate_rule(rule)[0]}


def test_generic_is_none_and_mapped_is_never_validated_by_the_generator():
    t = translations({"category": "process_creation", "product": "windows"}, "Image|endswith: '\\cmd.exe'")
    assert t["splunk"]["verification"] in ("documented", "assumed")
    generic = translations({"category": "webserver"}, "cs-method: GET")
    assert generic["crowdstrike"]["mapping"] == "generic" and generic["crowdstrike"]["verification"] == "none"
    for ts in (t, generic):
        assert all(x["verification"] != "validated" for x in ts.values())


def test_a_mapping_whose_data_source_says_unverified_is_assumed_and_the_label_cannot_disagree():
    dns = translations({"category": "dns"}, "query|endswith: '.evil.com'")
    assert "nverified" in dns["splunk"]["dataSource"] and dns["splunk"]["verification"] == "assumed"
    okta = translations({"product": "okta", "service": "okta"}, "eventType: user.session.start")
    assert "nverified" not in okta["splunk"]["dataSource"] and okta["splunk"]["verification"] == "documented"
