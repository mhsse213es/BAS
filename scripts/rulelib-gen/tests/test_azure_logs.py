"""Azure activity, audit and sign-in log rules are field-mapped for Sentinel only (AzureActivity, AuditLogs, SigninLogs).
Splunk, Elastic, Defender XDR and CrowdStrike stay generic and say so. A field the table lacks is a recorded failure."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, translate_rule


def _rule(text):
    return SigmaCollection.from_yaml(textwrap.dedent(text)).rules[0]


def azure(service, selection):
    return f"""
    title: Azure Rule
    id: 13131313-1313-1313-1313-131313131313
    status: test
    logsource:
        product: azure
        service: {service}
    detection:
        selection:
            {selection}
        condition: selection
    level: medium
"""


ACTIVITY = azure("activitylogs", "operationName: 'MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION'")
AUDIT = azure("auditlogs", "properties.message: 'Add conditional access policy'")
SIGNIN = azure("signinlogs", "ResultType: '50057'")
NO_COLUMN = azure("activitylogs", "someMadeUpField: 'x'")


def by_backend(ts):
    return {t["backend"]: t for t in ts}


def test_families_recognised():
    assert log_source_family(_rule(ACTIVITY)) == "azure_activitylogs"
    assert log_source_family(_rule(AUDIT)) == "azure_auditlogs"
    assert log_source_family(_rule(SIGNIN)) == "azure_signinlogs"
    assert log_source_family(_rule(azure("pim", "riskEventType: 'x'"))) == ""
    assert log_source_family(_rule(ACTIVITY.replace("product: azure", "product: aws"))) == ""


def test_sentinel_uses_the_right_table_and_column_for_each_log():
    for rule, table, column in ((ACTIVITY, "AzureActivity", "OperationNameValue"),
                                (AUDIT, "AuditLogs", "OperationName"),
                                (SIGNIN, "SigninLogs", "ResultType")):
        t = by_backend(translate_rule(_rule(rule))[0])["microsoft_sentinel"]
        assert t["mapping"] == "pipeline" and t["pipeline"] and table in t["dataSource"], table
        assert t["query"].startswith(table) and column in t["query"], (table, t["query"])
        assert "operationName" not in t["query"] and "properties.message" not in t["query"]


def test_every_other_backend_stays_generic():
    for rule in (ACTIVITY, AUDIT, SIGNIN):
        t = by_backend(translate_rule(_rule(rule))[0])
        for b in ("microsoft_defender", "splunk", "elastic", "crowdstrike"):
            if b in t:
                assert t[b]["mapping"] == "generic" and t[b]["dataSource"] == "", (rule[:40], b)


def test_a_field_the_table_lacks_is_a_recorded_failure_not_a_generic_fallback():
    ts, failures = translate_rule(_rule(NO_COLUMN))
    assert "microsoft_sentinel" not in by_backend(ts)
    assert "someMadeUpField" in {f["backend"]: f["reason"] for f in failures}["microsoft_sentinel"]
