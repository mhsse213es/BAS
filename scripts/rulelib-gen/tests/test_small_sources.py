"""The small log sources: web proxy / web server, DNS, antivirus, Linux auditd, Cisco IOS, Okta, Zeek, Kubernetes audit,
GCP audit, OpenCanary and Bitbucket. Each maps only for the SIEMs whose schema is documented; the rest stay generic."""
import textwrap

from sigma.collection import SigmaCollection

from translate import log_source_family, looks_corrupt, translate_rule


def rule_for(logsource, detection="selection:\n            x: 'y'"):
    ls = "\n".join(f"        {k}: {v}" for k, v in logsource.items())
    return SigmaCollection.from_yaml(textwrap.dedent(f"""
    title: Small Source Rule
    id: 15151515-1515-1515-1515-151515151515
    status: test
    logsource:
{ls}
    detection:
        {detection}
        condition: selection
    level: medium
""")).rules[0]


def sel(field, value="'v'"):
    return f"selection:\n            {field}: {value}"


def by(ts):
    return {t["backend"]: t for t in ts}


def run(logsource, detection):
    ts, failures = translate_rule(rule_for(logsource, detection))
    return by(ts), {f["backend"]: f["reason"] for f in failures}


def test_families():
    assert log_source_family(rule_for({"category": "proxy"})) == "web_proxy"
    assert log_source_family(rule_for({"category": "webserver"})) == "web_server"
    assert log_source_family(rule_for({"service": "apache"})) == "web_server"
    assert log_source_family(rule_for({"category": "dns"})) == "dns_log"
    assert log_source_family(rule_for({"product": "linux", "service": "auditd"})) == "linux_auditd"
    assert log_source_family(rule_for({"product": "linux", "service": "sshd"})) == ""
    assert log_source_family(rule_for({"product": "okta", "service": "okta"})) == "okta"


def test_web_maps_w3c_fields_to_cim_for_splunk_and_ecs_for_elastic():
    t, _ = run({"category": "proxy"}, "selection:\n            c-useragent|contains: 'curl'\n            cs-method: GET")
    assert t["splunk"]["mapping"] == "pipeline" and "http_user_agent" in t["splunk"]["query"] and "http_method" in t["splunk"]["query"]
    assert 'tag="web"' in t["splunk"]["query"] or "tag=web" in t["splunk"]["query"]
    assert t["elastic"]["mapping"] == "pipeline" and "user_agent.original" in t["elastic"]["query"] and "http.request.method" in t["elastic"]["query"]
    for b in ("microsoft_sentinel", "microsoft_defender", "crowdstrike"):
        if b in t:
            assert t[b]["mapping"] == "generic", b


def test_a_web_field_with_no_equivalent_is_a_recorded_failure_not_a_raw_name():
    t, f = run({"category": "proxy"}, sel("cs-cookie|contains", "'x'"))
    assert "elastic" not in t and "cs-cookie" in f["elastic"]
    assert "splunk" not in t and "cs-cookie" in f["splunk"]


def test_dns_log():
    t, _ = run({"category": "dns"}, sel("query|endswith", "'.evil.com'"))
    assert t["splunk"]["mapping"] == "pipeline" and "query" in t["splunk"]["query"] and "dns" in t["splunk"]["query"]
    assert t["elastic"]["mapping"] == "pipeline" and "dns.question.name" in t["elastic"]["query"]


def test_linux_auditd_is_splunk_only_with_the_unix_addon_sourcetype():
    t, _ = run({"product": "linux", "service": "auditd"}, sel("type", "EXECVE"))
    assert t["splunk"]["mapping"] == "pipeline" and 'sourcetype="linux_audit"' in t["splunk"]["query"]
    for b in ("elastic", "microsoft_sentinel", "crowdstrike"):
        if b in t:
            assert t[b]["mapping"] == "generic", b


def test_cisco_ios_scopes_keyword_rules_to_the_source():
    t, _ = run({"product": "cisco", "service": "aaa"}, "selection:\n            - 'AAA'")
    assert t["splunk"]["mapping"] == "pipeline" and 'sourcetype="cisco:ios"' in t["splunk"]["query"]


def test_okta_keeps_the_system_log_keys_and_scopes_the_sourcetype():
    t, _ = run({"product": "okta", "service": "okta"}, sel("eventType", "user.session.start"))
    assert t["splunk"]["mapping"] == "pipeline" and 'sourcetype="OktaIM2:log"' in t["splunk"]["query"] and "eventType" in t["splunk"]["query"]


def test_zeek_and_kubernetes_use_elastic_stock_pipelines_and_never_a_wildcard_field_name():
    z, _ = run({"product": "zeek", "service": "dns"}, sel("query|endswith", "'.evil.com'"))
    assert z["elastic"]["mapping"] == "pipeline" and "zeek.dns" in z["elastic"]["query"]
    assert z["splunk"]["mapping"] == "generic"
    smb, f = run({"product": "zeek", "service": "smb_files"}, sel("path|endswith", "'\\\\IPC$'"))
    if "elastic" in smb:
        assert "\\*." not in smb["elastic"]["query"]
    k, _ = run({"product": "kubernetes", "service": "audit"}, sel("verb", "delete"))
    assert k["elastic"]["mapping"] == "pipeline" and "kubernetes.audit" in k["elastic"]["query"]


def test_native_json_sources_are_identity_mapped_for_splunk_only():
    for ls, field in (({"product": "opencanary", "category": "application"}, "logtype"),
                      ({"product": "bitbucket", "service": "audit"}, "auditType.action")):
        t, _ = run(ls, sel(field, "'1001'"))
        assert t["splunk"]["mapping"] == "pipeline" and t["splunk"]["dataSource"] and field in t["splunk"]["query"], ls
        assert t["elastic"]["mapping"] == "generic", ls


def test_gcp_audit_keeps_filebeat_names_and_fails_on_other_shapes():
    t, _ = run({"product": "gcp", "service": "gcp.audit"}, sel("gcp.audit.method_name", "'x'"))
    assert t["elastic"]["mapping"] == "pipeline" and "event.dataset" in t["elastic"]["query"]
    t2, f2 = run({"product": "gcp", "service": "gcp.audit"}, sel("data.protoPayload.logName", "'x'"))
    assert "elastic" not in t2 and "data.protoPayload.logName" in f2["elastic"]


def test_azure_risk_detection_maps_for_sentinel_but_pim_alerts_do_not():
    t, _ = run({"product": "azure", "service": "riskdetection"}, sel("riskEventType", "unfamiliarFeatures"))
    s = t["microsoft_sentinel"]
    assert s["mapping"] == "pipeline" and s["query"].startswith("AADUserRiskEvents") and "RiskEventType" in s["query"]
    assert "riskEventType" not in s["query"]
    pim, f = run({"product": "azure", "service": "pim"}, sel("riskEventType", "invalidLicenseAlertIncident"))
    assert pim["microsoft_sentinel"]["mapping"] == "generic"


def test_free_text_application_logs_stay_generic():
    t, _ = run({"product": "django", "category": "application"}, "selection:\n            - 'Traceback'")
    for b in t:
        assert t[b]["mapping"] == "generic", b
    assert not any(looks_corrupt(x["query"]) for x in t.values())


def test_failure_reasons_drop_the_host_path_and_the_long_field_list_but_keep_the_field():
    from translate import clean_reason
    raw = ("SigmaTransformationError: Invalid SigmaDetectionItem field name encountered: TargetName. Please use valid fields for "
           "the SecurityEvent table, or the following fields that have fieldmappings in this pipeline:\nAccessList, AccessMask, "
           "Account in C:\\Users\\Administrator\\Downloads\\x\\rule.yml")
    out = clean_reason(raw)
    assert "TargetName" in out and "SecurityEvent" in out
    assert "AccessList" not in out and "Users" not in out and "\n" not in out
    assert clean_reason("plain message") == "plain message"
