"""Stage 2 of the generator pipeline: convert one Sigma rule into every supported vendor's query language via pySigma
backends. A conversion failure for one backend is caught and recorded; it never stops the others (see the design
spec's quality-gate policy: an isolated rule/backend gap is a warning, not a build failure).

Field mapping. A bare pySigma backend emits Sigma's own field names with no table, index or event type, so the query
matches nothing in a real SIEM. For the log-source families listed in a backend's `mappings` a processing pipeline is
applied, so the query names the SIEM's real table/index/event type and fields. Every mapped translation records the
pipeline used and the data source the customer must collect for the query to match anything. Rules in a family with
no mapping are translated generically and labelled that way; the original Sigma rule is never altered.

Adding a backend (QRadar next) is one more `BackendSpec` in BACKENDS: a key, a pySigma backend class, a language and
its mappings. Nothing else in the generator or the rule library changes."""
import copy
import re
import importlib.metadata
from dataclasses import dataclass, field
from typing import Callable

from sigma.backends.crowdstrike import LogScaleBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.kusto import KustoBackend as SentinelKustoBackend
from sigma.backends.microsoft365defender import KustoBackend as DefenderKustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.crowdstrike import crowdstrike_fdr_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.elasticsearch.zeek import ecs_zeek_beats
from sigma.pipelines.elasticsearch.kubernetes import ecs_kubernetes
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.processing.conditions import ExcludeFieldCondition, IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
)
from sigma.processing.transformations.base import DetectionItemTransformation, SigmaTransformationError
from sigma.types import SigmaBool, SigmaString

WINDOWS_PROCESS_CREATION = "windows_process_creation"
WINDOWS_NETWORK_CONNECTION = "windows_network_connection"
WINDOWS_PS_SCRIPT = "windows_ps_script"
WINDOWS_REGISTRY_SET = "windows_registry_set"
WINDOWS_FILE_EVENT = "windows_file_event"
WINDOWS_IMAGE_LOAD = "windows_image_load"
WINDOWS_SECURITY = "windows_security"
WINDOWS_SYSTEM = "windows_system"
WINDOWS_PS_MODULE = "windows_ps_module"
LINUX_PROCESS_CREATION = "linux_process_creation"
MACOS_PROCESS_CREATION = "macos_process_creation"
AWS_CLOUDTRAIL = "aws_cloudtrail"
WINDOWS_EVENTLOG = "windows_eventlog"
# Windows categories (Sysmon and others) mapped by the long-tail tables at the end of this module.
WINDOWS_TAIL_CATEGORIES = (
    "process_access", "dns_query", "pipe_created", "driver_load", "create_remote_thread",
    "registry_event", "registry_delete", "file_delete", "ps_classic_start", "ps_classic_provider_start",
    "wmi_event", "sysmon_status", "sysmon_error", "file_executable_detected", "process_tampering",
)
AZURE_ACTIVITYLOGS = "azure_activitylogs"
AZURE_RISKDETECTION = "azure_riskdetection"
# (product, service, category) of the small log sources -> family. Empty string = the rule does not set it.
SMALL_SOURCE_FAMILIES = {
    ("", "", "proxy"): "web_proxy", ("", "", "webserver"): "web_server", ("", "apache", ""): "web_server",
    ("", "", "dns"): "dns_log", ("", "", "antivirus"): "antivirus_log",
    ("linux", "auditd", ""): "linux_auditd",
    ("cisco", "aaa", ""): "cisco_ios", ("cisco", "ldp", ""): "cisco_ios", ("cisco", "bgp", ""): "cisco_ios",
    ("okta", "okta", ""): "okta",
    ("kubernetes", "audit", ""): "k8s_audit", ("kubernetes", "audit", "application"): "k8s_audit",
    ("gcp", "gcp.audit", ""): "gcp_audit",
    ("opencanary", "", "application"): "opencanary", ("bitbucket", "audit", ""): "bitbucket_audit",
    **{("zeek", svc, ""): "zeek_log" for svc in ("dns", "http", "smb_files", "rdp", "kerberos", "dce_rpc")},
}
AZURE_AUDITLOGS = "azure_auditlogs"
AZURE_SIGNINLOGS = "azure_signinlogs"


def _splunk_sysmon_pipeline(identifier: str, category: str, event_code: int) -> ProcessingPipeline:
    return ProcessingPipeline(
        name=f"Audspect Splunk Sysmon {category}",
        allowed_backends={"splunk"},
        priority=20,
        items=[ProcessingItem(
            identifier=identifier,
            transformation=AddConditionTransformation({
                "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "EventCode": event_code,
            }),
            rule_conditions=[LogsourceCondition(category=category, product="windows")],
        )],
    )


# Sigma's Linux process_creation fields and their ECS equivalents. A field not listed here has no ECS equivalent that
# this generator can state, so a rule using it is a recorded failure rather than a query with a raw Sigma field name.
ECS_LINUX_PROCESS_FIELDS = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "User": "user.name",
    "CurrentDirectory": "process.working_directory",
}


class UnmappedFieldFailure(DetectionItemTransformation):
    """Fails the rule for this backend, naming the field that has no equivalent."""

    def __init__(self, label: str):
        super().__init__()
        self.label = label

    def apply_detection_item(self, detection_item):
        if detection_item.field is None:  # a keyword (free-text) item has no field to map
            return
        raise SigmaTransformationError(f"Field {detection_item.field} has no equivalent in the {self.label} pipeline")


def _ecs_unix_process_pipeline(product: str, label: str) -> ProcessingPipeline:
    """pySigma's ecs_windows (and ecs_macos_esf) pipelines do not rename Image/CommandLine for Linux or macOS rules, so
    their queries keep Sigma's own names. This maps the process_creation fields to ECS and restricts the query to
    process start events. Unverified against live Elastic data."""
    def linux_process():  # a condition object can belong to only one processing item
        return [LogsourceCondition(category="process_creation", product=product)]

    return ProcessingPipeline(
        name=f"Audspect ECS {label} process creation",
        priority=20,
        items=[
            ProcessingItem(
                identifier=f"audspect_ecs_{product}_process_fields",
                transformation=FieldMappingTransformation(ECS_LINUX_PROCESS_FIELDS),
                rule_conditions=linux_process(),
            ),
            ProcessingItem(
                identifier=f"audspect_ecs_{product}_process_unmapped_field",
                transformation=UnmappedFieldFailure(f"{label} process"),
                field_name_conditions=[ExcludeFieldCondition(fields=list(ECS_LINUX_PROCESS_FIELDS.values()))],
                rule_conditions=linux_process(),
            ),
            ProcessingItem(
                identifier=f"audspect_ecs_{product}_process_start",
                transformation=AddConditionTransformation({"event.category": "process", "event.type": "start"}),
                rule_conditions=linux_process(),
            ),
        ],
    )


# Sigma's CloudTrail field names are CloudTrail's own JSON keys. Where a SIEM stores the event with different names, the
# mapping below renames the simple top-level fields; a nested field (requestParameters.x, userIdentity.sessionContext...)
# has no safe equivalent and makes the rule a recorded failure instead of a query with a raw name.
SENTINEL_AWS_COLUMNS = {
    "eventName": "EventName", "eventSource": "EventSource", "awsRegion": "AWSRegion", "sourceIPAddress": "SourceIpAddress",
    "userAgent": "UserAgent", "errorCode": "ErrorCode", "errorMessage": "ErrorMessage",
    "userIdentity.type": "UserIdentityType", "userIdentity.arn": "UserIdentityArn",
    "requestParameters": "RequestParameters", "responseElements": "ResponseElements",
}
ECS_AWS_CLOUDTRAIL_FIELDS = {
    "eventName": "event.action", "eventSource": "event.provider", "awsRegion": "cloud.region", "sourceIPAddress": "source.ip",
    "userAgent": "user_agent.original", "errorCode": "aws.cloudtrail.error_code", "errorMessage": "aws.cloudtrail.error_message",
    "userIdentity.type": "aws.cloudtrail.user_identity.type", "userIdentity.arn": "aws.cloudtrail.user_identity.arn",
}


def _azure_pipeline(service: str, table: str, renames: dict) -> ProcessingPipeline:
    """The Azure Monitor pipeline on an explicit table, preceded by the few renames the stock pipeline lacks. It rejects
    any column the table does not have, so such a rule is a recorded failure."""
    if not renames:
        return azure_monitor_pipeline(table)
    rename = ProcessingPipeline(items=[ProcessingItem(
        identifier=f"audspect_sentinel_azure_{service}_columns",
        transformation=FieldMappingTransformation(renames),
        rule_conditions=[LogsourceCondition(product="azure", service=service)],
    )], priority=5)
    return rename + azure_monitor_pipeline(table)


def sentinel_azure_activity_pipeline() -> ProcessingPipeline:
    # Sigma's operationName holds the raw "MICROSOFT.X/Y/action" value, which is the OperationNameValue column.
    return _azure_pipeline("activitylogs", "AzureActivity", {"operationName": "OperationNameValue"})


def sentinel_azure_audit_pipeline() -> ProcessingPipeline:
    # Sigma's properties.message on Entra audit logs holds the operation name (for example "Add member to role").
    return _azure_pipeline("auditlogs", "AuditLogs", {"properties.message": "OperationName"})


def sentinel_azure_risk_pipeline() -> ProcessingPipeline:
    return _azure_pipeline("riskdetection", "AADUserRiskEvents", {"riskEventType": "RiskEventType"})


def sentinel_azure_signin_pipeline() -> ProcessingPipeline:
    return _azure_pipeline("signinlogs", "SigninLogs", {})


def _aws() -> list:
    return [LogsourceCondition(product="aws", service="cloudtrail")]  # a condition object belongs to one item only


def sentinel_aws_cloudtrail_pipeline() -> ProcessingPipeline:
    """Renames CloudTrail's JSON keys to the AWSCloudTrail table's columns, then lets the Azure Monitor pipeline build
    the query on that table (it rejects any column the table does not have)."""
    rename = ProcessingPipeline(items=[ProcessingItem(
        identifier="audspect_sentinel_aws_cloudtrail_columns",
        transformation=FieldMappingTransformation(SENTINEL_AWS_COLUMNS),
        rule_conditions=_aws(),
    )], priority=5)
    return rename + azure_monitor_pipeline("AWSCloudTrail")


def splunk_aws_cloudtrail_pipeline() -> ProcessingPipeline:
    """CloudTrail events indexed by the Splunk Add-on for AWS keep their JSON keys as field names, so only the source
    needs stating."""
    return ProcessingPipeline(
        name="Audspect Splunk AWS CloudTrail",
        allowed_backends={"splunk"},
        priority=20,
        items=[ProcessingItem(
            identifier="audspect_splunk_aws_cloudtrail",
            transformation=AddConditionTransformation({"sourcetype": "aws:cloudtrail"}),
            rule_conditions=_aws(),
        )],
    )


def ecs_aws_cloudtrail_pipeline() -> ProcessingPipeline:
    """Maps CloudTrail's top-level keys to the fields Filebeat's AWS module (or the Elastic AWS integration) writes, and
    restricts the query to that dataset. Unverified against live Elastic data."""
    return ProcessingPipeline(
        name="Audspect ECS AWS CloudTrail",
        priority=20,
        items=[
            ProcessingItem(
                identifier="audspect_ecs_aws_cloudtrail_fields",
                transformation=FieldMappingTransformation(ECS_AWS_CLOUDTRAIL_FIELDS),
                rule_conditions=_aws(),
            ),
            ProcessingItem(
                identifier="audspect_ecs_aws_cloudtrail_unmapped_field",
                transformation=UnmappedFieldFailure("AWS CloudTrail"),
                field_name_conditions=[ExcludeFieldCondition(fields=list(ECS_AWS_CLOUDTRAIL_FIELDS.values()))],
                rule_conditions=_aws(),
            ),
            ProcessingItem(
                identifier="audspect_ecs_aws_cloudtrail_dataset",
                transformation=AddConditionTransformation({"event.dataset": "aws.cloudtrail"}),
                rule_conditions=_aws(),
            ),
        ],
    )


def ecs_linux_process_creation_pipeline() -> ProcessingPipeline:
    return _ecs_unix_process_pipeline("linux", "Linux")


def ecs_macos_process_creation_pipeline() -> ProcessingPipeline:
    return _ecs_unix_process_pipeline("macos", "macOS")


def sentinel_security_event_pipeline() -> ProcessingPipeline:
    """The Azure Monitor pipeline picks a table from a short list of known event ids and fails the rest. Every
    Windows Security-log event is in SecurityEvent, so the table is set explicitly."""
    return azure_monitor_pipeline("SecurityEvent")


def splunk_sysmon_image_load_pipeline() -> ProcessingPipeline:
    """Sigma's image_load is a module (DLL) being loaded: Sysmon event 7. The bundled Splunk pipeline adds no source
    or event code."""
    return _splunk_sysmon_pipeline("audspect_splunk_sysmon_image_load", "image_load", 7)


def splunk_sysmon_file_event_pipeline() -> ProcessingPipeline:
    """Sigma's file_event is a file being created: Sysmon event 11. The bundled Splunk pipeline adds no source or
    event code."""
    return _splunk_sysmon_pipeline("audspect_splunk_sysmon_file_event", "file_event", 11)


def splunk_sysmon_registry_set_pipeline() -> ProcessingPipeline:
    """Sigma's registry_set is a registry value being set: Sysmon event 13. The bundled Splunk pipeline adds no source
    or event code."""
    return _splunk_sysmon_pipeline("audspect_splunk_sysmon_registry_set", "registry_set", 13)


def _splunk_powershell_pipeline(identifier: str, category: str, event_code: int) -> ProcessingPipeline:
    return ProcessingPipeline(
        name=f"Audspect Splunk PowerShell {category}",
        allowed_backends={"splunk"},
        priority=20,
        items=[ProcessingItem(
            identifier=identifier,
            transformation=AddConditionTransformation({
                "source": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
                "EventCode": event_code,
            }),
            rule_conditions=[LogsourceCondition(category=category, product="windows")],
        )],
    )


def splunk_powershell_script_block_pipeline() -> ProcessingPipeline:
    """PowerShell script block logging is Windows event 4104 in the PowerShell/Operational log. The bundled Splunk
    pipeline adds no source or event code, so a bare query would search every index for ScriptBlockText."""
    return _splunk_powershell_pipeline("audspect_splunk_powershell_script_block", "ps_script", 4104)


def splunk_powershell_module_pipeline() -> ProcessingPipeline:
    """PowerShell module logging is Windows event 4103 in the same log; its text is the event's Payload."""
    return _splunk_powershell_pipeline("audspect_splunk_powershell_module", "ps_module", 4103)


def splunk_sysmon_process_creation_pipeline() -> ProcessingPipeline:
    """pySigma's bundled Splunk pipeline adds no process-creation condition (that lives in the separate Sysmon
    pipeline package), so without this a Splunk query has no source or event code. This adds the standard Sysmon
    event 1 condition used by the Splunk Add-on for Sysmon; Sigma's process_creation field names are Sysmon's own."""
    return _splunk_sysmon_pipeline("audspect_splunk_sysmon_process_creation", "process_creation", 1)


def splunk_sysmon_network_connection_pipeline() -> ProcessingPipeline:
    """Same gap for network connections: the bundled pipeline adds no source or event code. Sysmon event 3 is the
    network connection event; Sigma's network_connection field names (Image, DestinationIp, ...) are Sysmon's own."""
    return _splunk_sysmon_pipeline("audspect_splunk_sysmon_network_connection", "network_connection", 3)


class InitiatedToDirection(DetectionItemTransformation):
    """pySigma's ecs_windows maps Sysmon's Initiated to network.direction but keeps the boolean (network.direction:true),
    which no ECS data contains: ECS and Winlogbeat's Sysmon module record egress / ingress. This rewrites the value so
    the Elastic query can match. Unverified against live Elastic data."""

    def apply_detection_item(self, detection_item):
        values = []
        for v in detection_item.value:
            text = str(v).strip().lower() if isinstance(v, (SigmaBool, SigmaString)) else ""
            if isinstance(v, SigmaBool):
                text = "true" if v.boolean else "false"
            values.append(SigmaString("egress" if text == "true" else "ingress" if text == "false" else str(v)))
        detection_item.value = values


def ecs_network_connection_pipeline() -> ProcessingPipeline:
    """The stock ecs_windows pipeline plus the direction correction (which must run after the field rename)."""
    fix = ProcessingPipeline(items=[ProcessingItem(
        identifier="audspect_ecs_initiated_to_direction",
        transformation=InitiatedToDirection(),
        field_name_conditions=[IncludeFieldCondition(fields=["network.direction"])],
    )])
    return ecs_windows() + fix


@dataclass(frozen=True)
class Mapping:
    """One field-mapping pipeline for one log-source family."""
    pipeline: Callable[[], ProcessingPipeline]
    name: str          # recorded on every translation that uses it
    data_source: str   # what the customer must collect for the query to match anything
    dist_name: str     # PyPI distribution providing the pipeline (version recorded); "" for in-repo pipelines
    # When set, the translation is labelled mapped only if the query contains this text. A stock pipeline that does not
    # recognise a log source leaves the query unchanged; it then stays generic instead of claiming a source it did not add.
    must_contain: str = ""


@dataclass(frozen=True)
class BackendSpec:
    backend_cls: type
    language: str
    dist_name: str     # PyPI distribution of the backend (version recorded)
    mappings: dict = field(default_factory=dict)  # family -> Mapping


# Why these pipelines: each was measured over all 1,177 SigmaHQ Windows process_creation rules (see
# docs/detection-rules-coverage.md). Sentinel uses the Defender XDR tables (97% convert) because ASIM (51%) and
# Security 4688 (41%) cannot express most rules' fields (no original file name, hashes, etc.).
BACKENDS: dict[str, BackendSpec] = {
    "microsoft_sentinel": BackendSpec(SentinelKustoBackend, "KQL", "pysigma-backend-kusto", {
        WINDOWS_PROCESS_CREATION: Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            "Microsoft Defender for Endpoint (Defender XDR) device events connected to Sentinel: the DeviceProcessEvents table",
            "pysigma-backend-kusto"),
        AZURE_ACTIVITYLOGS: Mapping(
            sentinel_azure_activity_pipeline, "audspect_sentinel_azure_activitylogs + azure_monitor_pipeline (query table AzureActivity)",
            "Azure activity (control-plane) logs in the AzureActivity table of the Log Analytics workspace (Azure Activity connector). "
            "Sigma's operationName is matched as OperationNameValue",
            "pysigma-backend-kusto"),
        AZURE_AUDITLOGS: Mapping(
            sentinel_azure_audit_pipeline, "audspect_sentinel_azure_auditlogs + azure_monitor_pipeline (query table AuditLogs)",
            "Microsoft Entra audit logs in the AuditLogs table of the Log Analytics workspace (Microsoft Entra ID connector). "
            "Sigma's properties.message is matched as OperationName",
            "pysigma-backend-kusto"),
        AZURE_RISKDETECTION: Mapping(
            sentinel_azure_risk_pipeline, "audspect_sentinel_azure_riskdetection + azure_monitor_pipeline (query table AADUserRiskEvents)",
            "Microsoft Entra ID Protection risk detections in the AADUserRiskEvents table of the Log Analytics workspace (Microsoft Entra ID "
            "connector, risk events enabled). Sigma's riskEventType is matched as RiskEventType",
            "pysigma-backend-kusto"),
        AZURE_SIGNINLOGS: Mapping(
            sentinel_azure_signin_pipeline, "azure_monitor_pipeline (query table SigninLogs)",
            "Microsoft Entra sign-in logs in the SigninLogs table of the Log Analytics workspace (Microsoft Entra ID connector)",
            "pysigma-backend-kusto"),
        AWS_CLOUDTRAIL: Mapping(
            sentinel_aws_cloudtrail_pipeline, "audspect_sentinel_aws_cloudtrail + azure_monitor_pipeline (query table AWSCloudTrail)",
            "AWS CloudTrail events in the AWSCloudTrail table of the Log Analytics workspace (Amazon Web Services connector). "
            "Nested fields such as requestParameters.x are not columns and are not mapped",
            "pysigma-backend-kusto"),
        MACOS_PROCESS_CREATION: Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            "Microsoft Defender for Endpoint on macOS (Defender XDR) device events connected to Sentinel: the DeviceProcessEvents table",
            "pysigma-backend-kusto"),
        LINUX_PROCESS_CREATION: Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            "Microsoft Defender for Endpoint on Linux (Defender XDR) device events connected to Sentinel: the DeviceProcessEvents table",
            "pysigma-backend-kusto"),
        WINDOWS_SECURITY: Mapping(
            sentinel_security_event_pipeline, "azure_monitor_pipeline (query table SecurityEvent)",
            "Windows Security events in the SecurityEvent table of the Log Analytics workspace (Windows Security Events via AMA "
            "connector). The audit policy for the event must be enabled on the endpoints",
            "pysigma-backend-kusto"),
        WINDOWS_IMAGE_LOAD: Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            "Microsoft Defender for Endpoint (Defender XDR) device events connected to Sentinel: the DeviceImageLoadEvents table",
            "pysigma-backend-kusto"),
        WINDOWS_FILE_EVENT: Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            "Microsoft Defender for Endpoint (Defender XDR) device events connected to Sentinel: the DeviceFileEvents table",
            "pysigma-backend-kusto"),
        WINDOWS_REGISTRY_SET: Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            "Microsoft Defender for Endpoint (Defender XDR) device events connected to Sentinel: the DeviceRegistryEvents table",
            "pysigma-backend-kusto"),
        WINDOWS_NETWORK_CONNECTION: Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            "Microsoft Defender for Endpoint (Defender XDR) device events connected to Sentinel: the DeviceNetworkEvents table",
            "pysigma-backend-kusto"),
    }),
    "microsoft_defender": BackendSpec(DefenderKustoBackend, "KQL", "pysigma-backend-microsoft365defender", {
        WINDOWS_PROCESS_CREATION: Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            "Microsoft Defender for Endpoint advanced hunting: the DeviceProcessEvents table",
            "pysigma-backend-microsoft365defender"),
        MACOS_PROCESS_CREATION: Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            "Microsoft Defender for Endpoint on macOS advanced hunting: the DeviceProcessEvents table",
            "pysigma-backend-microsoft365defender"),
        LINUX_PROCESS_CREATION: Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            "Microsoft Defender for Endpoint on Linux advanced hunting: the DeviceProcessEvents table",
            "pysigma-backend-microsoft365defender"),
        WINDOWS_IMAGE_LOAD: Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            "Microsoft Defender for Endpoint advanced hunting: the DeviceImageLoadEvents table",
            "pysigma-backend-microsoft365defender"),
        WINDOWS_FILE_EVENT: Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            "Microsoft Defender for Endpoint advanced hunting: the DeviceFileEvents table",
            "pysigma-backend-microsoft365defender"),
        WINDOWS_REGISTRY_SET: Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            "Microsoft Defender for Endpoint advanced hunting: the DeviceRegistryEvents table",
            "pysigma-backend-microsoft365defender"),
        WINDOWS_NETWORK_CONNECTION: Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            "Microsoft Defender for Endpoint advanced hunting: the DeviceNetworkEvents table",
            "pysigma-backend-microsoft365defender"),
    }),
    "splunk": BackendSpec(SplunkBackend, "SPL", "pysigma-backend-splunk", {
        WINDOWS_PROCESS_CREATION: Mapping(
            splunk_sysmon_process_creation_pipeline, "audspect_splunk_sysmon_process_creation",
            "Sysmon event 1 (process creation) indexed by Splunk through the Splunk Add-on for Sysmon "
            "(source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)",
            ""),
        WINDOWS_PS_MODULE: Mapping(
            splunk_powershell_module_pipeline, "audspect_splunk_powershell_module",
            "PowerShell module logging (Windows event 4103, Microsoft-Windows-PowerShell/Operational) indexed by Splunk "
            "(source XmlWinEventLog:Microsoft-Windows-PowerShell/Operational, matched on the Payload field). "
            "Module logging must be enabled on the endpoints",
            ""),
        AWS_CLOUDTRAIL: Mapping(
            splunk_aws_cloudtrail_pipeline, "audspect_splunk_aws_cloudtrail",
            "AWS CloudTrail events indexed by the Splunk Add-on for AWS (sourcetype aws:cloudtrail); CloudTrail's own JSON keys "
            "are the field names",
            ""),
        WINDOWS_SYSTEM: Mapping(
            splunk_windows_pipeline, "splunk_windows_pipeline",
            "Windows System event log indexed by Splunk (source WinEventLog:System, event id as EventCode) through the "
            "Splunk Add-on for Microsoft Windows",
            "pysigma-backend-splunk"),
        WINDOWS_SECURITY: Mapping(
            splunk_windows_pipeline, "splunk_windows_pipeline",
            "Windows Security event log indexed by Splunk (source WinEventLog:Security, event id as EventCode) through the "
            "Splunk Add-on for Microsoft Windows. The audit policy for the event must be enabled on the endpoints",
            "pysigma-backend-splunk"),
        WINDOWS_IMAGE_LOAD: Mapping(
            splunk_sysmon_image_load_pipeline, "audspect_splunk_sysmon_image_load",
            "Sysmon event 7 (image loaded) indexed by Splunk through the Splunk Add-on for Sysmon "
            "(source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational). Image load logging is off by default in Sysmon and must be enabled",
            ""),
        WINDOWS_FILE_EVENT: Mapping(
            splunk_sysmon_file_event_pipeline, "audspect_splunk_sysmon_file_event",
            "Sysmon event 11 (file created) indexed by Splunk through the Splunk Add-on for Sysmon "
            "(source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)",
            ""),
        WINDOWS_REGISTRY_SET: Mapping(
            splunk_sysmon_registry_set_pipeline, "audspect_splunk_sysmon_registry_set",
            "Sysmon event 13 (registry value set) indexed by Splunk through the Splunk Add-on for Sysmon "
            "(source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)",
            ""),
        WINDOWS_PS_SCRIPT: Mapping(
            splunk_powershell_script_block_pipeline, "audspect_splunk_powershell_script_block",
            "PowerShell script block logging (Windows event 4104, Microsoft-Windows-PowerShell/Operational) indexed by Splunk "
            "(source XmlWinEventLog:Microsoft-Windows-PowerShell/Operational). Script block logging must be enabled on the endpoints",
            ""),
        WINDOWS_NETWORK_CONNECTION: Mapping(
            splunk_sysmon_network_connection_pipeline, "audspect_splunk_sysmon_network_connection",
            "Sysmon event 3 (network connection) indexed by Splunk through the Splunk Add-on for Sysmon "
            "(source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)",
            ""),
    }),
    "elastic": BackendSpec(LuceneBackend, "Lucene", "pysigma-backend-elasticsearch", {
        WINDOWS_PROCESS_CREATION: Mapping(
            ecs_windows, "ecs_windows",
            "Windows process events in ECS field names (Elastic Defend, or Winlogbeat / Sysmon with the ECS ingest pipeline)",
            "pysigma-backend-elasticsearch"),
        WINDOWS_SYSTEM: Mapping(
            ecs_windows, "ecs_windows",
            "Windows System event log in ECS field names (Winlogbeat or the Elastic Agent Windows integration, winlog.channel System)",
            "pysigma-backend-elasticsearch"),
        AWS_CLOUDTRAIL: Mapping(
            ecs_aws_cloudtrail_pipeline, "audspect_ecs_aws_cloudtrail",
            "AWS CloudTrail events in the fields Filebeat's AWS module or the Elastic AWS integration write "
            "(event.dataset aws.cloudtrail; nested fields such as requestParameters.* are not mapped). Unverified against live Elastic data",
            ""),
        MACOS_PROCESS_CREATION: Mapping(
            ecs_macos_process_creation_pipeline, "audspect_ecs_macos_process_creation",
            "macOS process start events in ECS field names (Elastic Defend for macOS), matched as "
            "event.category process and event.type start. Unverified against live Elastic data",
            ""),
        LINUX_PROCESS_CREATION: Mapping(
            ecs_linux_process_creation_pipeline, "audspect_ecs_linux_process_creation",
            "Linux process start events in ECS field names (Elastic Defend for Linux, or Auditbeat), matched as "
            "event.category process and event.type start. Unverified against live Elastic data",
            ""),
        WINDOWS_SECURITY: Mapping(
            ecs_windows, "ecs_windows",
            "Windows Security event log in ECS field names (Winlogbeat or Elastic Agent Windows integration, winlog.channel Security). "
            "The audit policy for the event must be enabled on the endpoints",
            "pysigma-backend-elasticsearch"),
        WINDOWS_IMAGE_LOAD: Mapping(
            ecs_windows, "ecs_windows",
            "Image/library load events in ECS field names (Winlogbeat's Sysmon module, event 7, or Elastic Defend library events). "
            "The query carries no event-type condition, so it relies on the field names being specific to these events. "
            "Image load logging is off by default in Sysmon and must be enabled",
            "pysigma-backend-elasticsearch"),
        WINDOWS_FILE_EVENT: Mapping(
            ecs_windows, "ecs_windows",
            "File creation events in ECS field names (Elastic Defend, or Winlogbeat's Sysmon module, event 11)",
            "pysigma-backend-elasticsearch"),
        WINDOWS_REGISTRY_SET: Mapping(
            ecs_windows, "ecs_windows",
            "Registry value-set events in ECS field names (Winlogbeat's Sysmon module, event 13). The registry value "
            "(Details) is matched as winlog.event_data.Details, so Elastic Defend alone may not carry it",
            "pysigma-backend-elasticsearch"),
        WINDOWS_PS_SCRIPT: Mapping(
            ecs_windows, "ecs_windows",
            "PowerShell script block events in ECS field names (Winlogbeat's PowerShell module or Elastic Defend, "
            "powershell.file.script_block_text). Script block logging must be enabled on the endpoints",
            "pysigma-backend-elasticsearch"),
        WINDOWS_NETWORK_CONNECTION: Mapping(
            ecs_network_connection_pipeline, "ecs_windows + audspect_ecs_initiated_to_direction",
            "Windows network connection events in ECS field names (Elastic Defend, or Winlogbeat's Sysmon module, event 3). "
            "The Sysmon Initiated field is matched as network.direction egress / ingress; this is unverified against live data",
            "pysigma-backend-elasticsearch"),
    }),
    "crowdstrike": BackendSpec(LogScaleBackend, "LogScale", "pysigma-backend-crowdstrike", {
        WINDOWS_PROCESS_CREATION: Mapping(
            crowdstrike_fdr_pipeline, "crowdstrike_fdr_pipeline",
            "CrowdStrike Falcon Data Replicator ProcessRollup2 events from the Windows sensor, in LogScale",
            "pysigma-backend-crowdstrike"),
        MACOS_PROCESS_CREATION: Mapping(
            crowdstrike_fdr_pipeline, "crowdstrike_fdr_pipeline",
            "CrowdStrike Falcon Data Replicator process events from the macOS sensor (event_platform Mac), in LogScale",
            "pysigma-backend-crowdstrike"),
        LINUX_PROCESS_CREATION: Mapping(
            crowdstrike_fdr_pipeline, "crowdstrike_fdr_pipeline",
            "CrowdStrike Falcon Data Replicator process events from the Linux sensor (event_platform Lin), in LogScale",
            "pysigma-backend-crowdstrike"),
        WINDOWS_IMAGE_LOAD: Mapping(
            crowdstrike_fdr_pipeline, "crowdstrike_fdr_pipeline",
            "CrowdStrike Falcon Data Replicator ClassifiedModuleLoad events from the Windows sensor, in LogScale",
            "pysigma-backend-crowdstrike"),
        WINDOWS_PS_SCRIPT: Mapping(
            crowdstrike_fdr_pipeline, "crowdstrike_fdr_pipeline",
            "CrowdStrike Falcon Data Replicator CommandHistory and ScriptControlScanTelemetry events from the Windows sensor, in LogScale",
            "pysigma-backend-crowdstrike"),
        WINDOWS_NETWORK_CONNECTION: Mapping(
            crowdstrike_fdr_pipeline, "crowdstrike_fdr_pipeline",
            "CrowdStrike Falcon Data Replicator NetworkConnectIP4 events from the Windows sensor, in LogScale "
            "(IPv4 only: IPv6 connections are not covered)",
            "pysigma-backend-crowdstrike"),
    }),
}


# ── Long tail of Windows log sources ──────────────────────────────────────────────────────────────────────────
# Chosen by measuring every unmapped Windows group against the stock pipelines and reading the output (not by whether
# the output changed): Elastic is left generic for process_access (pySigma emits a corrupt query for regex rules),
# create_remote_thread, pipe_created, driver_load and file_delete, whose ECS fields are not specific to the event.
# Sentinel and Defender are not mapped for file_access: file events are creation/modification, not reads.
_SYSMON_SPLUNK = {   # category -> (event codes, what the event is)
    "process_access": ((10,), "process access"),
    "dns_query": ((22,), "DNS query"),
    "pipe_created": ((17, 18), "named pipe created / connected"),
    "driver_load": ((6,), "driver loaded"),
    "create_remote_thread": ((8,), "remote thread created"),
    "registry_event": ((12, 13, 14), "registry object created or deleted, value set, key or value renamed"),
    "registry_delete": ((12,), "registry object deleted"),
    "file_delete": ((23, 26), "file delete archived / detected"),
    "wmi_event": ((19, 20, 21), "WMI event filter / consumer / binding"),
    "sysmon_status": ((4, 16), "Sysmon service state / configuration change"),
    "sysmon_error": ((255,), "Sysmon error"),
    "file_executable_detected": ((29,), "executable file written"),
    "process_tampering": ((25,), "process image tampering"),
}


def _splunk_condition_pipeline(identifier: str, category: str, conditions: dict) -> ProcessingPipeline:
    return ProcessingPipeline(
        name=f"Audspect Splunk {category}", allowed_backends={"splunk"}, priority=20,
        items=[ProcessingItem(
            identifier=identifier, transformation=AddConditionTransformation(conditions),
            rule_conditions=[LogsourceCondition(category=category, product="windows")],
        )],
    )


def _sysmon_splunk_factory(category: str):
    codes = _SYSMON_SPLUNK[category][0]
    value = codes[0] if len(codes) == 1 else list(codes)
    return lambda: _splunk_condition_pipeline(
        f"audspect_splunk_sysmon_{category}", category,
        {"source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "EventCode": value})


def splunk_ps_classic_start_pipeline() -> ProcessingPipeline:
    return _splunk_condition_pipeline("audspect_splunk_ps_classic_start", "ps_classic_start",
                                      {"source": "WinEventLog:Windows PowerShell", "EventCode": 400})


def ecs_ps_classic_start_pipeline() -> ProcessingPipeline:
    return _ecs_ps_classic("ps_classic_start", "400")


def _ecs_ps_classic(category: str, code: str) -> ProcessingPipeline:
    add = ProcessingPipeline(items=[ProcessingItem(
        identifier=f"audspect_ecs_{category}",
        transformation=AddConditionTransformation({"winlog.channel": "Windows PowerShell", "event.code": code}),
        rule_conditions=[LogsourceCondition(category=category, product="windows")],
    )], priority=100)
    return ecs_windows() + add


def _register_long_tail() -> None:
    splunk, elastic = BACKENDS["splunk"].mappings, BACKENDS["elastic"].mappings
    sentinel, defender, crowd = (BACKENDS[k].mappings for k in ("microsoft_sentinel", "microsoft_defender", "crowdstrike"))
    for category, (codes, what) in _SYSMON_SPLUNK.items():
        events = ", ".join(str(c) for c in codes)
        splunk[f"windows_{category}"] = Mapping(
            _sysmon_splunk_factory(category), f"audspect_splunk_sysmon_{category}",
            f"Sysmon event {events} ({what}) indexed by Splunk through the Splunk Add-on for Sysmon "
            "(source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational). Sysmon must be configured to log these events", "")
    splunk["windows_ps_classic_start"] = Mapping(
        splunk_ps_classic_start_pipeline, "audspect_splunk_ps_classic_start",
        "Windows PowerShell classic log, event 400 (engine state changed), indexed by Splunk (source WinEventLog:Windows PowerShell)", "")
    elastic["windows_ps_classic_start"] = Mapping(
        ecs_ps_classic_start_pipeline, "ecs_windows + audspect_ecs_ps_classic_start",
        "Windows PowerShell classic log, event 400, in ECS field names (Winlogbeat, winlog.channel Windows PowerShell)",
        "pysigma-backend-elasticsearch")
    splunk["windows_ps_classic_provider_start"] = Mapping(
        lambda: _splunk_condition_pipeline("audspect_splunk_ps_classic_provider_start", "ps_classic_provider_start",
                                           {"source": "WinEventLog:Windows PowerShell", "EventCode": 600}),
        "audspect_splunk_ps_classic_provider_start",
        "Windows PowerShell classic log, event 600 (provider lifecycle), indexed by Splunk (source WinEventLog:Windows PowerShell)", "")
    elastic["windows_ps_classic_provider_start"] = Mapping(
        lambda: _ecs_ps_classic("ps_classic_provider_start", "600"), "ecs_windows + audspect_ecs_ps_classic_provider_start",
        "Windows PowerShell classic log, event 600, in ECS field names (Winlogbeat, winlog.channel Windows PowerShell)",
        "pysigma-backend-elasticsearch")
    for category, events in (("dns_query", "22"), ("registry_event", "12, 13, 14"), ("registry_delete", "12")):
        elastic[f"windows_{category}"] = Mapping(
            ecs_windows, "ecs_windows",
            f"Windows Sysmon events {events} in ECS field names (Winlogbeat's Sysmon module). The query carries no event-type "
            "condition, so it relies on the field names being specific to these events",
            "pysigma-backend-elasticsearch")
    for category, table in (("registry_event", "DeviceRegistryEvents"), ("registry_delete", "DeviceRegistryEvents"),
                            ("file_delete", "DeviceFileEvents")):
        sentinel[f"windows_{category}"] = Mapping(
            microsoft_xdr_pipeline, "microsoft_xdr_pipeline",
            f"Microsoft Defender for Endpoint (Defender XDR) device events connected to Sentinel: the {table} table", "pysigma-backend-kusto")
        defender[f"windows_{category}"] = Mapping(
            microsoft_365_defender_pipeline, "microsoft_365_defender_pipeline",
            f"Microsoft Defender for Endpoint advanced hunting: the {table} table", "pysigma-backend-microsoft365defender")
    for category in ("dns_query", "driver_load"):
        crowd[f"windows_{category}"] = Mapping(
            crowdstrike_fdr_pipeline, "crowdstrike_fdr_pipeline",
            "CrowdStrike Falcon Data Replicator events from the Windows sensor, in LogScale (event type set by the pipeline)",
            "pysigma-backend-crowdstrike")
    # Event-log services: only labelled mapped when the stock pipeline actually added the source or channel.
    splunk[WINDOWS_EVENTLOG] = Mapping(
        splunk_windows_pipeline, "splunk_windows_pipeline",
        "The Windows event log channel for this service indexed by Splunk (source WinEventLog:<channel>, event id as EventCode) "
        "through the Splunk Add-on for Microsoft Windows. The channel must be collected and its logging enabled",
        "pysigma-backend-splunk", 'source="')
    elastic[WINDOWS_EVENTLOG] = Mapping(
        ecs_windows, "ecs_windows",
        "The Windows event log channel for this service in ECS field names (Winlogbeat or the Elastic Agent Windows integration, "
        "winlog.channel). The channel must be collected and its logging enabled",
        "pysigma-backend-elasticsearch", "winlog.channel")


_register_long_tail()


# ── Small log sources ────────────────────────────────────────────────────────────────────────────────────────
# Mapped only where the product's field names are documented (or are Sigma's own names); everything else stays generic.
# Splunk uses the CIM names where a CIM data model covers the source. Unverified against live data unless stated.
WEB_CIM = {
    "c-uri": "url", "cs-uri": "url", "cs-uri-query": "uri_query", "cs-method": "http_method", "c-useragent": "http_user_agent",
    "cs-user-agent": "http_user_agent", "cs-host": "url_domain", "cs-referer": "http_referrer", "sc-status": "status",
}
WEB_ECS = {
    "c-uri": "url.original", "cs-uri": "url.original", "cs-uri-query": "url.query", "c-uri-extension": "url.extension",
    "cs-method": "http.request.method", "c-useragent": "user_agent.original", "cs-user-agent": "user_agent.original",
    "cs-host": "url.domain", "cs-referer": "http.request.referrer", "sc-status": "http.response.status_code",
    "dst_ip": "destination.ip", "r-dns": "url.domain",
}
DNS_CIM = {"query": "query", "record_type": "record_type", "answer": "answer"}
DNS_ECS = {"query": "dns.question.name", "record_type": "dns.question.type", "answer": "dns.answers.data"}


def _source_pipeline(name: str, shapes: list, fields: dict | None = None, conditions: dict | None = None,
                     label: str = "", field_pattern: str = "") -> Callable[[], ProcessingPipeline]:
    """A pipeline for one log source (one or more log-source shapes): rename fields, fail the rule on a field with no
    equivalent, add source conditions. Fresh condition objects per item, as pySigma requires."""
    def build() -> ProcessingPipeline:
        def lc():
            return [LogsourceCondition(**{k: v for k, v in s.items() if v}) for s in shapes]
        items = []
        if fields:
            items.append(ProcessingItem(identifier=f"{name}_fields", transformation=FieldMappingTransformation(dict(fields)),
                                        rule_conditions=lc(), rule_condition_linking=any))
        if label and (fields or field_pattern):
            known = ExcludeFieldCondition(fields=[field_pattern], mode="re") if field_pattern else ExcludeFieldCondition(fields=list(fields.values()))
            items.append(ProcessingItem(identifier=f"{name}_unmapped", transformation=UnmappedFieldFailure(label),
                                        field_name_conditions=[known], rule_conditions=lc(), rule_condition_linking=any))
        if conditions:
            items.append(ProcessingItem(identifier=f"{name}_source", transformation=AddConditionTransformation(dict(conditions)),
                                        rule_conditions=lc(), rule_condition_linking=any))
        return ProcessingPipeline(name=name, priority=20, items=items)
    return build


def _zeek_pipeline() -> ProcessingPipeline:
    """ecs_zeek_beats turns the smb_files fields into an invalid wildcard field name; name them as Filebeat's zeek module does."""
    smb = ProcessingPipeline(items=[ProcessingItem(
        identifier="audspect_ecs_zeek_smb_files",
        transformation=FieldMappingTransformation({"path": "zeek.smb_files.path", "name": "zeek.smb_files.name"}),
        rule_conditions=[LogsourceCondition(product="zeek", service="smb_files")],
    )], priority=5)
    return smb + ecs_zeek_beats()


def _register_small_sources() -> None:
    splunk, elastic = BACKENDS["splunk"].mappings, BACKENDS["elastic"].mappings

    def add(target: dict, family: str, name: str, shapes: list, data_source: str, **kw) -> None:
        target[family] = Mapping(_source_pipeline(name, shapes, **kw), name, data_source, "")

    web_proxy, web_server = [{"category": "proxy"}], [{"category": "webserver"}, {"service": "apache"}]
    add(splunk, "web_proxy", "audspect_splunk_web_proxy", web_proxy,
        "Proxy events normalised to the Splunk CIM Web data model (tag web): url, http_method, http_user_agent, ... The proxy's "
        "add-on must provide the CIM mapping", fields=WEB_CIM, conditions={"tag": "web"}, label="Splunk CIM Web")
    add(splunk, "web_server", "audspect_splunk_web_server", web_server,
        "Web server access events normalised to the Splunk CIM Web data model (tag web). The server's add-on must provide the CIM "
        "mapping", fields=WEB_CIM, conditions={"tag": "web"}, label="Splunk CIM Web")
    add(elastic, "web_proxy", "audspect_ecs_web_proxy", web_proxy,
        "Proxy events in ECS url.*, http.*, user_agent.* fields (Filebeat's proxy/web modules or the Elastic integrations). No "
        "dataset restriction is added: scope the query to the proxy's index", fields=WEB_ECS, label="ECS web")
    add(elastic, "web_server", "audspect_ecs_web_server", web_server,
        "Web server access events in ECS url.*, http.*, user_agent.* fields (Filebeat's apache/nginx/iis modules). No dataset "
        "restriction is added: scope the query to the server's index", fields=WEB_ECS, label="ECS web")

    dns = [{"category": "dns"}]
    add(splunk, "dns_log", "audspect_splunk_dns", dns,
        "DNS events normalised to the Splunk CIM Network Resolution (DNS) data model (tag dns): query, record_type, answer. "
        "CIM field names are unverified", fields=DNS_CIM, conditions={"tag": "dns"}, label="Splunk CIM DNS")
    add(elastic, "dns_log", "audspect_ecs_dns", dns,
        "DNS events in ECS dns.* fields (Packetbeat DNS, Filebeat network modules)", fields=DNS_ECS, label="ECS DNS")

    add(splunk, "antivirus_log", "audspect_splunk_antivirus", [{"category": "antivirus"}],
        "Antivirus detections normalised to the Splunk CIM Malware data model (tag malware): signature",
        fields={"Signature": "signature"}, conditions={"tag": "malware"}, label="Splunk CIM Malware")

    add(splunk, "linux_auditd", "audspect_splunk_linux_auditd", [{"product": "linux", "service": "auditd"}],
        "The Linux audit log (/var/log/audit/audit.log) indexed by the Splunk Add-on for Unix and Linux (sourcetype linux_audit); "
        "auditd's own keys (type, a0..a3, exe, name, key) are the field names. SYSCALL is matched as syscall (unverified)",
        fields={"SYSCALL": "syscall"}, conditions={"sourcetype": "linux_audit"})

    cisco = [{"product": "cisco", "service": s} for s in ("aaa", "ldp", "bgp")]
    add(splunk, "cisco_ios", "audspect_splunk_cisco_ios", cisco,
        "Cisco IOS / IOS-XE syslog indexed with the Cisco Networks Add-on (sourcetype cisco:ios); the rule is a free-text search of the message",
        conditions={"sourcetype": "cisco:ios"})
    add(elastic, "cisco_ios", "audspect_ecs_cisco_ios", cisco,
        "Cisco IOS syslog ingested by Filebeat's cisco module (event.dataset cisco.ios); the rule is a free-text search of the message. Unverified",
        conditions={"event.dataset": "cisco.ios"})

    add(splunk, "okta", "audspect_splunk_okta", [{"product": "okta", "service": "okta"}],
        "Okta System Log events indexed by the Splunk Add-on for Okta Identity Cloud (sourcetype OktaIM2:log); the System Log's "
        "own JSON keys (eventType, actor.alternateId, outcome.result) are the field names",
        conditions={"sourcetype": "OktaIM2:log"})

    add(splunk, "opencanary", "audspect_splunk_opencanary", [{"product": "opencanary", "category": "application"}],
        "OpenCanary's JSON log with its own keys (logtype ...), extracted as JSON fields by Splunk. No source restriction is added: "
        "scope the query to the index holding it")
    add(splunk, "bitbucket_audit", "audspect_splunk_bitbucket_audit", [{"product": "bitbucket", "service": "audit"}],
        "Bitbucket Data Center audit events as JSON with their own keys (auditType.category, auditType.action), extracted as JSON "
        "fields by Splunk. No source restriction is added: scope the query to the index holding it")

    add(elastic, "gcp_audit", "audspect_ecs_gcp_audit", [{"product": "gcp", "service": "gcp.audit"}],
        "GCP audit logs ingested by Filebeat's gcp module / the Elastic GCP integration (event.dataset gcp.audit; fields gcp.audit.*). "
        "A rule using the raw protoPayload shape instead is not expressible",
        conditions={"event.dataset": "gcp.audit"}, label="GCP audit", field_pattern=r"^gcp\.audit\..+$")

    elastic["zeek_log"] = Mapping(_zeek_pipeline, "ecs_zeek_beats + audspect_ecs_zeek_smb_files",
                                  "Zeek logs in the field names Filebeat's zeek module writes (event.dataset zeek.<log>)",
                                  "pysigma-backend-elasticsearch", "zeek.")
    elastic["k8s_audit"] = Mapping(ecs_kubernetes, "ecs_kubernetes",
                                   "Kubernetes API audit events in the field names Filebeat's kubernetes audit fileset writes "
                                   "(kubernetes.audit.*)", "pysigma-backend-elasticsearch", "kubernetes.audit")


_register_small_sources()


def _version(dist_name: str) -> str:
    if not dist_name:
        return ""
    try:
        return importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _pysigma_version() -> str:
    return _version("pysigma") or "unknown"


def log_source_family(rule) -> str:
    """The family a rule's log source belongs to, or "" when it has no mapped family."""
    ls = rule.logsource
    small = SMALL_SOURCE_FAMILIES.get((ls.product or "", ls.service or "", ls.category or ""))
    if small:
        return small
    if ls.product == "windows" and not ls.service and ls.category in WINDOWS_TAIL_CATEGORIES:
        return f"windows_{ls.category}"
    if ls.product == "windows" and ls.service and ls.service not in ("security", "system") and not ls.category:
        return WINDOWS_EVENTLOG
    if ls.product == "aws" and ls.service == "cloudtrail" and not ls.category:
        return AWS_CLOUDTRAIL
    if ls.product == "azure" and not ls.category:
        family = {"activitylogs": AZURE_ACTIVITYLOGS, "auditlogs": AZURE_AUDITLOGS, "signinlogs": AZURE_SIGNINLOGS, "riskdetection": AZURE_RISKDETECTION}.get(ls.service)
        if family:
            return family
    if ls.product == "linux" and ls.category == "process_creation" and not ls.service:
        return LINUX_PROCESS_CREATION
    if ls.product == "macos" and ls.category == "process_creation" and not ls.service:
        return MACOS_PROCESS_CREATION
    if ls.product == "windows" and not ls.category:
        # Only these two logs have a mapping; Sentinel's Security pipeline is registered for WINDOWS_SECURITY alone, so
        # a System-log rule is never pointed at the SecurityEvent table.
        if ls.service == "security":
            return WINDOWS_SECURITY
        if ls.service == "system":
            return WINDOWS_SYSTEM
    if ls.product == "windows" and not ls.service:
        if ls.category == "process_creation":
            return WINDOWS_PROCESS_CREATION
        if ls.category == "network_connection":
            return WINDOWS_NETWORK_CONNECTION
        if ls.category == "ps_script":
            return WINDOWS_PS_SCRIPT
        if ls.category == "registry_set":
            return WINDOWS_REGISTRY_SET
        if ls.category == "file_event":
            return WINDOWS_FILE_EVENT
        if ls.category == "image_load":
            return WINDOWS_IMAGE_LOAD
        if ls.category == "ps_module":
            return WINDOWS_PS_MODULE
    return ""


_LEAKED_OBJECT = re.compile(r"Sigma(?:String|RegularExpression|Number|Bool|CIDR|Null|Expansion|Placeholder|Query)\(|\w\.\\\*\.")


def looks_corrupt(query: str) -> bool:
    """True when a pySigma object's repr leaked into the query text (a pySigma defect seen with regex rules under
    ecs_windows). Such a query can never match, so it is a recorded failure."""
    return bool(_LEAKED_OBJECT.search(query))


def translate_rule(rule) -> tuple[list[dict], list[dict]]:
    """Returns (translations, failures) for one SigmaRule across every backend in BACKENDS. Never raises: a
    per-backend exception becomes a failure entry. The caller's rule is never changed (pipelines edit rules in
    place, so each conversion works on its own copy)."""
    translations: list[dict] = []
    failures: list[dict] = []
    family = log_source_family(rule)

    for backend_key, spec in BACKENDS.items():
        mapping = spec.mappings.get(family) if family else None
        try:
            kwargs = {"processing_pipeline": mapping.pipeline()} if mapping else {}
            backend = spec.backend_cls(**kwargs)
            queries = backend.convert(SigmaCollection([copy.deepcopy(rule)]))
            if queries and mapping and mapping.must_contain and mapping.must_contain not in queries[0]:
                mapping = None  # the pipeline did not recognise this log source: keep the plain translation, labelled generic
                queries = spec.backend_cls().convert(SigmaCollection([copy.deepcopy(rule)]))
            if not queries:
                failures.append({"backend": backend_key, "reason": "backend returned no query"})
                continue
            if looks_corrupt(queries[0]):
                failures.append({"backend": backend_key, "reason": "the backend produced an invalid query (a pySigma object leaked into the text)"})
                continue
            generator = f"pySigma {_pysigma_version()} / {spec.dist_name} {_version(spec.dist_name)}"
            if mapping:
                generator += f" / pipeline {mapping.name}"
                if mapping.dist_name and mapping.dist_name != spec.dist_name:
                    generator += f" ({mapping.dist_name} {_version(mapping.dist_name)})"
            translations.append({
                "backend": backend_key,
                "language": spec.language,
                "query": queries[0],
                "generator": generator,
                "mapping": "pipeline" if mapping else "generic",
                "pipeline": mapping.name if mapping else "",
                "dataSource": mapping.data_source if mapping else "",
            })
        except Exception as e:  # noqa: BLE001 — deliberately broad: one backend's exception must never stop the
            # others (SigmaBackendError, SigmaTransformationError, NotImplementedError ... all funnel here).
            failures.append({"backend": backend_key, "reason": f"{type(e).__name__}: {e}"})

    return translations, failures
