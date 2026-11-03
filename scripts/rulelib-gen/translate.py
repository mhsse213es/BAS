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
AZURE_ACTIVITYLOGS = "azure_activitylogs"
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
        raise SigmaTransformationError(f"Field {detection_item.field} has no ECS equivalent in the {self.label} pipeline")


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
    if ls.product == "aws" and ls.service == "cloudtrail" and not ls.category:
        return AWS_CLOUDTRAIL
    if ls.product == "azure" and not ls.category:
        family = {"activitylogs": AZURE_ACTIVITYLOGS, "auditlogs": AZURE_AUDITLOGS, "signinlogs": AZURE_SIGNINLOGS}.get(ls.service)
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
            if not queries:
                failures.append({"backend": backend_key, "reason": "backend returned no query"})
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
