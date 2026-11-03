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
from sigma.pipelines.crowdstrike import crowdstrike_fdr_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.processing.conditions import IncludeFieldCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.types import SigmaBool, SigmaString

WINDOWS_PROCESS_CREATION = "windows_process_creation"
WINDOWS_NETWORK_CONNECTION = "windows_network_connection"


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
    if ls.product == "windows" and not ls.service:
        if ls.category == "process_creation":
            return WINDOWS_PROCESS_CREATION
        if ls.category == "network_connection":
            return WINDOWS_NETWORK_CONNECTION
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
