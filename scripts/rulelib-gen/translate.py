"""Stage 2 of the generator pipeline: convert one Sigma rule into every
supported vendor's query language via pySigma backends. A conversion failure
for one backend is caught and recorded — it never stops the others (see the
design spec's quality-gate policy: an isolated rule/backend gap is a warning,
not a build failure)."""
import importlib.metadata

from sigma.backends.crowdstrike import LogScaleBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.kusto import KustoBackend as SentinelKustoBackend
from sigma.backends.microsoft365defender import KustoBackend as DefenderKustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

# backend key -> (backend class, language label, PyPI distribution name for the generator string)
BACKENDS: dict[str, tuple[type, str, str]] = {
    "microsoft_sentinel": (SentinelKustoBackend, "KQL", "pysigma-backend-kusto"),
    "microsoft_defender": (DefenderKustoBackend, "KQL", "pysigma-backend-microsoft365defender"),
    "splunk": (SplunkBackend, "SPL", "pysigma-backend-splunk"),
    "elastic": (LuceneBackend, "Lucene", "pysigma-backend-elasticsearch"),
    "crowdstrike": (LogScaleBackend, "LogScale", "pysigma-backend-crowdstrike"),
}


def _pysigma_version() -> str:
    try:
        return importlib.metadata.version("pysigma")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _backend_version(dist_name: str) -> str:
    try:
        return importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def translate_rule(rule) -> tuple[list[dict], list[dict]]:
    """Returns (translations, failures) for one SigmaRule across every
    backend in BACKENDS. Never raises — a per-backend exception becomes a
    failure entry instead."""
    translations: list[dict] = []
    failures: list[dict] = []
    single_rule_collection = SigmaCollection([rule])

    for backend_key, (backend_cls, language, dist_name) in BACKENDS.items():
        try:
            backend = backend_cls()
            queries = backend.convert(single_rule_collection)
            if not queries:
                failures.append({"backend": backend_key, "reason": "backend returned no query"})
                continue
            translations.append({
                "backend": backend_key,
                "language": language,
                "query": queries[0],
                "generator": f"pySigma {_pysigma_version()} / {dist_name} {_backend_version(dist_name)}",
            })
        except Exception as e:  # noqa: BLE001 — deliberately broad: one backend's
            # exception must never stop the others (SigmaBackendError,
            # NotImplementedError, etc. all funnel here as a recorded failure).
            failures.append({"backend": backend_key, "reason": f"{type(e).__name__}: {e}"})

    return translations, failures
