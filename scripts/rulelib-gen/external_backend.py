"""Backends that cannot share the main Python environment.

pySigma's QRadar backend requires pySigma < 0.10, while the other five backends need 1.4.0, and the two cannot be
installed together. So QRadar runs in a second, isolated environment (see qradar/README.md) through a tiny protocol:
the generator writes a JSON list of {"id": <sigma id>, "path": <rule file>} to the script's stdin, and the script
writes one JSON object to stdout: {"_meta": {"generator": ...}, "<sigma id>": {"query": ...} | {"reason": ...}}.

Nothing here runs during packaging or on a customer server: it is a dev-time generator step, like the rest of this
folder."""
import json
import subprocess


class ExternalBackendError(Exception):
    pass


def run_external(python_exe: str, script: str, items: list[dict], timeout: int = 3600) -> tuple[dict, str]:
    """Runs script under python_exe. Returns (results by sigma id, generator string). Raises ExternalBackendError on
    a crash or unreadable output: a broken second environment must stop the build, never silently drop a backend."""
    proc = subprocess.run([python_exe, script], input=json.dumps(items), capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise ExternalBackendError(f"{script} failed with exit {proc.returncode}: {proc.stderr.strip()[-500:]}")
    try:
        out = json.loads(proc.stdout)
    except ValueError as e:
        raise ExternalBackendError(f"{script} output is not valid JSON: {e}") from e
    generator = (out.pop("_meta", {}) or {}).get("generator", "")
    return out, generator


def merge_external(record: dict, backend: str, language: str, result: dict | None, generator: str) -> None:
    """Adds the external backend's answer to a rule record. Always generic: these backends have no field-mapping
    pipeline here, so a query is never presented as ready to paste."""
    if result and result.get("query"):
        record["translations"].append({
            "backend": backend, "language": language, "query": result["query"], "generator": generator,
            "mapping": "generic", "pipeline": "", "dataSource": "", "verification": "none",
        })
        return
    reason = (result or {}).get("reason") or "no result returned for this rule"
    record["failures"].append({"backend": backend, "reason": reason})
