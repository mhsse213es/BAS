"""Runs in the QRadar environment (pySigma 0.9.x + pysigma-backend-qradar), NOT the main generator environment.
Protocol: see external_backend.py. Reads [{"id", "path"}] on stdin, writes the results object on stdout.

Rules are converted with the backend's default settings and no pipeline: the package's bundled Windows pipelines were
measured and convert almost nothing (and two of them crash), so no QRadar query is claimed to be field-mapped."""
import copy
import importlib.metadata
import json
import sys

from sigma.backends.qradar import QradarBackend
from sigma.collection import SigmaCollection


def _v(dist):
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def main():
    items = json.load(sys.stdin)
    out = {"_meta": {"generator": f"pySigma {_v('pysigma')} / pysigma-backend-qradar {_v('pysigma-backend-qradar')} (isolated environment)"}}
    for it in items:
        try:
            rule = SigmaCollection.load_ruleset([it["path"]]).rules[0]
            queries = QradarBackend().convert(SigmaCollection([copy.deepcopy(rule)]))
            out[it["id"]] = {"query": queries[0]} if queries else {"reason": "backend returned no query"}
        except Exception as e:  # noqa: BLE001 - one rule's failure must never stop the others
            out[it["id"]] = {"reason": f"{type(e).__name__}: {e}"}
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
