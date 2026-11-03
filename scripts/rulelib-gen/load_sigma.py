"""Stage 1 of the generator pipeline: load Sigma rules from a directory and
keep only the ones tagging a technique the platform already covers.

Reads only local files — never fetches over the network, so it works fully
air-gapped. Obtaining/updating the Sigma rule source directory (a curated
subset checked into sigma_seed/, or in the future a full SigmaHQ/sigma
checkout passed via a different path) is the operator's responsibility, not
this script's."""
import glob
import os
import re

import yaml
from sigma.collection import SigmaCollection

TECHNIQUE_TAG_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)


def rule_technique_ids(rule) -> set[str]:
    """Extracts ATT&CK technique IDs (e.g. "T1059.001") from a SigmaRule's tags."""
    out: set[str] = set()
    for tag in rule.tags:
        m = TECHNIQUE_TAG_RE.match(str(tag))
        if not m:
            continue
        tid = "T" + m.group(1)
        if m.group(2):
            tid += "." + m.group(2)
        out.add(tid)
    return out


EXCLUDED_STATUS = {"deprecated", "unsupported"}


def _wanted(path: str, technique_ids: set[str]) -> bool:
    """Cheap pre-filter on the raw YAML so pySigma only parses rules that can match: not deprecated or
    unsupported, and tagged with one of technique_ids. A file that cannot be read is skipped, never fatal."""
    try:
        with open(path, encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
    except Exception:  # noqa: BLE001
        return False
    for doc in docs:
        if str(doc.get("status") or "").lower() in EXCLUDED_STATUS or "detection" not in doc:
            continue
        for tag in doc.get("tags") or []:
            m = TECHNIQUE_TAG_RE.match(str(tag))
            if m and ("T" + m.group(1) + ("." + m.group(2) if m.group(2) else "")) in technique_ids:
                return True
    return False


def load_rules(sigma_dir: str, technique_ids: set[str]) -> list:
    """Loads every *.yml file under sigma_dir (recursively: a SigmaHQ checkout is nested) and returns the
    SigmaRule objects whose tags include at least one of technique_ids. Deprecated and unsupported rules are
    left out, and a file pySigma cannot parse is skipped so one bad upstream file never blocks a build."""
    out = []
    for path in sorted(glob.glob(os.path.join(sigma_dir, "**", "*.yml"), recursive=True)):
        if not _wanted(path, technique_ids):
            continue
        try:
            rules = SigmaCollection.load_ruleset([path]).rules
        except Exception:  # noqa: BLE001
            continue
        out.extend(r for r in rules if rule_technique_ids(r) & technique_ids)
    return out
