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


def load_rules(sigma_dir: str, technique_ids: set[str]) -> list:
    """Loads every *.yml file under sigma_dir and returns the SigmaRule
    objects whose tags include at least one of technique_ids."""
    paths = sorted(glob.glob(os.path.join(sigma_dir, "*.yml")))
    if not paths:
        return []
    collection = SigmaCollection.load_ruleset(paths)
    return [r for r in collection.rules if rule_technique_ids(r) & technique_ids]
