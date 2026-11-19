"""Scans this platform's scenario YAML files to find which ATT&CK techniques
already have detection-profile content shipped — the scoping boundary for
which Sigma rules the generator bothers converting (see the design spec's
"Generator Pipeline" section: first slice is scoped to existing coverage,
not full SigmaHQ)."""
import glob
import os
import re

import yaml


def covered_techniques(scenarios_dir: str) -> set[str]:
    """Returns every technique_id belonging to a step that also references
    detection_profiles, across every *.yaml file directly under scenarios_dir."""
    out: set[str] = set()
    for path in glob.glob(os.path.join(scenarios_dir, "*.yaml")):
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if not doc or "steps" not in doc:
            continue
        for step in doc["steps"]:
            if step.get("detection_profiles") and step.get("technique_id"):
                out.add(step["technique_id"])
    return out


_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def tested_techniques(scenarios_dir: str) -> set[str]:
    """Every technique_id of every step in every scenario YAML under scenarios_dir (recursive). This is what
    Audspect actually runs, and so the scope of the full rule library."""
    out: set[str] = set()
    for path in glob.glob(os.path.join(scenarios_dir, "**", "*.yaml"), recursive=True):
        try:
            with open(path, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except Exception:  # noqa: BLE001 - one unreadable scenario must not hide the others
            continue
        if not isinstance(doc, dict):
            continue
        for step in doc.get("steps") or []:
            if not isinstance(step, dict):
                continue
            tid = str(step.get("technique_id") or "").strip().upper()
            if _TECHNIQUE_RE.match(tid):
                out.add(tid)
    return out


def applicable_technique_ids(tested: set[str]) -> set[str]:
    """The tested techniques plus the parent of each tested sub-technique: a rule tagged only with the parent
    (T1059) still applies to a step that runs T1059.001."""
    return set(tested) | {t.split(".")[0] for t in tested if "." in t}
