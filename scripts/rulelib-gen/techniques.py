"""Scans this platform's scenario YAML files to find which ATT&CK techniques
already have detection-profile content shipped — the scoping boundary for
which Sigma rules the generator bothers converting (see the design spec's
"Generator Pipeline" section: first slice is scoped to existing coverage,
not full SigmaHQ)."""
import glob
import os

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
