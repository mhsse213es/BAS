#!/usr/bin/env python3
"""Export EM-01 steps to JSON so the PowerShell runner needs no Python on the test host.

Run on the build machine (needs PyYAML):
  python scripts/em01/export_steps_json.py scenarios/endpoint-mastery/em-01-control-validation.yaml scripts/em01/em-01-steps.json
"""
import datetime as dt
import hashlib
import json
import sys

import yaml

src, dst = sys.argv[1], sys.argv[2]
raw = open(src, "rb").read()
doc = yaml.safe_load(raw.decode("utf-8-sig"))
out = {
    "scenario": doc["id"],
    "source_file": src.replace("\\", "/").split("/")[-1],
    "source_sha256": hashlib.sha256(raw).hexdigest(),
    "exported_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    "steps": [
        {"index": i, "name": s["name"], "technique_id": s.get("technique_id", ""),
         "timeout_sec": int(s.get("timeout_sec", 30)), "command": s["command"]}
        for i, s in enumerate(doc["steps"])
    ],
}
with open(dst, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
print(f"exported {len(out['steps'])} steps, source sha256 {out['source_sha256']}")
