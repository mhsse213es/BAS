#!/usr/bin/env python3
"""Run the EM-01 (Endpoint Mastery 01) read-only posture checks on this host.

Runs every step of the scenario YAML with Windows PowerShell, mirrors the
engine's verdict rules (FAIL > ERROR > SKIP > PASS, verdict prefix matched
anywhere in the output, no verdict = NO_VERDICT), and writes:

  results.csv   one row per step: index, verdict, name, technique, output
  results.json  same data plus host context and the YAML sha256
  summary.txt   counts and the host context, for pasting into a report

Read-only: the commands are the scenario's own Get-*/registry/query steps.
Overrides are read from the environment by the commands themselves
(BAS_EM01_OUTBOUND_BASELINE, BAS_EM01_FW_LOG_MB, BAS_EM01_SECLOG_MB,
BAS_EM01_AV_DEF_HOURS). Set them in this shell before running if needed.

Requires: Python 3.8+, PyYAML (pip install pyyaml), Windows PowerShell 5.1.

Usage:
  python em01_readonly_run.py --scenario scenarios\\endpoint-mastery\\em-01-control-validation.yaml --out C:\\em01-results
"""

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

VERDICTS = ("PASS", "FAIL", "SKIP", "ERROR")


def host_context():
    """Collect the host facts that decide Client vs Server expectations."""
    script = (
        "$os = Get-CimInstance Win32_OperatingSystem; "
        "$cs = Get-CimInstance Win32_ComputerSystem; "
        "[pscustomobject]@{ Caption=$os.Caption; Version=$os.Version; ProductType=$os.ProductType; "
        "Model=$cs.Model; Manufacturer=$cs.Manufacturer; "
        "IsAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
        ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } | ConvertTo-Json -Compress"
    )
    out = run_ps_text(script, timeout=60)
    try:
        ctx = json.loads(out)
    except ValueError:
        ctx = {"error": out.strip()[:300]}
    ctx["ProductTypeMeaning"] = {1: "Client", 2: "Domain controller", 3: "Server"}.get(
        ctx.get("ProductType"), "unknown")
    ctx["hostname"] = os.environ.get("COMPUTERNAME", "")
    ctx["runAt"] = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    return ctx


def run_ps_text(script, timeout):
    """Run inline PowerShell and return stdout (used for host context only)."""
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as f:
        f.write(script)
        path = f.name
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""
    finally:
        os.unlink(path)


def verdict_of(output):
    """Mirror orchestrator/internal/scenario/interpreter.go dominantVerdict.

    Priority FAIL > ERROR > SKIP > PASS, independent of line order. Only the
    exact uppercase 'ERROR:' counts; FAIL/SKIP/PASS are matched case-insensitively.
    """
    fail = err = skip = pss = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if fail is None and low.startswith("fail:"):
            fail = line
        elif err is None and line.startswith("ERROR:"):
            err = line
        elif skip is None and low.startswith("skip:"):
            skip = line
        elif pss is None and low.startswith("pass:"):
            pss = line
    if fail:
        return "FAIL", fail
    if err:
        return "ERROR", err
    if skip:
        return "SKIP", skip
    if pss:
        return "PASS", pss
    return "NO_VERDICT", ""


def run_step(command, timeout):
    # BOM so Windows PowerShell 5.1 reads non-ASCII text in the scenario correctly.
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as f:
        f.write(command)
        path = f.name
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    finally:
        os.unlink(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True, help="path to em-01-control-validation.yaml")
    ap.add_argument("--out", required=True, help="output directory (created if missing)")
    args = ap.parse_args()

    raw = open(args.scenario, "rb").read()
    doc = yaml.safe_load(raw.decode("utf-8-sig"))
    steps = doc["steps"]
    os.makedirs(args.out, exist_ok=True)
    host = host_context()

    rows = []
    for i, s in enumerate(steps):
        timeout = int(s.get("timeout_sec", 30)) + 30
        out, rc = run_step(s["command"], timeout)
        verdict, line = verdict_of(out)
        rows.append({
            "index": i,
            "verdict": verdict,
            "name": s["name"],
            "technique": s.get("technique_id", ""),
            "exit_code": rc,
            "verdict_line": line,
            "output": out.strip(),
        })
        print(f"[{i:02d}] {verdict:<10} {s['name'][:75]}", flush=True)

    counts = {v: sum(1 for r in rows if r["verdict"] == v) for v in VERDICTS + ("NO_VERDICT",)}
    meta = {
        "scenario": os.path.basename(args.scenario),
        "scenario_sha256": hashlib.sha256(raw).hexdigest(),
        "steps": len(rows),
        "counts": counts,
        "host": host,
    }

    with open(os.path.join(args.out, "results.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "results": rows}, f, indent=2)

    lines = [
        f"EM-01 read-only run: {meta['scenario']}",
        f"YAML sha256: {meta['scenario_sha256']}",
        f"Host: {host.get('hostname')} | {host.get('Caption')} | ProductType={host.get('ProductType')} "
        f"({host.get('ProductTypeMeaning')}) | {host.get('Manufacturer')} {host.get('Model')} | admin={host.get('IsAdmin')}",
        f"Run at: {host.get('runAt')}",
        "Counts: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
        "",
        "Non-PASS results:",
    ]
    for r in rows:
        if r["verdict"] != "PASS":
            lines.append(f"  [{r['index']:02d}] {r['verdict']:<10} {r['name']}")
            if r["verdict_line"]:
                lines.append(f"        {r['verdict_line'][:240]}")
    with open(os.path.join(args.out, "summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("\n" + "\n".join(lines[:5]))
    print(f"Wrote {args.out}\\results.csv, results.json, summary.txt")
    return 0 if counts.get("NO_VERDICT", 0) == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
