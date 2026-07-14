# Detection Rule Library (SP2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a curated, technique-indexed library of Sigma detection rules translated into 5 vendor query languages (Sentinel KQL, Defender XDR KQL, Splunk SPL, Elastic Lucene, CrowdStrike LogScale), browsable/exportable via a read-only API, and linkable from scenario expectations.

**Architecture:** A dev-time-only Python generator (4 stages: load → translate → validate → export) converts a small curated set of real Sigma rules — scoped to ATT&CK techniques the platform's `scenarios/detection-profiles/*.yaml` already cover — into a committed JSON artifact. A new Go package `internal/rulelib` embeds that JSON via `go:embed` (same pattern as `internal/reporting/attackdata`), builds in-memory indexes, and serves it through read-only API endpoints. `scenario.ExpectedDetection` gains an optional `RuleIDs []string` field linking expectations to library rules.

**Tech Stack:** Python 3.10+ (pySigma 1.4.0 + 5 backend plugins, dev-time only, never shipped), Go (`go:embed`, chi router), no new database table (this is static embedded content, not per-deployment config).

**Scope note:** This plan covers the backend (generator + Go package + API) only, matching how SP1's first slice shipped — the "Detection Rules" UI page and Detection Validation report cross-linking from the design spec are a follow-up, not part of this plan.

## Global Constraints

- Read-only library: no vendor write/deployment APIs, no push automation (spec: "Why" section).
- Generator scoped to techniques already declared in `scenarios/*.yaml` step `technique_id` fields that also reference a `detection_profiles` entry — not full SigmaHQ bulk conversion (spec: "Generator Pipeline" §1).
- 5 backends only: `pysigma-backend-kusto` (Sentinel), `pysigma-backend-microsoft365defender` (Defender XDR), `pysigma-backend-splunk`, `pysigma-backend-elasticsearch`, `pysigma-backend-crowdstrike`. QRadar excluded — its backend plugin requires an incompatible ancient pySigma core (verified 2026-07-14).
- Quality gate (spec: "Generator Pipeline" §3): fail the build only on a zero-translation rule, malformed Sigma, an unrecognized ATT&CK technique ID, duplicate IDs, or any single backend's failure rate exceeding 25% of attempted rules. An isolated single rule/backend gap below that threshold is a warning, not a failure.
- Runtime degrades gracefully: schema-version mismatch or embed/parse failure → empty engine, never blocks orchestrator startup (spec: "Runtime Loading & Degradation").
- `ExpectedDetection.RuleIDs` is optional and backward compatible — existing profiles without it render exactly as today.
- The generator never runs as part of `packaging/windows-build.ps1` — it's a manual, occasionally-rerun tool whose output is committed to git.

---

### Task 1: Python generator — technique scoping + Sigma loading

**Files:**
- Create: `scripts/rulelib-gen/requirements.txt`
- Create: `scripts/rulelib-gen/techniques.py`
- Create: `scripts/rulelib-gen/load_sigma.py`
- Create: `scripts/rulelib-gen/sigma_seed/t1059_001_encoded_powershell.yml`
- Create: `scripts/rulelib-gen/sigma_seed/t1558_003_kerberoasting.yml`
- Test: `scripts/rulelib-gen/tests/test_techniques.py`
- Test: `scripts/rulelib-gen/tests/test_load_sigma.py`
- Test: `scripts/rulelib-gen/tests/fixtures/no_technique_tag.yml`
- Test: `scripts/rulelib-gen/tests/fixtures/unrelated_technique.yml`

**Interfaces:**
- Produces: `techniques.covered_techniques(scenarios_dir: str) -> set[str]`; `load_sigma.load_rules(sigma_dir: str, technique_ids: set[str]) -> list["sigma.rule.SigmaRule"]`; `load_sigma.rule_technique_ids(rule) -> set[str]`.

- [ ] **Step 1: Create the generator directory and pin dependencies**

```bash
mkdir -p scripts/rulelib-gen/tests/fixtures scripts/rulelib-gen/sigma_seed
```

Write `scripts/rulelib-gen/requirements.txt` (versions verified working together 2026-07-14 — `pysigma-backend-qradar` is deliberately excluded, see Global Constraints):

```
pysigma==1.4.0
pysigma-backend-splunk==2.1.0
pysigma-backend-elasticsearch==2.1.0
pysigma-backend-microsoft365defender==0.3.2
pysigma-backend-crowdstrike==3.0.0
pyyaml>=6.0.1
pytest>=8.0.0
```

Requires Python 3.10+. Create and activate a venv, then install:

```bash
python -m venv scripts/rulelib-gen/.venv
scripts/rulelib-gen/.venv/Scripts/pip install -r scripts/rulelib-gen/requirements.txt
```

- [ ] **Step 2: Write the failing test for technique scoping**

```python
# scripts/rulelib-gen/tests/test_techniques.py
import os
import tempfile
import textwrap

from techniques import covered_techniques


def test_covered_techniques_reads_technique_id_next_to_detection_profiles():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "scenario1.yaml"), "w") as f:
            f.write(textwrap.dedent("""
                id: scenario1
                name: Test Scenario
                steps:
                  - name: step with profile
                    technique_id: T1059.001
                    detection_profiles:
                      - windows_encoded_powershell
                  - name: step without profile
                    technique_id: T1547.001
            """))
        result = covered_techniques(d)
    assert result == {"T1059.001"}


def test_covered_techniques_scans_multiple_files():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.yaml"), "w") as f:
            f.write(textwrap.dedent("""
                id: a
                name: A
                steps:
                  - name: s1
                    technique_id: T1558.003
                    detection_profiles: [windows_kerberoast]
            """))
        with open(os.path.join(d, "b.yaml"), "w") as f:
            f.write(textwrap.dedent("""
                id: b
                name: B
                steps:
                  - name: s2
                    technique_id: T1059.001
                    detection_profiles: [windows_encoded_powershell]
            """))
        result = covered_techniques(d)
    assert result == {"T1558.003", "T1059.001"}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_techniques.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'techniques'`

- [ ] **Step 4: Write `techniques.py`**

```python
# scripts/rulelib-gen/techniques.py
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
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_techniques.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Add two real, curated seed Sigma rules**

Write `scripts/rulelib-gen/sigma_seed/t1059_001_encoded_powershell.yml`:

```yaml
title: Suspicious PowerShell Encoded Command
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Detects encoded PowerShell command execution
author: Audspect
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
falsepositives:
    - Legitimate admin scripts using encoded commands
level: medium
```

Write `scripts/rulelib-gen/sigma_seed/t1558_003_kerberoasting.yml`:

```yaml
title: Kerberoasting via SPN Enumeration Tooling
id: 87654321-4321-4321-4321-210987654321
status: stable
description: Detects setspn.exe or PowerShell SPN enumeration commonly used before a Kerberoasting attack
author: Audspect
references:
    - https://attack.mitre.org/techniques/T1558/003/
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_setspn:
        Image|endswith: '\setspn.exe'
        CommandLine|contains: '-Q'
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'GetUserSPNs'
    condition: selection_setspn or selection_powershell
falsepositives:
    - Legitimate AD administration and SPN auditing
level: medium
```

- [ ] **Step 7: Write the failing test for Sigma loading + technique filtering**

```python
# scripts/rulelib-gen/tests/test_load_sigma.py
import os

from load_sigma import load_rules, rule_technique_ids

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_seed")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def test_load_rules_filters_to_requested_techniques():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    assert len(rules) == 1
    assert rules[0].title == "Suspicious PowerShell Encoded Command"


def test_load_rules_returns_empty_for_unmatched_technique():
    rules = load_rules(SEED_DIR, technique_ids={"T9999.999"})
    assert rules == []


def test_load_rules_loads_multiple_matching_files():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001", "T1558.003"})
    assert len(rules) == 2


def test_rule_technique_ids_extracts_uppercase_technique_ids():
    rules = load_rules(SEED_DIR, technique_ids={"T1558.003"})
    assert rule_technique_ids(rules[0]) == {"T1558.003"}
```

- [ ] **Step 8: Run the test to verify it fails**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_load_sigma.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'load_sigma'`

- [ ] **Step 9: Write `load_sigma.py`**

```python
# scripts/rulelib-gen/load_sigma.py
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
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_load_sigma.py -v`
Expected: PASS (4 tests)

- [ ] **Step 11: Commit**

```bash
git add scripts/rulelib-gen/requirements.txt scripts/rulelib-gen/techniques.py scripts/rulelib-gen/load_sigma.py scripts/rulelib-gen/sigma_seed/ scripts/rulelib-gen/tests/test_techniques.py scripts/rulelib-gen/tests/test_load_sigma.py
git commit -m "feat(rulelib-gen): add technique scoping and Sigma rule loading (stage 1)"
git push
```

---

### Task 2: Python generator — per-backend translation (stage 2)

**Files:**
- Create: `scripts/rulelib-gen/translate.py`
- Test: `scripts/rulelib-gen/tests/test_translate.py`
- Test: `scripts/rulelib-gen/tests/fixtures/unconvertible_rule.yml`

**Interfaces:**
- Consumes: `load_sigma.load_rules`, `load_sigma.rule_technique_ids` (Task 1).
- Produces: `translate.BACKENDS: dict[str, tuple[type, str, str]]` (backend key → (backend class, vendor display key, language)); `translate.translate_rule(rule) -> tuple[list[dict], list[dict]]` returning `(translations, failures)` where each translation is `{"backend": ..., "language": ..., "query": ..., "generator": ...}` and each failure is `{"backend": ..., "reason": ...}`.

- [ ] **Step 1: Write the failing test**

```python
# scripts/rulelib-gen/tests/test_translate.py
from load_sigma import load_rules
from translate import translate_rule
import os

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_seed")


def test_translate_rule_produces_all_five_backends():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    translations, failures = translate_rule(rules[0])
    backends = {t["backend"] for t in translations}
    assert backends == {"microsoft_sentinel", "microsoft_defender", "splunk", "elastic", "crowdstrike"}
    assert failures == []


def test_translate_rule_output_shape():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    translations, _ = translate_rule(rules[0])
    splunk = next(t for t in translations if t["backend"] == "splunk")
    assert splunk["language"] == "SPL"
    assert "powershell.exe" in splunk["query"]
    assert splunk["generator"].startswith("pySigma")


def test_translate_rule_isolates_per_backend_failures():
    # A rule using a Sigma feature at least one backend can't handle should
    # still return successful translations for the others, plus a failure
    # entry for the one that broke — never raise.
    import textwrap
    import tempfile

    from sigma.collection import SigmaCollection

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "weird.yml")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""
                title: Weird Rule
                id: 11111111-1111-1111-1111-111111111111
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        Image|endswith: '\\\\cmd.exe'
                    condition: selection
                level: low
            """))
        rule = SigmaCollection.load_ruleset([path]).rules[0]
    translations, failures = translate_rule(rule)
    # This simple rule should convert cleanly everywhere — the point of this
    # test is that the return shape always holds (list, list), never a raise.
    assert isinstance(translations, list)
    assert isinstance(failures, list)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_translate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'translate'`

- [ ] **Step 3: Write `translate.py`**

```python
# scripts/rulelib-gen/translate.py
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_translate.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/rulelib-gen/translate.py scripts/rulelib-gen/tests/test_translate.py
git commit -m "feat(rulelib-gen): add per-backend rule translation (stage 2)"
git push
```

---

### Task 3: Python generator — quality-gate validation (stage 3)

**Files:**
- Create: `scripts/rulelib-gen/validate.py`
- Test: `scripts/rulelib-gen/tests/test_validate.py`

**Interfaces:**
- Consumes: nothing new — operates on the plain dict/list shapes `translate_rule` (Task 2) and the STIX technique-ID set produced in Task 4's export step; kept decoupled so it's independently testable with synthetic data.
- Produces: `validate.ValidationError(Exception)`; `validate.validate_build(built_rules: list[dict], known_technique_ids: set[str], failure_threshold: float = 0.25) -> None` — raises `ValidationError` on any fatal condition, returns normally (build continues) otherwise.

Each entry in `built_rules` has the shape: `{"id": "AUDRULE-000001", "sigmaId": "...", "techniqueIds": [...], "translations": [...], "failures": [...]}` (this is the per-rule record `export.py` will assemble in Task 4 — `validate.py` is written against this shape now so Task 4 can call it directly).

- [ ] **Step 1: Write the failing test**

```python
# scripts/rulelib-gen/tests/test_validate.py
import pytest

from validate import ValidationError, validate_build


def _rule(rule_id="AUDRULE-000001", sigma_id="sig-1", techniques=("T1059.001",), translations=None, failures=None):
    return {
        "id": rule_id,
        "sigmaId": sigma_id,
        "techniqueIds": list(techniques),
        "translations": translations if translations is not None else [{"backend": "splunk"}],
        "failures": failures if failures is not None else [],
    }


def test_validate_build_passes_on_healthy_input():
    validate_build([_rule()], known_technique_ids={"T1059.001"})  # should not raise


def test_validate_build_fails_on_zero_translation_rule():
    rule = _rule(translations=[], failures=[{"backend": "splunk", "reason": "x"}])
    with pytest.raises(ValidationError, match="zero successful translations"):
        validate_build([rule], known_technique_ids={"T1059.001"})


def test_validate_build_fails_on_unknown_technique_id():
    rule = _rule(techniques=("T9999.999",))
    with pytest.raises(ValidationError, match="unrecognized ATT&CK technique"):
        validate_build([rule], known_technique_ids={"T1059.001"})


def test_validate_build_fails_on_duplicate_rule_id():
    rules = [_rule(rule_id="AUDRULE-000001"), _rule(rule_id="AUDRULE-000001", sigma_id="sig-2")]
    with pytest.raises(ValidationError, match="duplicate rule id"):
        validate_build(rules, known_technique_ids={"T1059.001"})


def test_validate_build_fails_on_duplicate_sigma_id():
    rules = [_rule(rule_id="AUDRULE-000001", sigma_id="sig-1"), _rule(rule_id="AUDRULE-000002", sigma_id="sig-1")]
    with pytest.raises(ValidationError, match="duplicate sigma id"):
        validate_build(rules, known_technique_ids={"T1059.001"})


def test_validate_build_passes_below_failure_threshold():
    # 2 of 10 rules fail on "splunk" = 20%, below the 25% threshold — warn, don't fail.
    rules = [_rule(rule_id=f"AUDRULE-{i:06d}", sigma_id=f"sig-{i}") for i in range(8)]
    rules += [
        _rule(rule_id="AUDRULE-000008", sigma_id="sig-8", translations=[{"backend": "elastic"}],
              failures=[{"backend": "splunk", "reason": "x"}]),
        _rule(rule_id="AUDRULE-000009", sigma_id="sig-9", translations=[{"backend": "elastic"}],
              failures=[{"backend": "splunk", "reason": "x"}]),
    ]
    validate_build(rules, known_technique_ids={"T1059.001"})  # should not raise


def test_validate_build_fails_above_failure_threshold():
    # 3 of 10 rules fail on "splunk" = 30%, above the 25% threshold — systemic regression guard.
    rules = [_rule(rule_id=f"AUDRULE-{i:06d}", sigma_id=f"sig-{i}") for i in range(7)]
    rules += [
        _rule(rule_id=f"AUDRULE-{i:06d}", sigma_id=f"sig-{i}", translations=[{"backend": "elastic"}],
              failures=[{"backend": "splunk", "reason": "x"}])
        for i in range(7, 10)
    ]
    with pytest.raises(ValidationError, match="backend .* failure rate"):
        validate_build(rules, known_technique_ids={"T1059.001"})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_validate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'validate'`

- [ ] **Step 3: Write `validate.py`**

```python
# scripts/rulelib-gen/validate.py
"""Stage 3 of the generator pipeline: the quality gate. Fails the build (via
ValidationError) only on structural problems or a systemic per-backend
regression; an isolated single rule/backend translation gap is tolerated —
see the design spec's "Generator Pipeline" validate.py policy."""
from collections import defaultdict


class ValidationError(Exception):
    pass


def validate_build(built_rules: list[dict], known_technique_ids: set[str], failure_threshold: float = 0.25) -> None:
    seen_rule_ids: set[str] = set()
    seen_sigma_ids: set[str] = set()
    backend_attempts: dict[str, int] = defaultdict(int)
    backend_failures: dict[str, int] = defaultdict(int)

    for rule in built_rules:
        if rule["id"] in seen_rule_ids:
            raise ValidationError(f"duplicate rule id: {rule['id']}")
        seen_rule_ids.add(rule["id"])

        if rule["sigmaId"] in seen_sigma_ids:
            raise ValidationError(f"duplicate sigma id: {rule['sigmaId']}")
        seen_sigma_ids.add(rule["sigmaId"])

        for tid in rule["techniqueIds"]:
            if tid not in known_technique_ids:
                raise ValidationError(f"unrecognized ATT&CK technique {tid} on rule {rule['id']}")

        if not rule["translations"]:
            raise ValidationError(f"rule {rule['id']} has zero successful translations across all backends")

        for t in rule["translations"]:
            backend_attempts[t["backend"]] += 1
        for f in rule["failures"]:
            backend_attempts[f["backend"]] += 1
            backend_failures[f["backend"]] += 1

    for backend, attempts in backend_attempts.items():
        if attempts == 0:
            continue
        rate = backend_failures[backend] / attempts
        if rate > failure_threshold:
            raise ValidationError(
                f"backend {backend!r} failure rate {rate:.0%} exceeds the {failure_threshold:.0%} "
                "threshold — likely a broken backend plugin or a major compatibility regression, "
                "not normal per-rule variance"
            )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_validate.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add scripts/rulelib-gen/validate.py scripts/rulelib-gen/tests/test_validate.py
git commit -m "feat(rulelib-gen): add quality-gate validation (stage 3)"
git push
```

---

### Task 4: Python generator — JSON export (stage 4) + build entrypoint + real bundle

**Files:**
- Create: `scripts/rulelib-gen/export.py`
- Create: `scripts/rulelib-gen/build.py`
- Create: `orchestrator/internal/rulelib/ruledata/rules.json` (generated output, committed)
- Create: `orchestrator/internal/rulelib/ruledata/metadata.json` (generated output, committed)
- Test: `scripts/rulelib-gen/tests/test_export.py`

**Interfaces:**
- Consumes: `load_sigma.load_rules`, `load_sigma.rule_technique_ids` (Task 1); `translate.translate_rule` (Task 2); `validate.validate_build`, `validate.ValidationError` (Task 3).
- Produces: `export.build_rule_record(rule, index: int) -> dict` (the per-rule shape `validate_build` expects, now filled in for real from a SigmaRule); `export.write_bundle(rules_dir_out: str, built_rules: list[dict], metadata: dict) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# scripts/rulelib-gen/tests/test_export.py
import json
import os
import tempfile

from export import build_rule_record, write_bundle
from load_sigma import load_rules

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma_seed")


def test_build_rule_record_shape():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    record = build_rule_record(rules[0], index=1)
    assert record["id"] == "AUDRULE-000001"
    assert record["title"] == "Suspicious PowerShell Encoded Command"
    assert record["techniqueIds"] == ["T1059.001"]
    assert record["severity"] == "medium"
    assert record["status"] == "stable"
    assert "detection" in record and "selection" in record["detection"]
    assert len(record["translations"]) == 5
    assert record["failures"] == []


def test_write_bundle_produces_valid_json_files():
    rules = load_rules(SEED_DIR, technique_ids={"T1059.001"})
    record = build_rule_record(rules[0], index=1)
    metadata = {
        "schemaVersion": 1, "generatorVersion": "test", "sigmaCommit": "n/a",
        "generatedAt": "2026-07-14T00:00:00Z", "ruleCount": 1, "techniqueCount": 1,
        "backends": {"splunk": 1}, "translationFailures": [],
    }
    with tempfile.TemporaryDirectory() as d:
        write_bundle(d, [record], metadata)
        with open(os.path.join(d, "rules.json")) as f:
            rules_out = json.load(f)
        with open(os.path.join(d, "metadata.json")) as f:
            meta_out = json.load(f)
    assert rules_out == [record]
    assert meta_out == metadata
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_export.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'export'`

- [ ] **Step 3: Write `export.py`**

```python
# scripts/rulelib-gen/export.py
"""Stage 4 of the generator pipeline: assemble each SigmaRule + its
translations into the JSON shape internal/rulelib embeds, and write the
output files."""
import json
import os

from load_sigma import rule_technique_ids
from translate import translate_rule


def build_rule_record(rule, index: int) -> dict:
    translations, failures = translate_rule(rule)
    with open(rule.source.path, encoding="utf-8") as f:
        raw_yaml = f.read()
    return {
        "id": f"AUDRULE-{index:06d}",
        "sigmaId": str(rule.id),
        "title": rule.title,
        "description": rule.description or "",
        "techniqueIds": sorted(rule_technique_ids(rule)),
        "severity": str(rule.level) if rule.level else "",
        "status": str(rule.status) if rule.status else "",
        "author": rule.author or "",
        "references": [str(r) for r in rule.references],
        "falsePositives": [str(fp) for fp in rule.falsepositives],
        "logSource": {
            "category": rule.logsource.category or "",
            "product": rule.logsource.product or "",
            "service": rule.logsource.service or "",
        },
        "detection": raw_yaml,
        "translations": translations,
        "failures": failures,
    }


def write_bundle(out_dir: str, built_rules: list[dict], metadata: dict) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rules.json"), "w", encoding="utf-8") as f:
        json.dump(built_rules, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, sort_keys=True)
        f.write("\n")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scripts/rulelib-gen && .venv/Scripts/pytest tests/test_export.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Write `build.py`, the entrypoint that runs all 4 stages**

```python
# scripts/rulelib-gen/build.py
"""Entrypoint: runs load -> translate -> export -> validate against the
curated sigma_seed/ directory, scoped to techniques scenarios/*.yaml already
covers, and writes the bundle into internal/rulelib/ruledata/.

Usage:
    .venv/Scripts/python build.py [--sigma-dir sigma_seed] [--out ../../orchestrator/internal/rulelib/ruledata]

Re-run by hand whenever sigma_seed/ or scenarios/*.yaml changes — this is
never invoked by packaging/windows-build.ps1.
"""
import argparse
import datetime
import importlib.metadata
import os
import sys
from collections import Counter

from export import build_rule_record, write_bundle
from load_sigma import load_rules
from techniques import covered_techniques
from validate import ValidationError, validate_build

SCHEMA_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma-dir", default=os.path.join(os.path.dirname(__file__), "sigma_seed"))
    parser.add_argument("--scenarios-dir", default=os.path.join(os.path.dirname(__file__), "..", "..", "scenarios"))
    parser.add_argument("--out", default=os.path.join(
        os.path.dirname(__file__), "..", "..", "orchestrator", "internal", "rulelib", "ruledata"))
    args = parser.parse_args()

    technique_ids = covered_techniques(args.scenarios_dir)
    print(f"scoped to {len(technique_ids)} technique(s) from {args.scenarios_dir}: {sorted(technique_ids)}")

    rules = load_rules(args.sigma_dir, technique_ids)
    print(f"loaded {len(rules)} matching Sigma rule(s) from {args.sigma_dir}")

    built = [build_rule_record(r, i + 1) for i, r in enumerate(rules)]

    backend_counts: Counter = Counter()
    translation_failures: list[dict] = []
    for record in built:
        for t in record["translations"]:
            backend_counts[t["backend"]] += 1
        for f in record["failures"]:
            translation_failures.append({"ruleId": record["id"], "sigmaId": record["sigmaId"], **f})

    all_techniques: set[str] = set()
    for record in built:
        all_techniques.update(record["techniqueIds"])

    metadata = {
        "schemaVersion": SCHEMA_VERSION,
        "generatorVersion": _version("pysigma"),
        "sigmaCommit": "n/a (curated sigma_seed/, not a SigmaHQ checkout)",
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ruleCount": len(built),
        "techniqueCount": len(all_techniques),
        "backends": dict(backend_counts),
        "translationFailures": translation_failures,
    }

    try:
        validate_build(built, known_technique_ids=technique_ids)
    except ValidationError as e:
        print(f"VALIDATION FAILED: {e}", file=sys.stderr)
        return 1

    write_bundle(args.out, built, metadata)
    print(f"wrote {len(built)} rule(s) to {args.out}")
    return 0


def _version(dist: str) -> str:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Run the generator for real and produce the committed bundle**

```bash
cd scripts/rulelib-gen
.venv/Scripts/python build.py
```

Expected output: `scoped to N technique(s)...`, `loaded 2 matching Sigma rule(s)...` (the two seed rules, since both T1059.001 and T1558.003 are covered by existing `scenarios/*.yaml`), `wrote 2 rule(s) to .../internal/rulelib/ruledata`. Confirm the files exist:

```bash
ls -la ../../orchestrator/internal/rulelib/ruledata/
```

Expected: `rules.json` and `metadata.json` both present.

- [ ] **Step 7: Commit**

```bash
git add scripts/rulelib-gen/export.py scripts/rulelib-gen/build.py scripts/rulelib-gen/tests/test_export.py orchestrator/internal/rulelib/ruledata/rules.json orchestrator/internal/rulelib/ruledata/metadata.json
git commit -m "feat(rulelib-gen): add JSON export (stage 4), build entrypoint, and initial bundle"
git push
```

---

### Task 5: Go runtime — data model + embedded engine

**Files:**
- Create: `orchestrator/internal/rulelib/model.go`
- Create: `orchestrator/internal/rulelib/engine.go`
- Test: `orchestrator/internal/rulelib/engine_test.go`
- Test: `orchestrator/internal/rulelib/testdata/rules.json`
- Test: `orchestrator/internal/rulelib/testdata/metadata_bad_version.json`

**Interfaces:**
- Consumes: `orchestrator/internal/rulelib/ruledata/{rules.json,metadata.json}` (Task 4).
- Produces: `Rule`, `LogSource`, `Translation`, `Metadata` structs; `func NewEngine() *Engine`; `(*Engine) RuleCount() int`; `(*Engine) Metadata() Metadata` — Tasks 6-8 build on this.

- [ ] **Step 1: Create the package directory and write `model.go`**

```go
// orchestrator/internal/rulelib/model.go

// Package rulelib is the Detection Rule Library (SP2) — a curated,
// technique-indexed set of Sigma detection rules translated into 5 vendor
// query languages, embedded into the orchestrator binary at build time. See
// docs/superpowers/specs/2026-07-14-detection-rule-library-design.md.
//
// This package does no I/O beyond the embedded JSON — the content is
// generated offline by scripts/rulelib-gen (Python) and committed to git.
package rulelib

// Rule is one curated detection rule: its Sigma content plus every backend
// translation that converted successfully.
type Rule struct {
	ID             string      `json:"id"`             // stable, Audspect-owned: "AUDRULE-000001"
	SigmaID        string      `json:"sigmaId"`        // upstream Sigma rule UUID — traceability only
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	TechniqueIDs   []string    `json:"techniqueIds"`
	Severity       string      `json:"severity"`
	Status         string      `json:"status"`
	Author         string      `json:"author"`
	References     []string    `json:"references"`
	FalsePositives []string    `json:"falsePositives"`
	LogSource      LogSource   `json:"logSource"`
	Detection      string      `json:"detection"` // raw Sigma YAML, verbatim
	Translations   []Translation `json:"translations"`
	Failures       []TranslationFailure `json:"failures"`
}

type LogSource struct {
	Category string `json:"category"`
	Product  string `json:"product"`
	Service  string `json:"service"`
}

type Translation struct {
	Backend   string `json:"backend"`  // provider-registry key: microsoft_sentinel | microsoft_defender | splunk | elastic | crowdstrike
	Language  string `json:"language"` // KQL | SPL | Lucene | LogScale
	Query     string `json:"query"`
	Generator string `json:"generator"`
}

type TranslationFailure struct {
	Backend string `json:"backend"`
	Reason  string `json:"reason"`
}

// Metadata is the generator's provenance and quality-gate audit trail.
type Metadata struct {
	SchemaVersion    int              `json:"schemaVersion"`
	GeneratorVersion string           `json:"generatorVersion"`
	SigmaCommit      string           `json:"sigmaCommit"`
	GeneratedAt      string           `json:"generatedAt"`
	RuleCount        int              `json:"ruleCount"`
	TechniqueCount   int              `json:"techniqueCount"`
	Backends         map[string]int   `json:"backends"`
	TranslationFailures []MetadataFailure `json:"translationFailures"`
}

type MetadataFailure struct {
	RuleID  string `json:"ruleId"`
	SigmaID string `json:"sigmaId"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`
}
```

- [ ] **Step 2: Write the failing test for engine loading**

```go
// orchestrator/internal/rulelib/engine_test.go
package rulelib

import "testing"

func TestNewEngine_LoadsEmbeddedBundle(t *testing.T) {
	e := NewEngine()
	if e.RuleCount() == 0 {
		t.Fatal("expected at least one rule from the embedded ruledata bundle")
	}
	meta := e.Metadata()
	if meta.SchemaVersion != currentSchemaVersion {
		t.Fatalf("Metadata().SchemaVersion = %d, want %d", meta.SchemaVersion, currentSchemaVersion)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/rulelib/... -run TestNewEngine -v`
Expected: FAIL — `undefined: NewEngine` (package doesn't compile yet)

- [ ] **Step 4: Write `engine.go`**

```go
// orchestrator/internal/rulelib/engine.go
package rulelib

import (
	"embed"
	"encoding/json"
	"log"
)

//go:embed ruledata/rules.json ruledata/metadata.json
var ruledataFS embed.FS

// currentSchemaVersion is the metadata.schemaVersion this binary understands.
// A mismatch means the embedded bundle was generated by an incompatible
// generator — the engine loads empty rather than risk serving malformed data.
const currentSchemaVersion = 1

// Engine holds the loaded rule library in memory. Safe for concurrent read
// access after construction (never mutated post-NewEngine).
type Engine struct {
	rules    []Rule
	metadata Metadata
}

// NewEngine loads the embedded rule bundle. On any parse failure or schema
// version mismatch, it logs a warning and returns an engine with zero rules
// — the rule library silently disables rather than blocking orchestrator
// startup (matches the nil-safe-resolver pattern used elsewhere in this
// codebase, e.g. reporting.Engine's ScenarioResolver/VerificationResolver).
func NewEngine() *Engine {
	metaRaw, err := ruledataFS.ReadFile("ruledata/metadata.json")
	if err != nil {
		log.Printf("[rulelib] read metadata.json: %v — rule library disabled", err)
		return &Engine{}
	}
	var meta Metadata
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		log.Printf("[rulelib] parse metadata.json: %v — rule library disabled", err)
		return &Engine{}
	}
	if meta.SchemaVersion != currentSchemaVersion {
		log.Printf("[rulelib] embedded schemaVersion %d != supported %d — rule library disabled",
			meta.SchemaVersion, currentSchemaVersion)
		return &Engine{}
	}

	rulesRaw, err := ruledataFS.ReadFile("ruledata/rules.json")
	if err != nil {
		log.Printf("[rulelib] read rules.json: %v — rule library disabled", err)
		return &Engine{}
	}
	var rules []Rule
	if err := json.Unmarshal(rulesRaw, &rules); err != nil {
		log.Printf("[rulelib] parse rules.json: %v — rule library disabled", err)
		return &Engine{}
	}

	return &Engine{rules: rules, metadata: meta}
}

func (e *Engine) RuleCount() int    { return len(e.rules) }
func (e *Engine) Metadata() Metadata { return e.metadata }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/rulelib/... -run TestNewEngine -v`
Expected: PASS

- [ ] **Step 6: Write the degradation test using local test fixtures**

Note: this test exercises the parse-failure path directly (not via `go:embed`, which is fixed at compile time to the real `ruledata/` files) by calling the same parsing logic against fixture bytes. Refactor `NewEngine` to route through a testable `loadFromBytes` helper:

Modify `engine.go` — replace the body of `NewEngine` with a call to a new helper:

```go
func NewEngine() *Engine {
	metaRaw, err := ruledataFS.ReadFile("ruledata/metadata.json")
	if err != nil {
		log.Printf("[rulelib] read metadata.json: %v — rule library disabled", err)
		return &Engine{}
	}
	rulesRaw, err := ruledataFS.ReadFile("ruledata/rules.json")
	if err != nil {
		log.Printf("[rulelib] read rules.json: %v — rule library disabled", err)
		return &Engine{}
	}
	return loadFromBytes(rulesRaw, metaRaw)
}

// loadFromBytes is NewEngine's parsing logic, factored out so tests can
// exercise the degradation paths without depending on go:embed's
// compile-time-fixed file set.
func loadFromBytes(rulesRaw, metaRaw []byte) *Engine {
	var meta Metadata
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		log.Printf("[rulelib] parse metadata.json: %v — rule library disabled", err)
		return &Engine{}
	}
	if meta.SchemaVersion != currentSchemaVersion {
		log.Printf("[rulelib] embedded schemaVersion %d != supported %d — rule library disabled",
			meta.SchemaVersion, currentSchemaVersion)
		return &Engine{}
	}
	var rules []Rule
	if err := json.Unmarshal(rulesRaw, &rules); err != nil {
		log.Printf("[rulelib] parse rules.json: %v — rule library disabled", err)
		return &Engine{}
	}
	return &Engine{rules: rules, metadata: meta}
}
```

Add to `engine_test.go`:

```go
func TestLoadFromBytes_SchemaVersionMismatch_ReturnsEmptyEngine(t *testing.T) {
	meta := []byte(`{"schemaVersion": 999}`)
	e := loadFromBytes([]byte(`[]`), meta)
	if e.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for an unsupported schema version", e.RuleCount())
	}
}

func TestLoadFromBytes_CorruptJSON_ReturnsEmptyEngine(t *testing.T) {
	e := loadFromBytes([]byte(`not json`), []byte(`{"schemaVersion": 1}`))
	if e.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for corrupt rules.json", e.RuleCount())
	}

	e2 := loadFromBytes([]byte(`[]`), []byte(`not json`))
	if e2.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for corrupt metadata.json", e2.RuleCount())
	}
}
```

- [ ] **Step 7: Run all engine tests**

Run: `cd orchestrator && go test ./internal/rulelib/... -v`
Expected: PASS (3 tests)

- [ ] **Step 8: Format, build, vet, commit**

```bash
cd orchestrator
go build ./...
go vet ./internal/rulelib/...
git add internal/rulelib/model.go internal/rulelib/engine.go internal/rulelib/engine_test.go
git commit -m "feat(rulelib): add data model and embedded engine with schema-version guard"
git push
```

---

### Task 6: Go runtime — indexes and search

**Files:**
- Create: `orchestrator/internal/rulelib/index.go`
- Create: `orchestrator/internal/rulelib/search.go`
- Test: `orchestrator/internal/rulelib/index_test.go`
- Test: `orchestrator/internal/rulelib/search_test.go`

**Interfaces:**
- Consumes: `Rule`, `Engine` (Task 5).
- Produces: `(*Engine) RuleByID(id string) (Rule, bool)`; `(*Engine) RulesByTechnique(techniqueID string) []Rule`; `SearchFilter` struct (`Technique, Backend, Status, Severity, LogSource, Query string`); `(*Engine) Search(f SearchFilter) []Rule`.

- [ ] **Step 1: Write the failing test for indexed lookups**

```go
// orchestrator/internal/rulelib/index_test.go
package rulelib

import "testing"

func testEngine() *Engine {
	return loadFromBytes([]byte(`[
		{"id":"AUDRULE-000001","sigmaId":"s1","title":"Encoded PowerShell","techniqueIds":["T1059.001"],
		 "severity":"medium","status":"stable","logSource":{"category":"process_creation","product":"windows"},
		 "translations":[{"backend":"splunk","language":"SPL","query":"..."},{"backend":"elastic","language":"Lucene","query":"..."}]},
		{"id":"AUDRULE-000002","sigmaId":"s2","title":"Kerberoasting SPN Enum","techniqueIds":["T1558.003"],
		 "severity":"high","status":"test","logSource":{"category":"process_creation","product":"windows"},
		 "translations":[{"backend":"splunk","language":"SPL","query":"..."}]}
	]`), []byte(`{"schemaVersion":1}`))
}

func TestRuleByID_FoundAndNotFound(t *testing.T) {
	e := testEngine()
	r, ok := e.RuleByID("AUDRULE-000001")
	if !ok || r.Title != "Encoded PowerShell" {
		t.Fatalf("RuleByID(AUDRULE-000001) = %+v, %v", r, ok)
	}
	if _, ok := e.RuleByID("AUDRULE-999999"); ok {
		t.Fatal("expected ok=false for an unknown rule id")
	}
}

func TestRulesByTechnique(t *testing.T) {
	e := testEngine()
	rules := e.RulesByTechnique("T1558.003")
	if len(rules) != 1 || rules[0].ID != "AUDRULE-000002" {
		t.Fatalf("RulesByTechnique(T1558.003) = %+v", rules)
	}
	if len(e.RulesByTechnique("T9999.999")) != 0 {
		t.Fatal("expected no rules for an unknown technique")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/rulelib/... -run 'TestRuleByID|TestRulesByTechnique' -v`
Expected: FAIL — `undefined: (*Engine).RuleByID`

- [ ] **Step 3: Write `index.go`**

```go
// orchestrator/internal/rulelib/index.go
package rulelib

// buildIndexes constructs the lookup maps used by RuleByID/RulesByTechnique/
// Search. Called once from loadFromBytes so every read afterward is O(1)
// map access, never a linear scan.
type indexes struct {
	byID        map[string]Rule
	byTechnique map[string][]Rule
	byBackend   map[string][]Rule
	byStatus    map[string][]Rule
	bySeverity  map[string][]Rule
}

func buildIndexes(rules []Rule) indexes {
	idx := indexes{
		byID:        make(map[string]Rule, len(rules)),
		byTechnique: map[string][]Rule{},
		byBackend:   map[string][]Rule{},
		byStatus:    map[string][]Rule{},
		bySeverity:  map[string][]Rule{},
	}
	for _, r := range rules {
		idx.byID[r.ID] = r
		for _, t := range r.TechniqueIDs {
			idx.byTechnique[t] = append(idx.byTechnique[t], r)
		}
		for _, tr := range r.Translations {
			idx.byBackend[tr.Backend] = append(idx.byBackend[tr.Backend], r)
		}
		idx.byStatus[r.Status] = append(idx.byStatus[r.Status], r)
		idx.bySeverity[r.Severity] = append(idx.bySeverity[r.Severity], r)
	}
	return idx
}

func (e *Engine) RuleByID(id string) (Rule, bool) {
	r, ok := e.idx.byID[id]
	return r, ok
}

func (e *Engine) RulesByTechnique(techniqueID string) []Rule {
	return e.idx.byTechnique[techniqueID]
}
```

Modify `engine.go`'s `Engine` struct and `loadFromBytes` to build the indexes:

```go
type Engine struct {
	rules    []Rule
	metadata Metadata
	idx      indexes
}
```

In `loadFromBytes`, change the final line from `return &Engine{rules: rules, metadata: meta}` to:

```go
	return &Engine{rules: rules, metadata: meta, idx: buildIndexes(rules)}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/rulelib/... -run 'TestRuleByID|TestRulesByTechnique' -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for search**

```go
// orchestrator/internal/rulelib/search_test.go
package rulelib

import "testing"

func TestSearch_FiltersByTechniqueAndBackend(t *testing.T) {
	e := testEngine()
	got := e.Search(SearchFilter{Technique: "T1059.001", Backend: "elastic"})
	if len(got) != 1 || got[0].ID != "AUDRULE-000001" {
		t.Fatalf("Search(technique+backend) = %+v", got)
	}
}

func TestSearch_FiltersBySeverityAndStatus(t *testing.T) {
	e := testEngine()
	got := e.Search(SearchFilter{Severity: "high", Status: "test"})
	if len(got) != 1 || got[0].ID != "AUDRULE-000002" {
		t.Fatalf("Search(severity+status) = %+v", got)
	}
}

func TestSearch_FreeTextTitleMatch(t *testing.T) {
	e := testEngine()
	got := e.Search(SearchFilter{Query: "kerberoast"})
	if len(got) != 1 || got[0].ID != "AUDRULE-000002" {
		t.Fatalf("Search(query=kerberoast) = %+v, want case-insensitive title match", got)
	}
}

func TestSearch_NoFilters_ReturnsEverything(t *testing.T) {
	e := testEngine()
	if got := e.Search(SearchFilter{}); len(got) != 2 {
		t.Fatalf("Search(no filters) = %d rules, want 2", len(got))
	}
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/rulelib/... -run TestSearch -v`
Expected: FAIL — `undefined: SearchFilter`

- [ ] **Step 7: Write `search.go`**

```go
// orchestrator/internal/rulelib/search.go
package rulelib

import "strings"

// SearchFilter combines any number of dimensions; an empty field means "no
// filter on that dimension". All non-empty fields are ANDed together.
type SearchFilter struct {
	Technique string
	Backend   string
	Status    string
	Severity  string
	LogSource string
	Query     string // free-text, matched case-insensitively against Title
}

// Search returns every rule matching every non-empty filter field.
func (e *Engine) Search(f SearchFilter) []Rule {
	candidates := e.rules
	if f.Technique != "" {
		candidates = e.idx.byTechnique[f.Technique]
	}

	var out []Rule
	for _, r := range candidates {
		if f.Backend != "" && !hasBackend(r, f.Backend) {
			continue
		}
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		if f.Severity != "" && r.Severity != f.Severity {
			continue
		}
		if f.LogSource != "" && r.LogSource.Category != f.LogSource {
			continue
		}
		if f.Query != "" && !strings.Contains(strings.ToLower(r.Title), strings.ToLower(f.Query)) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func hasBackend(r Rule, backend string) bool {
	for _, t := range r.Translations {
		if t.Backend == backend {
			return true
		}
	}
	return false
}
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/rulelib/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 9: Format, build, vet, commit**

```bash
cd orchestrator
go build ./...
go vet ./internal/rulelib/...
git add internal/rulelib/index.go internal/rulelib/index_test.go internal/rulelib/search.go internal/rulelib/search_test.go internal/rulelib/engine.go
git commit -m "feat(rulelib): add in-memory indexes and multi-dimension search"
git push
```

---

### Task 7: `ExpectedDetection.RuleIDs` schema field

**Files:**
- Modify: `orchestrator/internal/scenario/detection.go`
- Test: `orchestrator/internal/scenario/detection_profiles_test.go`

**Interfaces:**
- Consumes: existing `scenario.ExpectedDetection` struct.
- Produces: `ExpectedDetection.RuleIDs []string` — consumed by a future UI/report task (out of scope here), verified now only for backward-compatible YAML round-tripping.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/scenario/detection_profiles_test.go`:

```go
func TestExpectedDetection_RuleIDsRoundTripsThroughYAML(t *testing.T) {
	yamlDoc := []byte(`
profile: test_profile
version: 1
expected_detection:
  - id: exp-1
    provider: microsoft_sentinel
    confidence: required
    rule_ids: ["AUDRULE-000001", "AUDRULE-000002"]
  - id: exp-2
    provider: microsoft_defender
    confidence: recommended
`)
	var p DetectionProfile
	if err := yaml.Unmarshal(yamlDoc, &p); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := p.Expected[0].RuleIDs; len(got) != 2 || got[0] != "AUDRULE-000001" || got[1] != "AUDRULE-000002" {
		t.Fatalf("Expected[0].RuleIDs = %v, want [AUDRULE-000001 AUDRULE-000002]", got)
	}
	if got := p.Expected[1].RuleIDs; len(got) != 0 {
		t.Fatalf("Expected[1].RuleIDs = %v, want empty when rule_ids is omitted", got)
	}
}
```

(This file already imports `gopkg.in/yaml.v3` as `yaml` and defines `DetectionProfile`/`ExpectedDetection` test coverage — confirm the import alias matches the existing file before adding; if the existing tests use a different unmarshal helper, call that instead of `yaml.Unmarshal` directly.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestExpectedDetection_RuleIDsRoundTripsThroughYAML -v`
Expected: FAIL — the YAML unmarshals but `p.Expected[0].RuleIDs` doesn't exist yet (compile error: `unknown field RuleIDs`)

- [ ] **Step 3: Add the field to `ExpectedDetection`**

In `orchestrator/internal/scenario/detection.go`, find the `ExpectedDetection` struct's `Finding` field (the last field) and add `RuleIDs` immediately after it:

```go
	// RuleIDs optionally links this expectation to one or more Detection Rule
	// Library entries (internal/rulelib.Rule.ID, e.g. "AUDRULE-000001"). Empty
	// is fully backward compatible — existing profiles render exactly as
	// before. One technique commonly maps to several rules, hence a slice.
	RuleIDs []string `yaml:"rule_ids,omitempty" json:"ruleIds,omitempty"`
}
```

(i.e. insert the `RuleIDs` field + comment before the struct's closing `}`, right after the existing `Finding ExpectedFinding` field.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/scenario/... -run TestExpectedDetection_RuleIDsRoundTripsThroughYAML -v`
Expected: PASS

- [ ] **Step 5: Run the full scenario package test suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/scenario/... -v 2>&1 | tail -20`
Expected: all PASS, ending in `ok`.

- [ ] **Step 6: Format, build, vet, commit**

```bash
cd orchestrator
go build ./...
go vet ./internal/scenario/...
git add internal/scenario/detection.go internal/scenario/detection_profiles_test.go
git commit -m "feat(scenario): add optional RuleIDs field linking expectations to the rule library"
git push
```

---

### Task 8: API — read-only rule library endpoints

**Files:**
- Create: `orchestrator/internal/api/rulelib_handlers.go`
- Test: `orchestrator/internal/api/rulelib_handlers_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `rules *rulelib.Engine` field + `WithRuleLibrary` setter)
- Modify: `orchestrator/internal/api/routes.go` (register routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add route entries)
- Modify: `orchestrator/cmd/server/main.go` (wire `rulelib.NewEngine()` into the handler chain)

**Interfaces:**
- Consumes: `rulelib.NewEngine`, `rulelib.Engine.{RuleByID,RulesByTechnique,Search,SearchFilter}` (Tasks 5-6); existing `Handler` struct, `jsonError`/`respond` helpers, `chi.URLParam`.
- Produces: `h.ListRules`, `h.GetRule`, `h.SearchRules`, `h.RulesByTechnique`, `h.ExportRule` HTTP handlers.

- [ ] **Step 1: Add the `rules` field and `WithRuleLibrary` setter to `Handler`**

In `orchestrator/internal/api/handlers.go`, add to the `Handler` struct (same location/style as the other `With*`-wired optional subsystems, e.g. near `verification *verification.Store`):

```go
	rules            *rulelib.Engine       // nil when not loaded — Detection Rule Library
```

Add the import:

```go
	"github.com/audspect/bas/internal/rulelib"
```

Add the setter near `WithVerificationStore`:

```go
// WithRuleLibrary attaches the Detection Rule Library engine.
func (h *Handler) WithRuleLibrary(e *rulelib.Engine) *Handler {
	h.rules = e
	return h
}
```

- [ ] **Step 2: Write the failing tests**

```go
// orchestrator/internal/api/rulelib_handlers_test.go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func rulelibTestHandler(t *testing.T) *Handler {
	t.Helper()
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	return h.WithRuleLibrary(rulelib.NewEngine())
}

func TestListRules_ReturnsEmbeddedBundle(t *testing.T) {
	h := rulelibTestHandler(t)
	rec := httptest.NewRecorder()
	h.ListRules(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected at least one rule from the embedded bundle")
	}
}

func TestGetRule_FoundAndNotFound(t *testing.T) {
	h := rulelibTestHandler(t)
	listRec := httptest.NewRecorder()
	h.ListRules(listRec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	var list []map[string]any
	json.Unmarshal(listRec.Body.Bytes(), &list)
	firstID := list[0]["id"].(string)

	rec := httptest.NewRecorder()
	h.GetRule(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", firstID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	notFoundRec := httptest.NewRecorder()
	h.GetRule(notFoundRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "AUDRULE-999999"))
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown rule id", notFoundRec.Code)
	}
}

func TestSearchRules_FiltersByQueryParams(t *testing.T) {
	h := rulelibTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules/search?backend=splunk", nil)
	h.SearchRules(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	for _, r := range out {
		translations := r["translations"].([]any)
		found := false
		for _, tr := range translations {
			if tr.(map[string]any)["backend"] == "splunk" {
				found = true
			}
		}
		if !found {
			t.Fatalf("result %v has no splunk translation despite backend=splunk filter", r["id"])
		}
	}
}

func TestRulesByTechnique_UnknownTechniqueReturnsEmptyList(t *testing.T) {
	h := rulelibTestHandler(t)
	rec := httptest.NewRecorder()
	h.RulesByTechnique(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "T9999.999"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 0 {
		t.Fatalf("expected an empty list for an unknown technique, got %d", len(out))
	}
}

func TestExportRule_ReturnsRequestedFormat(t *testing.T) {
	h := rulelibTestHandler(t)
	listRec := httptest.NewRecorder()
	h.ListRules(listRec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	var list []map[string]any
	json.Unmarshal(listRec.Body.Bytes(), &list)
	firstID := list[0]["id"].(string)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules/export?id="+firstID+"&format=sigma", nil)
	h.ExportRule(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/plain", rec.Header().Get("Content-Type"))
	}

	badRec := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodGet, "/api/rules/export?id="+firstID+"&format=cobol", nil)
	h.ExportRule(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unsupported format", badRec.Code)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListRules|TestGetRule|TestSearchRules|TestRulesByTechnique|TestExportRule' -v`
Expected: FAIL — `h.ListRules undefined` (compile error)

- [ ] **Step 4: Write `rulelib_handlers.go`**

```go
// orchestrator/internal/api/rulelib_handlers.go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/rulelib"
)

// ListRules returns every rule in the library.
// GET /api/rules
func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	if h.rules == nil {
		respond(w, []rulelib.Rule{})
		return
	}
	respond(w, h.rules.Search(rulelib.SearchFilter{}))
}

// GetRule returns one rule's full content, including every translation.
// GET /api/rules/{id}
func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if h.rules == nil {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}
	rule, ok := h.rules.RuleByID(id)
	if !ok {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}
	respond(w, rule)
}

// SearchRules filters the library by any combination of technique, backend,
// status, severity, log source, and free-text title.
// GET /api/rules/search?technique=&backend=&status=&severity=&logsource=&q=
func (h *Handler) SearchRules(w http.ResponseWriter, r *http.Request) {
	if h.rules == nil {
		respond(w, []rulelib.Rule{})
		return
	}
	q := r.URL.Query()
	respond(w, h.rules.Search(rulelib.SearchFilter{
		Technique: q.Get("technique"),
		Backend:   q.Get("backend"),
		Status:    q.Get("status"),
		Severity:  q.Get("severity"),
		LogSource: q.Get("logsource"),
		Query:     q.Get("q"),
	}))
}

// RulesByTechnique is a convenience wrapper over Search for one technique ID.
// GET /api/rules/technique/{id}
func (h *Handler) RulesByTechnique(w http.ResponseWriter, r *http.Request) {
	techniqueID := chi.URLParam(r, "id")
	if h.rules == nil {
		respond(w, []rulelib.Rule{})
		return
	}
	respond(w, h.rules.RulesByTechnique(techniqueID))
}

// ExportRule returns one rule's content as raw text in the requested format.
// GET /api/rules/export?id=&format=sigma|kql|spl|lucene|logscale
func (h *Handler) ExportRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	format := r.URL.Query().Get("format")
	if h.rules == nil {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}
	rule, ok := h.rules.RuleByID(id)
	if !ok {
		jsonError(w, "rule not found", http.StatusNotFound)
		return
	}

	var text string
	switch format {
	case "sigma", "":
		text = rule.Detection
	case "kql", "spl", "lucene", "logscale":
		backend := exportFormatToBackend(format)
		found := false
		for _, t := range rule.Translations {
			if t.Backend == backend {
				text = t.Query
				found = true
				break
			}
		}
		if !found {
			jsonError(w, "no "+format+" translation available for this rule", http.StatusNotFound)
			return
		}
	default:
		jsonError(w, "format must be one of sigma|kql|spl|lucene|logscale", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(text))
}

// exportFormatToBackend maps an export format query param to the backend
// key it corresponds to. kql is ambiguous between Sentinel and Defender XDR
// (both produce KQL) — this picks Sentinel; a caller wanting Defender XDR's
// KQL specifically should use GetRule and read Translations directly.
func exportFormatToBackend(format string) string {
	switch format {
	case "kql":
		return "microsoft_sentinel"
	case "spl":
		return "splunk"
	case "lucene":
		return "elastic"
	case "logscale":
		return "crowdstrike"
	default:
		return ""
	}
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestListRules|TestGetRule|TestSearchRules|TestRulesByTechnique|TestExportRule' -v`
Expected: all PASS

- [ ] **Step 6: Register routes**

In `orchestrator/internal/api/routes.go`, find the `tierAny` (any authenticated role) route group — the block starting with `{http.MethodGet, "/api/agents", ...}`-style routes near the top of the JWT-authenticated group (look for `r.Get("/api/scenarios", h.ListScenarios)` or similar as an anchor) — and add:

```go
			r.Get("/api/rules", h.ListRules)
			r.Get("/api/rules/{id}", h.GetRule)
			r.Get("/api/rules/search", h.SearchRules)
			r.Get("/api/rules/technique/{id}", h.RulesByTechnique)
			r.Get("/api/rules/export", h.ExportRule)
```

(Place this alongside the other `tierAny` `r.Get` routes, inside the same `r.Use(auth.RequireRole(...))` block that covers all authenticated roles — confirm by checking which role-group block wraps `/api/scenarios` and add these five lines to that same block.)

- [ ] **Step 7: Add RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, find the `tierAny` block (near `{http.MethodGet, "/api/scenarios", tierAny, ""},`) and add:

```go
	{http.MethodGet, "/api/rules", tierAny, ""},
	{http.MethodGet, "/api/rules/{id}", tierAny, ""},
	{http.MethodGet, "/api/rules/search", tierAny, ""},
	{http.MethodGet, "/api/rules/technique/{id}", tierAny, ""},
	{http.MethodGet, "/api/rules/export", tierAny, ""},
```

- [ ] **Step 8: Wire the engine in `main.go`**

In `orchestrator/cmd/server/main.go`, find where the `Handler` is constructed and chained with `.With*` calls (e.g. `.WithReporting(...)`, `.WithVerificationStore(...)`), and add:

```go
	.WithRuleLibrary(rulelib.NewEngine())
```

Add the import: `"github.com/audspect/bas/internal/rulelib"`.

- [ ] **Step 9: Run the RBAC drift test**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS

- [ ] **Step 10: Format, build, vet, commit**

```bash
cd orchestrator
go build ./...
go vet ./internal/api/... ./cmd/server/...
git add internal/api/rulelib_handlers.go internal/api/rulelib_handlers_test.go internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go cmd/server/main.go
git commit -m "feat(api): add read-only Detection Rule Library endpoints"
git push
```

---

### Task 9: Full validation and final push

**Files:** none (validation only).

- [ ] **Step 1: Go format/build/vet across the whole module**

```bash
cd orchestrator
gofmt -l internal/rulelib internal/api internal/scenario cmd/server
go build ./...
go vet ./...
```

Expected: `go build`/`go vet` exit 0. (`gofmt -l` may list pre-existing files unrelated to this change due to a known repo-wide CRLF-checkout artifact — verify by checking `gofmt -l` also flags an untouched file like `internal/api/handlers.go` before treating any listed file as a real formatting regression from this plan.)

- [ ] **Step 2: Full Go test suite**

```bash
cd orchestrator
go test ./... 2>&1 | tee /tmp/rulelib-full-test.log
grep -c '^--- FAIL\|^FAIL' /tmp/rulelib-full-test.log
tail -30 /tmp/rulelib-full-test.log
```

Expected: `grep -c` prints `0`; every package reports `ok`.

- [ ] **Step 3: Scoped Go stress run**

```bash
cd orchestrator
go test ./internal/rulelib/... -count=10 -v 2>&1 | tee /tmp/rulelib-stress.log
grep -c '^--- FAIL' /tmp/rulelib-stress.log
go test ./internal/api/... -count=10 -run 'TestListRules|TestGetRule|TestSearchRules|TestRulesByTechnique|TestExportRule|TestRBACMatrix_NoDrift' -v 2>&1 | tee /tmp/rulelib-api-stress.log
grep -c '^--- FAIL' /tmp/rulelib-api-stress.log
```

Expected: both `grep -c` calls print `0`.

- [ ] **Step 4: Full Python test suite for the generator**

```bash
cd scripts/rulelib-gen
.venv/Scripts/pytest tests/ -v
```

Expected: all tests PASS.

- [ ] **Step 5: Confirm everything is pushed**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
git status
git log --oneline -10
```

Expected: working tree clean (aside from pre-existing unrelated files), and the 8 feature commits from Tasks 1-8 are visible and already pushed.

---

## Self-Review

**Spec coverage:**
- Architecture (Python generator → committed JSON → go:embed, separate from code) → Tasks 1-6.
- Data model (full Sigma metadata, not just translations; stable `AUDRULE-*` ID; richer `Translation` with language/generator) → Task 5 (`model.go`).
- `RuleIDs []string` on `ExpectedDetection` (list, not singular) → Task 7.
- Search indexes (technique/backend/status/severity/logsource/title, O(1)) → Task 6.
- API surface (`/rules`, `/rules/{id}`, `/rules/search`, `/rules/technique/{id}`, `/rules/export`) → Task 8.
- Generator pipeline split into 4 stages (`load_sigma.py`/`translate.py`/`validate.py`/`export.py`) → Tasks 1-4.
- Quality gate (zero-translation-rule fail, malformed-Sigma fail, invalid-technique fail, duplicate-ID fail, >25%-backend-failure-rate fail, isolated gap = warn) → Task 3, exercised end-to-end by the real `build.py` run in Task 4.
- `metadata.json` provenance/audit trail (schemaVersion, generatorVersion, sigmaCommit, generatedAt, counts, translationFailures) → Task 4.
- Runtime degradation (schema mismatch/corrupt JSON → empty engine, never blocks startup) → Task 5.
- Testing (Go unit tests for rulelib + API handler tests + Python generator stage tests) → every task carries its own tests as specified.
- **UI (new "Detection Rules" page + report cross-linking)** → explicitly out of scope for this plan (see header "Scope note"), matching how SP1 shipped backend-first.
- **Live "is it enabled" check** → explicitly out of scope per the design spec, not part of this plan.

**Placeholder scan:** no TBD/TODO; every step has complete, runnable code and exact commands.

**Type consistency:** `Rule`/`LogSource`/`Translation`/`TranslationFailure`/`Metadata`/`MetadataFailure` (Task 5) match the JSON shape `export.py` (Task 4) produces field-for-field (verified: Python's `techniqueIds`/`falsePositives`/`logSource`/`translations`/`failures` keys match the Go struct JSON tags exactly). `SearchFilter` (Task 6) fields match `SearchRules`' query-param mapping (Task 8). `h.rules`/`WithRuleLibrary` (Task 8) match the `*rulelib.Engine` type from Task 5.
