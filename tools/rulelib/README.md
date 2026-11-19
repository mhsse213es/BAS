# Detection rule library: dev-time tools

Everything here runs on a **build machine with network access**. Nothing in this folder ships to a customer, and a
customer's isolated server downloads nothing: the generated rules are committed under
`orchestrator/internal/rulelib/ruledata/` and embedded in the orchestrator binary.

| File | Purpose |
|---|---|
| `SIGMA_COMMIT` | The exact SigmaHQ commit the library is generated from (reproducible builds). |
| `fetch_sigma.sh` | Fetches that commit into `sigma/` (git-ignored, about 70 MB). |
| `coverage.py` | Measures how many SigmaHQ rules exist for the ATT&CK techniques Audspect's scenarios run. |
| `translation_stats.py` | Measures how many of those rules convert to each of the five SIEM languages. |

Python environment (use the pins; `pyparsing` 3.3 breaks pySigma 1.4.0):

    python -m venv .venv && .venv/bin/pip install -r scripts/rulelib-gen/requirements.txt
    sh tools/rulelib/fetch_sigma.sh
    .venv/bin/python tools/rulelib/coverage.py --md docs/detection-rules-coverage.md
    .venv/bin/python tools/rulelib/translation_stats.py

Rules are licensed under the Detection Rule License (DRL) 1.1; exports must carry the attribution (see the report).
