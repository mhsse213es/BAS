# QRadar translations: a separate environment

The pySigma QRadar backend (`pysigma-backend-qradar`, latest 0.3.3) requires `pySigma < 0.10`. The other five
backends need pySigma 1.4.0, and the two cannot be installed together. So QRadar queries are produced by
`convert_qradar.py` in a **second virtual environment**, and `build.py` talks to it through a small JSON protocol
(`../external_backend.py`). This is a dev-time generator step only; nothing here ships or runs on a customer server.

## Set up (once)

```
python -m venv .venv-qradar
.venv-qradar/Scripts/pip install -r scripts/rulelib-gen/qradar/requirements-qradar.txt
```

## Generate the library with QRadar

```
python scripts/rulelib-gen/build.py \
  --sigma-dir tools/rulelib/sigma/rules --sigma-root tools/rulelib/sigma \
  --qradar-python .venv-qradar/Scripts/python.exe
```

A full run must either pass `--qradar-python` or say `--no-qradar` explicitly, so a library is never silently
missing QRadar. If the second environment crashes, the build stops.

## What the output is, and is not

- **Always generic.** Queries are AQL (`SELECT UTF8(payload) ... FROM events WHERE ...`) using Sigma's own field
  names as custom event properties (for example `"Image"`, `"Process CommandLine"`). The package's bundled Windows
  pipelines were measured: they convert 77 of 845 Windows process-creation rules and two of them crash, so no QRadar
  query is claimed to be field-mapped. The customer must have matching custom event properties, or adapt the query.
- **Not run against a QRadar.** Nobody has executed these queries on a real QRadar. AQL escaping of backslashes in
  the generated patterns, in particular, is unverified.
- **Some rules cannot be expressed.** The backend only supports a fixed set of fields for each log source; a rule
  that uses another field is recorded as "backend translation unavailable" with the backend's reason (351 of 2,104
  rules at SigmaHQ r2026-04-01).
- **Different pySigma version.** The generator string on each QRadar translation records the pySigma and backend
  versions used (pySigma 0.9.11), because rule parsing differs slightly from the other backends.
