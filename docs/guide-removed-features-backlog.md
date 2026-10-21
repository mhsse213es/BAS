# Removed-from-guides backlog

Features and claims removed from the customer guides because the code does not support
them. Each entry is a candidate for a separately scoped build. None is planned for a
specific release.

| # | Item | What the guides said | What the code has | Needed to build |
|---|---|---|---|---|
| 1 | Lab Mode | Execution mode enabling payload-bearing steps; required `lab_mode: true` in YAML and enrollment config | No `lab_mode` gate. Only a `fidelity: lab-only` label on Caldera steps | Decide whether a gate is wanted; if so, enforce it at dispatch and in the agent |
| 2 | CEF export | Simulation logs exportable as Common Event Format for SIEM | No CEF output | Format spec, export endpoint, tests |
| 3 | Deferred posture execution | `deferred`, `defer_until`, `defer_window_minutes` on posture steps | No defer handling in orchestrator, agent or dashboard | Scheduler and agent changes, and a spec for restarts inside the window |
| 4 | Business Unit Score | Average Prevention Score per business-unit label | Not implemented | Label model, score definition, dashboard view |
| 5 | Report footer email | Reports for named users carry the requester's email in each page footer | No such footer | Decide whether PII in footers is wanted; then build |
| 6 | Automatic Attack Path Findings | Collections create findings (open, in progress, validated, resolved) | No automatic creation. Finding statuses are open, resolved, closed, accepted | Creation rules, dedupe by category, status model |
| 7 | MITRE ATT&CK v14 compliance report | Framework with generated report | No ATT&CK mapper. Techniques are tagged on scenarios only | A real mapping file and report support |
| 8 | CIS Benchmarks v8 compliance report | Framework with generated report | No CIS mapping. The CIS Ubuntu L1 scenario exists, but no report | A real mapping file and report support |
| 9 | NIST SP 800-53 Rev 5 | Listed as a framework | No mapping shipped (NIST CSF 2.0 is shipped) | A real mapping file and report support |
| 10 | Architecture message types and tables | `MsgRunDispatched`, `MsgRunStepResult`; tables `run_steps`, `run_reports`, `campaign_runs`, `exercises`, `attackpath_results`, `attackpath_assets`, `art_atomics`, `schema_migrations` | None exist in the code | Confirm intended storage design first; the guide will be rewritten from the real schema |
| 11 | Lab-mode scenario gate in scenarios guide | `lab` execution mode row and `lab-only` described as a gate | `lab-only` is a fidelity label only | Covered by item 1 |
| 12 | Reverse-proxy agent path on 443 | Agents could reach the server on 443 through a TLS proxy | Agents use mTLS on 9443 directly; the proxy example covers the dashboard only | Only if a verified proxied agent configuration is wanted |
| 13 | Setup wizard on port 9001 | Web-based setup wizard | None in this release; install is CLI only | Not planned; remove from history docs if no longer relevant |

Known issue, separate from this list: the admin password is re-applied from
`BAS_ADMIN_PASSWORD` on every start and a built-in default is used when unset. The fix is
a code change (see the admin-password commit), not a feature build.
