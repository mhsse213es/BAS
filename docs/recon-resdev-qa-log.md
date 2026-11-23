# Reconnaissance and resource development: QA log

Scenarios: `recon-code-repo-footprint-sim` (T1593.003), `recon-dns-enumeration-sim` (T1596.001),
`resdev-lookalike-domain-sim` (T1583.001), `resdev-codesign-cert-sim` (T1588.003).
All four are local or `.invalid`-only. None registers a domain, contacts a registrar, or touches a real host.

## Automated checks

| Check | Result |
|---|---|
| Scenario signatures (`verify-all`) | 294 of 294 pass, on the merged tree |
| Step-contract ratchet | New steps have zero cleanup, detection and telemetry gaps |
| Scenario suite (`go test ./internal/scenario/`) | Pass, 404.8 s, exit 0 |

## Lab run (Windows lab host, `feat/resdev-cert-draft`, run through `scripts/run-carbanak-steps.ps1`)

The runner gives raw evidence only, so these are not scored verdicts.

| Step | Output | Expected |
|---|---|---|
| T1593.003 code-repository footprint | 2 internal-looking identifiers in the fixture | The 2 planted `.invalid` and `.lab` names |
| T1596.001 DNS enumeration | 8 names queried, 8 did not resolve | All names are `.invalid`, so none resolves |
| T1583.001 lookalike domains | 7 candidates written locally, none registered | Local file only |
| T1588.003 code-signing certificate | Self-signed certificate created in CurrentUser store | Removed by cleanup |

## Cleanup (done by hand: the runner does not execute `cleanup:` blocks)

- Code-signing certificate `CN=Examplebank Synthetic Publisher` removed from `Cert:\CurrentUser\My`.
- `%TEMP%\bas_resdev_cert_thumb.txt` and `%TEMP%\bas_resdev_candidates.txt` removed.
- `%TEMP%\bas_recon_repo_fixture` removed.

## Open items

- The runner does not run `cleanup:` blocks. Cleanup for these steps was manual, so the runner needs a cleanup pass before these steps are used in a repeated run.
- The DNS step sends queries through the lab resolver, so resolver logs should be checked against the step's telemetry note. This has not been done.
- Telemetry and EDR detection were not checked against the detection notes in any of the four scenarios.
- The orchestrator's combined verdict was not run for these steps.
