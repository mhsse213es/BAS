# AD CS mastery scenario: QA log

Scenario: `scenarios/adcs-esc-template-exposure-audit.yaml` (generated; never edit by hand).
Source: `orchestrator/internal/adcsaudit/` (`lib.ps1`, `gen.go`) and `orchestrator/cmd/gen-adcs-scenario`.
Regenerate: `cd orchestrator && go run ./cmd/gen-adcs-scenario ../scenarios/adcs-esc-template-exposure-audit.yaml`, then re-sign with `scripts/signer.go`.

## What it is

18 read-only stages: 0 context, 1-15 one per ESC, 16 publication and trust, 17 correlation. Findings carry a state:
confirmed, path (exploitable issuance path), potential (needs live verification), insufficient (could not be read).
A stage PASSes only when every source it needs was read and nothing was found. Potential or insufficient evidence is
SKIP, never PASS. Every finding line is `low-privileged principal -> right -> object -> conditions -> impact`.
Nothing requests a certificate or changes a template, CA object, CA setting or registry value.

## Verified (offline)

- Analyzer logic: 60-plus fixture cases (`internal/adcsaudit/adcsaudit_test.go`), run through real PowerShell: each ESC
  vulnerable / mitigated / unreadable, deny ACEs, tier-0-only enrollment, manager approval, RA signature, unread sources.
- Correlation: published vs unpublished template, CA-level flag with and without a reachable template, clean, unread source.
- Off-domain host: every stage returns SKIP (never PASS) in about a second.
- Generation deterministic and matches the committed file; static check that no write or certificate-request command appears.
- Step-contract ledger regenerated; baseline gained only a zero-gap entry for the ESC8 probe file.

## NOT verified

- The collectors (LDAP template and PKI ACL reads, `certutil -getreg`, remote registry for CA security and DC mapping,
  altSecurityIdentities search, NTAuth certificate parsing, the ESC8 HTTP probe) have never run against a real AD CS
  environment. This build host is not domain joined. Needs a lab run before any maturity claim.
- Per-ESC limits stated by the scenario: CA enrollment-agent restrictions (ESC3), the CA patch level (ESC15), the DC
  2025 binding-update level (ESC10), HSM assurance (ESC12), HTTPS Extended Protection (ESC8) are not readable here.
- ESC8 is POTENTIAL unless `BAS_ADCS_LIVE_PROBE=true`, so stage 17 cannot PASS without the probe.
- Detection and telemetry text in each step is expectation, not confirmed against a SIEM.

## Open

- Separate `adcs-esc8-web-enrollment-probe.yaml` still exists; its overlap with stage 8 is undecided.
- Not deployed; the console has not been checked against the new step list.
