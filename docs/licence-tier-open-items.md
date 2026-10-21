# Licence tier: open items

This records what the Core / Advanced / Enterprise tier change does **not** yet cover, so it is not
mistaken for complete. The design is in the conversation that introduced it; the code is in
`orchestrator/internal/license/tier.go`, `orchestrator/internal/scenario/engine.go` (`SetLicence`,
`Get`, `List`) and `orchestrator/internal/api/product_gate.go`.

## Enforced now

- **Scenario lookup and listing.** `Engine.Get` and `Engine.List` refuse any scenario whose
  `product_line` the verified licence does not permit. The server sets the gate once at startup
  (`cmd/server/main.go`, `engine.SetLicence(license.PermitsNow)`).
- **Product API routes.** `ProductGate` (`internal/api/product_gate.go`) answers 403
  `product_not_licensed` to requests under a product-specific prefix that the licence does not
  include. It applies to reads and writes. The prefix map is listed in that file.
- **Locked licence.** A locked licence permits no product line.
- **Dev build.** A build without a licence file is seeded as Enterprise, so it keeps every product.

## Not yet decided: prefixes left open at the route layer

These API prefixes are not mapped to a product, so `ProductGate` does not refuse them. Scenario
execution through them is still limited by the engine gate, where the scenario is resolved through
the engine. Each needs a product decision before it is mapped:

`ad`, `adversary-templates`, `analytics`, `art`, `attack`, `attackpath`, `audit-logs`,
`backup-assurance`, `backups`, `campaigns`, `compliance`, `content`, `content-registry`,
`controlhealth`, `correlation`, `coverage`, `crypto`, `dashboard`, `detectverify`, `dns-security-checks`,
`em`, `evidence`, `exercises`, `execution-policy`, `exposure`, `findings`, `intel`, `intelligence`,
`iocs`, `isolation-checks`, `job-schedules`, `jobs`, `knowledge-graph`, `notifications`, `openaev`,
`ot-safety-imports`, `panos-exposure`, `payload-families`, `pipeline-approvals`, `posture`,
`predict`, `recommend`, `regulatory-*`, `relationship-*`, `relationships`, `remediation-*`,
`remote-access-*`, `report`, `reports`, `rules`, `scan`, `scheduled-assessments`, `scim`, `search`,
`siem`, `sla`, `sso`, `tamper-events`, `target-scope-imports`, `taxii`, `technique-verification-runs`,
`techniques`, `tenants`, `threat-intel`, `threat-priority`, `threatintel`, `threats`, `ti`,
`ticketing`, `transport-security-checks`, `variants`, `verifications`, `vex`, `zone-isolation-imports`.

Several of these run scenarios (for example `exercises`, `campaigns`, `scheduled-assessments`,
`payload-families`, `technique-verification-runs`, `verifications`). Their execution must be confirmed
to resolve scenarios through `Engine.Get` before this list is closed.

## Not yet verified

- **Background jobs.** Scheduled and recovery paths (for example `RecoverEmailGWRuns`, scheduled
  assessment dispatch, revalidation) have not been checked against the engine gate.
- **WebSocket actions.** `/ws/browser` and `/ws/agent` have not been checked for scenario-execution
  messages.
- **Report and evidence access.** Reports and evidence for an unlicensed product are not yet refused.
- **Direct engine bypass.** `Engine.DeleteAs` reads the scenario map directly. It deletes only custom
  files and runs nothing, so it is not an execution path, but it is not gated.

## Not built

- **Product code is still in the binary.** Tiers control what is licensed to run. They do not remove
  unlicensed product code. A customer with access to the binary can read it.
- **Console grouping and licence line.** The Scenario section is not yet grouped by product line, and
  the Licence section does not yet show the tier.
- **Package filtering.** `windows-build.ps1 -LicenseType` is not yet implemented.
