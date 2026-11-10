# FS Threat-Actor Library — QA Log (REQ-019)

**Requirement:** REQ-019 (Must) — *FS threat-actor library*, scored **3/5** in
`Assessment/BAS_Evaluation_Detailed_Report.md`. The gap: FIN7, Lazarus/APT38
(SWIFT), APT36 and Scattered Spider were present, but **Carbanak, Cobalt Group,
Silence, TA505 and FIN8 were missing/partial** — all bank-targeting actors the
BFSI workbook lists and tests directly (Section B + POC-28/29). This work adds
the five missing kill chains to complete the library.

**Branch:** `req019-fs-threat-actors`  ·  **Date:** 2026-11-10

## What was added

Five telemetry-safe, Windows-only, five-stage named-actor kill chains in
`scenarios/`, each signed (`.sig`) and following the established FS-actor
pattern (`fin7-kill-chain.yaml`): `product_line: killchain`, narrative
description with real source citations, `[BAS-SIM-<ACTOR>]` output markers,
`production_safe: true` + `reversible: true` on every step, and PASS/FAIL
posture findings with per-step telemetry + detection guidance.

| Scenario file | Actor (ATT&CK group) | Stage ATT&CK sequence |
|---|---|---|
| `carbanak-kill-chain.yaml` | Carbanak / Anunak (G0008) | T1033 → T1056.001 → T1125 → T1074.001 → T1071.001 |
| `cobalt-group-kill-chain.yaml` | Cobalt Group (G0080) | T1518.001 → T1087.002 → T1059.001 → T1021.002 → T1071.004 |
| `silence-kill-chain.yaml` | Silence / Whisper Spider (G0091) | T1087.001 → T1016 → T1115 → T1047 → T1105 |
| `ta505-kill-chain.yaml` | TA505 (G0092) | T1518 → T1547.001 → T1059.001 → T1053.005 → T1071.001 |
| `fin8-kill-chain.yaml` | FIN8 / Syssphinx (G0061) | T1047 → T1518.001 → T1140 → T1543.003 → T1071.001 |

Technique mixes were deliberately differentiated per actor (and from the
existing FIN7 chain) to reflect each group's documented tradecraft — e.g.
Carbanak operator video/keystroke surveillance, Cobalt Strike SMB named-pipe
and DNS beacons, Silence clipboard/WMI recon and ATM-tooling ingress, TA505
Run-key + scheduled-task persistence and encoded loader, FIN8 WMI
living-off-the-land + service-installed backdoor surface.

## Safety review (telemetry-safe / production-safe)

- **No real attack effect.** C2 beacons use RFC 5737 (192.0.2.x, non-routable);
  DNS beacon uses a reserved `.invalid` NXDOMAIN name (RFC 2606). No keyboard
  hook, no screen/video frame, no clipboard content read (length/type only), no
  download, no WMI/service method invoked.
- **The two state-changing steps are reversible with hard cleanup.** TA505 S2
  (HKCU Run value) and S4 (user scheduled task) write a single clearly-tagged
  `BAS-SIM-TA505` entry and remove it both in the command body *and* the
  `cleanup:` block. HKCU/user-context only — no HKLM, no SYSTEM task.
- **ASCII-only commands.** All command blocks are ASCII; an initial draft used
  em-dashes (U+2014) which Windows PowerShell 5.1, reading a file as CP1252,
  turns into a smart-quote (0x94 → U+201D) that breaks string parsing. Replaced
  with `--` to match the fin7 convention. (See verification below.)

## Verification performed

| Check | Command | Result |
|---|---|---|
| Parse + windows-only + exact technique sequence + safety flags + BAS-SIM markers | `go test ./internal/scenario/ -run TestFSThreatActorKillChains` | PASS (5/5) |
| PowerShell syntax of all 25 command blocks (AST parse, no execution) | `[Parser]::ParseFile` over dumped blocks | 0 errors / 25 |
| Loads through the production engine with a licensed product line | `TestBuiltinScenarios_AllHaveValidProductLine` (count 122→127) | PASS |
| Licence gating (killchain = Enterprise, hidden from Core) | `TestLicenceGate_CoreRefusesKillChain`, `TestRequireLicensed_*` | PASS |
| Signature verification against the compiled-in key (prod enforcement) | `go run scripts/signer.go verify-all ../scenarios` | `ok=156 fail=0` |
| Build | `go build ./...` | clean |
| `internal/contentregistry` structural check unaffected | `go test ./internal/contentregistry/` | PASS |

## NOT done / honest gaps

- **Not run against a real Windows agent.** Syntax and load are verified; live
  execution + telemetry/detection observation on staging is deferred to the
  user (consistent with other kill-chain deliverables). The PASS/FAIL posture
  logic is reviewed but not exercised end-to-end on a live endpoint.
- **Eval score not self-bumped.** REQ-019 is left at its current 3/5 in the
  assessment report. Moving it to 5 is the assessor's call after testing the
  content via POC-28/29 — not a self-assigned score (scoring-honesty).
- **No per-step threat-intel provenance fields.** These follow the fin7 FS-actor
  style (narrative citations only), matching their library siblings, rather than
  the newer per-step `threat_intel_sources`/`family_attribution_confidence`
  grounding used by the recent ransomware chains (black-basta/medusa/rhysida).
  Adding structured grounding is an available follow-up quality pass.
- **Not rebuilt/deployed.** Needs the normal `install.sh --upgrade`; the signed
  YAMLs ship in the scenario corpus.
