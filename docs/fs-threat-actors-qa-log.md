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

## Status of the three closure decisions

1. **Live Windows validation — OUTSTANDING (see runbook below).** Syntax + load
   are verified; execution and detection validation are NOT done. Not treated
   as operational validation.
2. **Eval score — LEFT AT 3/5.** The assessor independently evaluates POC-28/29
   before any re-score. Implementation completion is not evidence of
   effectiveness.
3. **Threat-intel grounding — DEFERRED, TRACKED (see follow-up below).**
   Narrative citations are used this iteration; their sources are traceable
   (listed below). Structured fields are a tracked follow-up.

## Staging live-validation runbook (REQ-019 decision #1 — OUTSTANDING)

Scenarios are **bind-mounted**, not baked into the image
(`packaging/compose/docker-compose.yml`: `- ./scenarios:/scenarios`,
`SCENARIOS_DIR=/scenarios`), and `packaging/build.sh` copies `scenarios/` into
the bundle after a `verify-all` signature gate (which these 5 `.sig` pass). So
reaching staging is the normal release path — not a code rebuild of content:

1. **Merge** PR #19 to `main`.
2. **Build the bundle** (heavy job, build host): `bash packaging/build.sh` — it
   runs `signer.go verify-all` over `scenarios/` and copies them in. Fails
   closed on any bad/missing signature.
3. **Deploy** on staging (`ssh audspect-staging`, i.e. zain@192.168.10.78):
   `sudo bash install.sh --upgrade --config setup.conf` — never `--install`
   over existing data, never raw docker compose.
4. **Confirm load** (human API, :9543, JWT as admin@k.com): the 5 ids —
   `carbanak-kill-chain`, `cobalt-group-kill-chain`, `silence-kill-chain`,
   `ta505-kill-chain`, `fin8-kill-chain` — appear in `GET /api/scenarios`
   (Enterprise/killchain tier). Scenario-signature verification runs at load;
   a tampered/CRLF file would be refused.
5. **Run against a live Windows agent** (one enrolled on :9443 mTLS): launch
   each via `POST /api/scenarios/{id}/run` (or the Runs UI), live mode.
6. **Capture execution telemetry + detection results** per stage and compare to
   the `telemetry:`/`detection:` blocks each scenario documents — e.g. Sysmon
   EID 1/3/7/11/13/17/22, Security EID 4688/4698/7045, PowerShell EID 4104,
   WMI-Activity EID 5857. Record the step PASS/FAIL posture and whether the
   SOC/EDR actually alerted. Submit detections via
   `POST /api/scenarios/runs/{runId}/detections`.

Only after step 6 is this "operationally validated". I can drive steps 4–6 via
the :9543 API once the user has completed the merge + build + deploy (steps
1–3, their heavy-job role), if they want me to.

## Tracked follow-up — structured threat-intel grounding (decision #3)

Deferred this iteration; tracked for a later pass. Add per-step
`threat_intel_sources` + `family_attribution_confidence` (+ `last_reviewed`) to
all 25 steps, matching the newer ransomware chains (black-basta/medusa/rhysida),
for auditability and consistency. The structural gate
(`contentregistry.stepProvenanceProblems`) requires: every source has a
`reference`; `confirmed` needs >=2 sources; non-`unsourced` needs >=1. Confidence
must be graded honestly per step, not blanket-`confirmed`.

**Narrative sources used this iteration (traceable):**
- Carbanak — Kaspersky "Carbanak APT" (2015); Group-IB *Anunak*; MITRE ATT&CK G0008.
- Cobalt Group — Group-IB "Cobalt" reports; Europol 2018 arrest; MITRE ATT&CK G0080.
- Silence — Group-IB "Silence: Moving into the darkside"; MITRE ATT&CK G0091.
- TA505 — Proofpoint / IBM X-Force TA505 reporting; MITRE ATT&CK G0092.
- FIN8 — Bitdefender/Symantec BADHATCH & Sardonic analyses; MITRE ATT&CK G0061.
