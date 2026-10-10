# AD Validation Lab — Operator Runbook (P5, M1 `dc-only`)

This runbook stands up, validates against, and tears down the controlled Active
Directory validation lab that backs `adlabrt`. It covers milestone **M1**: a
single self-contained Windows Server Domain Controller VM on Hyper-V.

Design: `docs/superpowers/specs/2026-10-10-p5-ad-lab-substrate-hyperv-design.md`.

## 1. Scope & safety

- The lab runs on **dedicated Hyper-V hardware — never the development/build
  host** (which lacks the resources and must stay unentangled).
- **No cloud, no cloud spend.** M1 is local Hyper-V only.
- The lab is a **throwaway domain** with **no trust relationship to any
  production or corporate directory**. It is destroyed and rebuilt from a clean
  base between runs.
- Nothing executes until isolation is verified (§4). An unverified or uncertain
  isolation result blocks the entire run — this is fail-closed by design.

## 2. Prerequisites

- A dedicated host with Hyper-V enabled and enough headroom for a pooled clean
  base checkpoint **plus** one live run.
- A dedicated **private** virtual switch named **`audspect-lab-private`**
  (Hyper-V switch type *Private* — not *External*, not *Internal*). No lab VM
  may have any other network adapter.
- A prepared, **offline, sysprepped** Windows Server base checkpoint named
  **`dc01-base-clean`**, already promoted to a Domain Controller for the lab's
  throwaway domain, licensed appropriately.
- Resource profile (M1 minimum; confirm during first bring-up):

  | Topology | vCPU | RAM | Disk |
  |---|---|---|---|
  | M1 `dc-only` (DC `dc01`) | 2 | 4 GB | ~40 GB base + per-run checkpoint delta |

  Later milestones (not M1): **+client** adds ~2 vCPU / 4 GB / 40 GB; **+AD CS**
  adds ~0–2 vCPU / 2–4 GB / 10 GB.

## 3. Stand up (M1 `dc-only`)

- Topology key: **`LabSpec.Name = "dc-only"`** — one VM `dc01` (role `dc`),
  cloned/reverted from `dc01-base-clean`, attached only to `audspect-lab-private`.
- Controlled attacker identity: **`LAB\attacker`**, granted exactly
  **`AllExtendedRights` on the domain root** (the right the DCSync primitive's
  prerequisites describe). This identity is the lab's own — never a production
  principal.
- Provisioning is driven through the substrate; it brings up the VM on the
  private switch and waits for the DC to reach a ready directory state within a
  bounded timeout.

## 4. Verify isolation (fail-closed — all four required)

Before anything runs, every one of these must return a **determinate, passed**
result. A failed, indeterminate, **or missing** check means the lab is **NOT
isolated** and the run is blocked; no provenance is minted.

1. **`private_switch`** — every lab VM network adapter is bound to
   `audspect-lab-private` (Private), with no additional adapters. Verified by
   querying the actual VM/adapter configuration, not by trusting the
   provisioning intent.
2. **`no_external_route`** — an **active** probe confirms the DC cannot reach
   (a) the host management network/gateway, (b) the internet, or (c) any non-lab
   host. A reachable result fails the check. A config-only inference is **not**
   sufficient; the probe must actually run.
3. **`no_production_ad`** — the lab DC's domain is the throwaway lab domain and
   has no trust path to any real/production directory.
4. **`distinct_identity`** — lab credentials/SIDs are the lab's own, never the
   host's or any production principal's.

## 5. Run a validation (positive + mandatory negative control)

A positive result is only trustworthy when the harness can also fail correctly,
so **each capability is validated as a pair in the same lab build**:

1. **Positive case** — run the primitive as `LAB\attacker` (holding the required
   right). Expected terminal state: `validated` (postcondition observed).
2. **Negative control** — run the **same** primitive as an identity **lacking**
   the required right. Expected terminal state: `not_validated` (postcondition
   NOT observed).
3. **Acceptance rule:** accept a `validated` result **only** when its paired
   negative control returned `not_validated` in the **same** lab build. A
   positive without a correct negative control is not accepted.

Other terminal states and their meaning: `provision_failed` (lab never came up),
`isolation_unverified` (§4 failed — nothing ran), `gate_denied` (operator
authorization absent, or a destructive class without explicit approval),
`execution_errored` (the run itself errored), `evidence_inconclusive` (the
observation was incomplete — never treated as a pass).

## 6. Evidence

M1 captures **lab-local evidence only**: run id, lab, target, case,
postcondition-observed, complete, and timing. **Shipping this evidence to a
SIEM/EDR and asserting detection is P6** and is out of scope here — a lab-local
`validated` means the action produced its postcondition, not that it was
detected.

## 7. Teardown

- Revert `dc01` to `dc01-base-clean` and delete the per-run VM/checkpoints.
- Teardown is **idempotent** and runs on **every** path — success, failure,
  cancellation, or panic — so a run can never leak a provisioned lab.
- Confirm no lab VM remains running and no per-run artifacts remain attached.

## 8. Readiness checklist (gate before building/running the real adapter)

The real Hyper-V execution is implemented/run only when **all** hold:

1. Dedicated Hyper-V host available and operator-authorized for this use.
2. Prepared offline sysprepped Windows Server base checkpoint (`dc01-base-clean`,
   DC-promoted for M1), licensed.
3. The §4 isolation checks are automatable on that host — especially the §4.2
   **active** no-external-route probe.
4. Secret handling confirmed: lab credentials are runtime-only, never logged,
   never committed.
5. Operator authorization (`adgate.Authorization{Authorized, DestructiveApproved}`)
   is bound to *this* run and *this* target, not an ambient flag.
6. The real `Commander` returns a **run-unique** target handle and makes
   provisioning **atomic**: if it partially creates a switch/VM and then fails,
   it cleans up its own partial state before returning the error. (`adlabrt`
   only guarantees teardown once provisioning has *succeeded*, so partial-failure
   cleanup is the Commander's responsibility — the fake-backed slice cannot
   defend it.)

Until all five hold, only the lab-independent substrate code (the `adlabhyperv`
package, tested against a fake command seam) exists; no real provisioning,
probing, or DC execution is performed.
