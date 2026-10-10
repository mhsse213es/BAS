# AD Validation Lab — Operator Runbook (P5, M1 `dc-only`)

This runbook stands up, validates against, and tears down the controlled Active
Directory validation lab that backs `adlabrt`. It covers milestone **M1**: a
single self-contained Windows Server Domain Controller VM on Hyper-V.

Design: `docs/superpowers/specs/2026-10-10-p5-ad-lab-substrate-hyperv-design.md`.

Names here (`audspect-lab-private`, `dc01`, `dc01-base-clean`, `LAB\attacker`,
`AllExtendedRights@domain-root`) match the `internal/adlabhyperv` topology
catalog, so the real adapter lines up with no changes.

Conventions: **host-side** commands run in an elevated PowerShell on the Hyper-V
host; **VM-side** commands run inside `dc01` via `vmconnect`.

## 1. Scope & safety

- Runs on **dedicated Hyper-V hardware — never the development/build host**.
- **No cloud, no cloud spend.** M1 is local Hyper-V only.
- The lab is a **throwaway domain** (`lab.local`) with **no trust to any
  production/corporate directory**, destroyed and rebuilt from a clean base
  between runs.
- Nothing executes until isolation is verified (§4). An unverified or uncertain
  isolation result blocks the entire run — fail-closed by design.
- Lab secrets (DSRM/SafeMode password, `attacker`/`labuser` passwords) are
  **runtime-only: never logged, never committed** (readiness criterion §8.4).

## 2. Prerequisites

- A **dedicated** physical host with VT-x/AMD-V + SLAT enabled in firmware,
  ≥8 GB free RAM and ~60 GB free disk for M1.
- A **Windows Server ISO** (2019/2022) + valid license/eval.
- Resource profile (M1 minimum; confirm during first bring-up):

  | Topology | vCPU | RAM | Disk |
  |---|---|---|---|
  | M1 `dc-only` (DC `dc01`) | 2 | 4 GB | ~40 GB base + per-run checkpoint delta |

  Later milestones (not M1): **+client** ~2 vCPU / 4 GB / 40 GB; **+AD CS**
  ~0–2 vCPU / 2–4 GB / 10 GB.

### 2.1 Enable Hyper-V + the dedicated private switch (host-side)

```powershell
# Windows Server host:
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
# (Win10/11 Pro host instead: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All  → reboot)

# The isolated switch — type MUST be Private (no host/External routing):
New-VMSwitch -Name "audspect-lab-private" -SwitchType Private
Get-VMSwitch -Name "audspect-lab-private" | Select Name,SwitchType   # expect: Private
```

## 3. Stand up (M1 `dc-only`)

Topology key `LabSpec.Name = "dc-only"` — one VM `dc01` (role `dc`) on
`audspect-lab-private`, controlled attacker `LAB\attacker` granted
`AllExtendedRights` on the domain root.

### 3.1 Create the DC VM (host-side)

```powershell
$vhd = "D:\lab\dc01.vhdx"   # adjust
New-VM -Name dc01 -Generation 2 -MemoryStartupBytes 4GB -NewVHDPath $vhd -NewVHDSizeBytes 40GB -SwitchName "audspect-lab-private"
Set-VM -Name dc01 -ProcessorCount 2
Set-VMMemory -VMName dc01 -DynamicMemoryEnabled $false -StartupBytes 4GB   # DCs want static RAM
Add-VMDvdDrive -VMName dc01 -Path "D:\iso\WindowsServer.iso"               # adjust
Set-VMFirmware -VMName dc01 -FirstBootDevice (Get-VMDvdDrive -VMName dc01)
Start-VM -Name dc01
vmconnect localhost dc01    # install Windows Server at the console
```

Install Windows Server, set the local admin password, finish to login.

### 3.2 Promote to a throwaway DC (VM-side)

```powershell
# Static IP on the private NIC, NO default gateway, self as DNS:
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
Rename-Computer -NewName dc01 -Restart
# after reboot:
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "<DSRM-pw>" -AsPlainText -Force) -Force
# reboots into the DC
```

### 3.3 Controlled identities: attacker (positive) + labuser (negative control) (VM-side)

`LAB\attacker` gets exactly the two replication extended rights DCSync needs
(this is what the catalog's `AllExtendedRights@domain-root` refers to).
`LAB\labuser` gets **no** special rights — it is the mandatory negative control
(§5) that must come back `not_validated`.

```powershell
New-ADUser -Name attacker -SamAccountName attacker -Enabled $true `
  -AccountPassword (ConvertTo-SecureString "<attacker-pw>" -AsPlainText -Force)
New-ADUser -Name labuser  -SamAccountName labuser  -Enabled $true `
  -AccountPassword (ConvertTo-SecureString "<labuser-pw>" -AsPlainText -Force)

$dn = (Get-ADDomain).DistinguishedName
dsacls $dn /G "LAB\attacker:CA;Replicating Directory Changes"
dsacls $dn /G "LAB\attacker:CA;Replicating Directory Changes All"
dsacls $dn | Select-String "attacker"     # verify the grant landed
# labuser deliberately gets NO grant.
```

## 4. Verify isolation (fail-closed — all four required)

Every check must return a **determinate, passed** result. A failed,
indeterminate, **or missing** check means the lab is **NOT isolated** and the
run is blocked; no provenance is minted.

```powershell
# 1. private_switch  (HOST): only audspect-lab-private, and it is Private
Get-VMNetworkAdapter -VMName dc01 | Select SwitchName          # expect ONLY audspect-lab-private
(Get-VMSwitch "audspect-lab-private").SwitchType               # expect Private

# 2. no_external_route  (VM — ACTIVE probe; config inference is NOT sufficient)
Test-NetConnection 8.8.8.8 -InformationLevel Quiet             # expect False
Test-NetConnection <your-host-mgmt-IP> -InformationLevel Quiet # expect False
Resolve-DnsName microsoft.com                                  # expect failure

# 3. no_production_ad  (VM)
Get-ADTrust -Filter *                                          # expect EMPTY

# 4. distinct_identity (VM)
(Get-ADDomain).DomainSID                                       # lab's own SID, not any prod SID
```

- **`private_switch`** — every lab VM adapter is bound to `audspect-lab-private`
  (Private), with no additional adapters. Verified against the actual VM/adapter
  config, not the provisioning intent.
- **`no_external_route`** — the active probe confirms the DC cannot reach the
  host network/gateway, the internet, or any non-lab host.
- **`no_production_ad`** — `lab.local` has no trust path to any real directory.
- **`distinct_identity`** — lab credentials/SIDs are the lab's own.

## 5. Run a validation (positive + mandatory negative control)

A positive result is trustworthy only when the harness can also fail correctly,
so each capability is validated as a pair **in the same lab build**:

1. **Positive** — run the primitive as `LAB\attacker` (holding the right).
   Expected terminal state: `validated` (postcondition observed).
2. **Negative control** — run the **same** primitive as `LAB\labuser` (lacking
   the right). Expected terminal state: `not_validated` (postcondition NOT
   observed).
3. **Acceptance rule:** accept a `validated` result **only** when its paired
   negative control returned `not_validated` in the **same** build.

Other terminal states: `provision_failed` (lab never came up),
`isolation_unverified` (§4 failed — nothing ran), `gate_denied` (operator
authorization absent, or a destructive class without explicit approval),
`execution_errored` (the run itself errored), `evidence_inconclusive` (the
observation was incomplete — never a pass).

## 6. Evidence

M1 captures **lab-local evidence only** (run id, lab, target, case,
postcondition-observed, complete, timing). Shipping evidence to a SIEM/EDR and
asserting detection is **P6** and is out of scope here — a lab-local `validated`
means the action produced its postcondition, not that it was detected.

## 7. Teardown

```powershell
# HOST, after a clean shutdown:
Stop-VM -Name dc01
Checkpoint-VM -Name dc01 -SnapshotName "dc01-base-clean"   # first time: capture the clean base
Get-VMSnapshot -VMName dc01                                # confirm dc01-base-clean exists

# Between runs: revert to the clean base, then delete per-run checkpoints:
Restore-VMSnapshot -VMName dc01 -Name "dc01-base-clean" -Confirm:$false
```

- Teardown is **idempotent** and runs on **every** path — success, failure,
  cancellation, panic — so a run can never leak a provisioned lab.
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

Until all hold, only the lab-independent substrate code (the `adlabhyperv`
package, tested against a fake command seam) exists; no real provisioning,
probing, or DC execution is performed.

## 9. Later milestones (only when a scenario needs them)

- **M2 (+domain-joined client)** — add a Windows client VM on
  `audspect-lab-private`, join it to `lab.local`, install the Audspect agent;
  for agent-based scenarios.
- **M3 (+AD CS)** — add the AD CS role (on `dc01` for M3-minimal, or a dedicated
  CA VM) to validate ESC1–4/6/8 certificate scenarios.

## 10. DCSync control-efficacy (Phase 5 vertical)

The first real control-efficacy test (`internal/adefficacy`): does AD's **native
replication-rights control** prevent DCSync by an unauthorized principal? Design:
`docs/superpowers/specs/2026-10-10-p5-dcsync-efficacy-vertical-design.md`.

Run both principals **in the same lab build** (the §3.3 pair):

- **`LAB\labuser`** (negative control, no rights) → run DCSync → **expect `blocked`**.
- **`LAB\attacker`** (positive control, rights granted) → run DCSync → **expect `allowed`**.

Evidence hierarchy — **do not conflate these**:

- **Primary: the DRSUAPI replication result.** `access_denied` → `blocked`;
  `succeeded` (secrets returned) → `allowed`; no conclusive result →
  `indeterminate`. This alone determines the outcome.
- **Secondary: Security event 4662** (directory-object access) — **corroboration
  only**. A 4662 by itself never proves a block, and is never assumed to mean
  success or failure; interpret it alongside the DRSUAPI result.

Acceptance rules (enforced by `adefficacy`):

- Only a **correlated, conclusive** DRSUAPI result yields a determinate verdict
  (`high` confidence). Uncorrelated, `indeterminate`, or 4662-only evidence →
  **`SKIPPED`** — never a PASS, so no false protection claim is possible.
- The `labuser` denial (negative PASS) is **accepted as trustworthy only when the
  `attacker` run cleanly PASSed** in the same build (`Pair.AcceptedNegativeVerdict`);
  otherwise it is downgraded to `SKIPPED`.

Readiness (extends §8): a real `ControlDecisionSource` must read the DC's DRSUAPI
result (primary) + 4662 (corroboration), correlated to each run. **None ships** —
`adefficacy` is fake-backed and performs **no** `CapabilityStates()`/`dispatchRun`
wiring. The live DCSync run against the real DC is **lab-gated** and operator-run.
