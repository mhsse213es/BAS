# E1 — AD Gap Capability Inventory (baseline / closure record)

**Date:** 2026-10-09
**Status:** E1 CLOSED. This is the evidence baseline for the 11 AD coverage gaps.
**Scope:** content-level reusable-vs-missing inventory only. No executable content
was authored. Execution/validation of any item is gated on controlled-lab
infrastructure (see "Lab dependencies").

## Method & sources

Resolved from the **stock public sources the build itself consumes** — no running
BAS stack was required:

- **ART atomics:** the orchestrator `Dockerfile` (`art-fetcher` stage) sparse-clones
  the **unmodified** public `redcanaryco/atomic-red-team` repo (`atomics/T*/T*.yaml`)
  and seeds every technique into `art_atomic_tests` at startup. So ART coverage ==
  upstream ART content.
- **Caldera:** `bas-caldera` = stock MITRE Caldera + the CTID
  `center-for-threat-informed-defense/adversary_emulation_library` (`emu` plugin) +
  the `atomic` plugin (which re-loads the same ART atomics) + the default `stockpile`.

Each verdict below is from reading **actual atomic/ability content**, not filenames
or ATT&CK technique IDs.

### Source coverage & confidence

| Source | How inspected | Confidence |
|---|---|---|
| ART technique YAMLs (`T1003.006`, `T1649`, `T1098`, `T1098.007`) | read the YAML content directly | **High** |
| CTID emu library (11 adversary plans + 12 micro-plans incl. `ad_enum`) | directory/catalog listing + targeted search for ADCS/cert | **High** for absence of an ADCS/cert plan |
| Caldera `stockpile` abilities | targeted web search (not an exhaustive per-ability read) | **Medium** |

**Honesty caveat:** "Missing" = *not found in the inspected content*, not
mathematically proven absent from every one of Caldera's ~3,500–5,000 loaded
ability YAMLs. A definitive negative for the ACL/RBCD rows would require a `grep`
over a running `bas-caldera` container's loaded abilities (which reintroduces the
build/deploy dependency). For ADCS ESC the negative is strong: that tradecraft
lives in dedicated tooling (Certipy/Certify), absent from all inspected catalogs.

## The inventory (11 primitives)

| Primitive | State | Evidence | Confidence |
|---|---|---|---|
| `dcsync` (T1003.006) | **Reusable** | ART `T1003.006.yaml`: 2 real DCSync atomics — Mimikatz `lsadump::dcsync` + DSInternals `Get-ADReplAccount` (Windows). Caldera inherits via `atomic`. | High |
| `adcs-esc1` (T1649) | **Missing** | ART `T1649.yaml` is cert-*theft* only (Export-Certificate), not template/enrollment abuse. No ADCS plan in emu; none in stockpile. | High |
| `adcs-esc2` (T1649) | **Missing** | same | High |
| `adcs-esc3` (T1649) | **Missing** | same | High |
| `adcs-esc4` (T1649) | **Missing** | same | High |
| `acl-forcechangepassword-abuse` | **Missing** | ART `T1098` has only *self*-password-change (`Set-ADAccountPassword` on own account); no ACL-driven reset of another user. | Med–High |
| `acl-genericall-takeover` | **Missing** | No DACL/ACL-modification or object-takeover atomic in ART `T1098`; none found in emu/stockpile. | Med–High |
| `acl-addmember-privileged-group` | **Partial** | ART `T1098` "Domain Account and Group Manipulate" runs `Add-ADGroupMember <group>` (default Domain Admins) — outcome matches, but it presumes rights; the `AddMember` ACL right is not modeled as prerequisite. | High (for ART); Med (Caldera completeness) |
| `acl-addself-privileged-group` | **Partial** | same group-add overlaps the outcome; the `AddSelf` extended-right ACL angle is not modeled. | High / Med |
| `rbcd-configure` | **Missing** | No atomic writes `msDS-AllowedToActOnBehalfOfOtherIdentity` in ART/emu/stockpile (inspected). | Med–High |
| `rbcd-impersonate` | **Missing** | No S4U2Self/S4U2Proxy impersonation atomic in ART/emu/stockpile (inspected). | Med–High |

**Summary:** 1 reusable · 2 partial · 8 missing.

## Lab dependencies (why "reusable ≠ runnable")

Every item — including the reusable DCSync — needs a **live, controlled AD
environment** to execute or validate, which does not exist yet:

- `dcsync`, `rbcd-*` → a **Domain Controller** (replication / S4U).
- `adcs-esc1..4` → a **Certificate Authority** + a vulnerable template per ESC.
- `acl-*` → a **writable domain** with the specific ACE pre-seeded.
- `rbcd-configure` additionally → MachineAccountQuota + a writable target.

So the inventory establishes *what to author*, not *what we can run*; the
controlled-lab path is the universal gate (tracked as the E2/D-runtime dependency).

## Decisions carried forward

- **Do not re-author DCSync** — reusable.
- **Partial items** (`AddMember`/`AddSelf`) are adaptation candidates, not
  author-from-scratch.
- **E2 authoring targets the 8 missing items**, each highest safety-interrupt
  class, each its own go/no-go, all lab-gated. Authoring is **held** until a
  controlled execution+validation path exists.
- **D-runtime stays deferred** until runnable content + a provenance-bearing
  controlled execution target exist and can be bypass-tested.

## Reproduction (if the stock sources change)

- ART: check `github.com/redcanaryco/atomic-red-team` → `atomics/<TID>/<TID>.yaml`.
- Caldera emu: `github.com/center-for-threat-informed-defense/adversary_emulation_library`.
- Definitive live check: `grep` loaded abilities on a running `bas-caldera` container
  (needs the stack up).
