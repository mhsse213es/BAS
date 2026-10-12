# Linux Ransomware Adapter (first vertical of sub-project #9) — Design

Sub-project #9 of the ransomware-mastery master roadmap: "Cross-platform
adapters (Linux, ESXi, storage)". This pass scopes the first of six platform
surfaces the roadmap's narrative (ransomware.txt §6) bundles together —
Linux file-server/backup protection — and explicitly defers ESXi/vSphere, VM
storage/datastores, NAS, cloud object storage, and hypervisor/storage
identities to later passes.

## A. Problem statement

All 8 existing ransomware scenarios are `supported_os: [windows]`. `rwevidence`
models exactly 4 techniques (T1490, T1486, T1567.002, T1560.001) via a
platform-blind `classifyRansomwareStep` dispatcher that nonetheless hardcodes
Windows-specific step names and skip-text (`"VSS Snapshot Enumeration"`,
`"no c: vss shadow copies exist"`). MITRE's own definitions of T1490 (Inhibit
System Recovery) and T1486 (Data Encrypted for Impact) already explicitly
cover Linux procedures — LVM/Btrfs/ZFS snapshot deletion for T1490, generic
file encryption for T1486 — so this is the **same two techniques** `rwevidence`
already evaluates, not new ones. The roadmap's own deliverable language
("platform adapters that reuse the same evidence model") confirms this: no
new `Capability`, no new `TechniqueID`, no `Platform` field anywhere.

`backupassurance`'s 6 observer interfaces (`DeletionProtectionObserver`,
`ImmutabilityObserver`, etc.) have zero platform-specific code today — they
are already fully reusable by construction, since an interface is agnostic
to what implements it. This pass makes **no change** to `backupassurance`;
a real Linux-backed observer implementation (or a platform-tagging/reporting
layer) is separately deferred work, not blocked by anything here.

## B. `rwevidence/dispatch.go` changes

Two small, additive edits to `classifyRansomwareStep` (`internal/rwevidence/dispatch.go`).
Both existing Windows recognitions stay untouched; Linux text is recognized
*alongside* them, in the same map and the same switch.

```go
var reconnaissanceStepNames = map[string]bool{
	"VSS Snapshot Enumeration":         true,
	"VSS + Backup Catalog Enumeration": true,
	"LVM Snapshot Enumeration":         true, // new: Linux analog, same role
}
```

```go
	switch {
	case strings.Contains(lower, "bas_confirm_vss_delete not set"):
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "bas_confirm_lvm_delete not set"): // new
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "no c: vss shadow copies exist"):
		return true, true, "no_target_precondition"
	case strings.Contains(lower, "no lvm snapshots exist"): // new
		return true, true, "no_target_precondition"
	default:
		return true, true, "skip_unclassified"
	}
```

No change to `T1486` handling: its two Windows steps (rename-probe and XOR
simulation) are not in `reconnaissanceStepNames` and hit no skip pattern
today, so they are classified as genuine attempts by the existing default
path. The Linux T1486 steps (below) reuse that same default path unchanged.

## C. New scenario: `scenarios/linux-ransomware-drill.yaml`

`supported_os: [linux]`. Four steps, each mirroring an existing Windows
step's exact safety discipline (same `fidelity`/`production_safe`/`risk`/
`blast_radius`/`reversible`/telemetry/detection documentation shape used
throughout `ransomware-drill.yaml`) — executor `bash` instead of `powershell`,
otherwise the same authoring convention:

1. **"LVM Snapshot Enumeration"** (`technique_id: T1490`, `action_key: enumerate`,
   `detection_profiles: [linux_lvm_snapshot_inhibition]`, `production_safe: true`,
   `requires_priv: user`). Read-only: counts existing LVM snapshots via `lvs`
   filtered to snapshot type. No snapshot touched. Mirrors "VSS Snapshot
   Enumeration" exactly — same role, same recon-only guarantee.

2. **"LVM Snapshot Removal (lab — requires `BAS_CONFIRM_LVM_DELETE=true`)"**
   (`technique_id: T1490`, `action_key: lvm_delete`, `detection_profiles:
   [linux_lvm_snapshot_inhibition]`, `fidelity: lab-only`, `production_safe:
   false`, `risk: high`, `requires_priv: admin`). Gate check first (skip with
   `"BAS_CONFIRM_LVM_DELETE not set to 'true'"` if the env var isn't exactly
   `"true"`); then a target-existence check (skip with `"no LVM snapshots
   exist"` if `lvs` finds none); only then deletes the oldest real snapshot
   via `lvremove -f`. Same risk profile as the already-accepted Windows VSS
   deletion step — this is deliberately not a weaker synthetic stand-in: the
   security question ("can an admin-level attacker destroy your actual
   recovery point") is identical, and testing it meaningfully requires acting
   on a real snapshot, gated the same way the Windows step already is.

3. **"File Rename Probe (.bas_locked extension)"** (`technique_id: T1486`,
   `action_key` omitted to match the Windows sibling's own convention,
   `detection_profiles: [linux_ransomware_encryption]`, `production_safe:
   true`, `requires_priv: user`). Creates one marker file in `/tmp`, renames
   to `.bas_locked`, renames back, deletes it. No real data touched.

4. **"XOR Encryption Simulation (lab — isolated temp dir, forced cleanup)"**
   (`technique_id: T1486`, `detection_profiles: [linux_ransomware_encryption]`,
   `fidelity: lab-only`, `production_safe: false`, `risk: high`, `requires_priv:
   user`). Creates an isolated scratch directory (e.g. under `/tmp`) with at
   most 3 dummy files, XOR-encrypts them in place, drops a marker ransom note,
   XOR-decrypts to restore (XOR is its own inverse), deletes the entire
   directory. Same file-cap/size-cap/cleanup-verification bounds as the
   Windows XOR step.

All four steps carry `[BAS-SIM]` output markers and accurate
telemetry/detection documentation, per the existing scenarios' convention.

## D. Registration touchpoints

Six places each carry their own copy of "the ransomware scenario file/ID
list." Each must learn about the new scenario, or it silently falls outside
existing validation without any test failing to say so:

1. `internal/api/rwevidence_dispatch.go`'s `ransomwareScenarioIDs map[string]bool`
   — add the new scenario's `id` (`linux-ransomware-drill`). This is the real
   dispatch gate: without this entry, a completed run of the new scenario is
   never evaluated by `rwevidence` at all, regardless of how correct the YAML
   or `dispatch.go` changes are.
2. `internal/rwdetect/profiles.go`'s `RansomwareRelevantProfiles []string` —
   append `"linux_lvm_snapshot_inhibition"` and `"linux_ransomware_encryption"`.
3. `internal/rwdetect/profiles_test.go`'s `ransomwareScenarioFiles` — append
   `"linux-ransomware-drill.yaml"`.
4. `internal/rwevidence/realcorpus_test.go`'s own, separately-maintained copy
   of the same file list — same append.
5. `internal/rwtaxonomy/mapping_corpus_test.go`'s own copy — same append. No
   new `TechniqueDomain` entries needed: `T1490`→`DomainRecoveryInhibition`
   and `T1486`→`DomainEncryptionAndDestruction` already exist from sub-project
   #8.
6. `web/src/features/ransomware.js`'s `RR_SCENARIO_IDS` — append
   `'linux-ransomware-drill'`, so a completed run surfaces in the scoring
   dashboard alongside the other 8.

Separately (a build/release step, not a code change): the new YAML needs its
own `.sig` generated via the repo's existing scenario-signing tooling, per
the standing scenario-signature-gate rule — every `scenarios/*.yaml` ships
with a matching `.sig`.

## E. Testing strategy

- `internal/rwevidence/dispatch_test.go` (existing file): new test cases
  proving `classifyRansomwareStep` recognizes `"LVM Snapshot Enumeration"`
  as non-attempt recon (mirrors the existing VSS recon test), and that both
  new skip-text patterns classify to `gate_not_confirmed` /
  `no_target_precondition` respectively — without touching any existing
  Windows-text test case, which must still pass unchanged.
- `internal/rwdetect`, `internal/rwevidence`, `internal/rwtaxonomy`'s existing
  real-corpus tests (items D.2-D.5 above) are the actual proof the new YAML
  is correctly registered everywhere required — a missed registration fails
  one of these, by design, rather than silently passing.
- A YAML-parse smoke test (`scenario.ParseYAML` on the new file, asserting it
  parses without error and has exactly 4 steps with the expected
  `TechniqueID`s) — the cheapest possible proof the file itself is
  well-formed, independent of any Go dispatch logic.

## F. Platform-isolation guardrail

Linux is a distinct execution and evidence adapter, not a cosmetic
command-swap of the Windows content. Two concrete risks this design must not
create, even without a `Platform` field anywhere:

- **A Linux-run result must never be reportable as validating Windows
  capability, or vice versa, just because both share `TechniqueID` T1490 or
  T1486.** This holds structurally today without any new field: every
  `rw_capability_results` row is scoped to one `RunID`, and one `RunID` is one
  scenario execution on one agent/OS — a Linux run's rows and a Windows run's
  rows are never the same row, and nothing in this pass introduces any
  cross-run rollup that could blur them. The concrete, testable guard this
  pass adds: the new scenario's `detection_profiles` entries are
  Linux-specific names (`linux_lvm_snapshot_inhibition`,
  `linux_ransomware_encryption`), never the existing `windows_*`-prefixed
  ones — so anyone cross-referencing a result's detection profile can tell
  which platform actually produced it, even though `CapabilityResult` itself
  carries no explicit platform tag.
- **Linux-host coverage must never be read as establishing ESXi, NAS, cloud
  storage, or hypervisor-identity coverage.** This pass touches none of those
  surfaces' content, code, or registration lists — section D's six
  touchpoints are all Linux-file-server-specific. Each of the other five
  platform surfaces §6 names gets its own later pass, its own spec, and its
  own registration work; nothing here pre-populates or implies progress on
  them.

## G. Explicitly deferred (not this pass)

- Real Linux command execution/wiring beyond what the new scenario's own
  `command:` blocks already specify — this pass is design + content + the
  dispatch-recognition code, lab-independent, matching every other
  sub-project's "design now, real lab validation later" discipline this
  session.
- ESXi/vSphere, VM storage/datastores, NAS, cloud object storage, and
  hypervisor/storage administrative identities — the other five platform
  surfaces §6 names. Each gets its own later pass once this first vertical
  is validated.
- Any `backupassurance` code change, including a real Linux-backed observer
  or a platform/target label on `backup_assurance_results` — explicitly out
  of scope; the package needs no change for this pass, and any future change
  there is a separate decision.
- Any scoring (`rwscore`) change. The existing 5-dimension weighted score
  already reads whatever `rw_capability_results` rows exist for a run,
  regardless of platform — a Linux run scores through the exact same path
  once dispatched, with no `rwscore` code change needed.
