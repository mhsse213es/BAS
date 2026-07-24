# Ubuntu Hardening Validation Scenario — Design

## Context

`scenarios/cis-ubuntu-l1.yaml` already validates 38 CIS Ubuntu L1 controls, but
it is a `local_check: true` scenario — every step reads current configuration
state (sysctl values, mount options, sshd config, systemctl status) and never
attempts an actual attack. `docs/guides/compliance-mapping.md` says this
outright: *"CIS L1 checks are configuration-only... They verify current
configuration state, not runtime attack blocking."*

That's a real gap: a system can be 100% compliant on paper (every control
configured correctly) while still being exploitable if a specific control
doesn't actually hold up under attack — sudo misconfiguration, an SUID binary
GTFOBins can abuse, a firewall rule with a hole in it, etc. Compliance answers
"is the control configured?"; this scenario answers "does the control actually
resist an attack?"

## Goal

A new, standalone BAS scenario — `ubuntu-hardening-validation` — that
actually attempts the attack techniques Ubuntu hardening controls (CIS L1,
CIS L2, Ubuntu STIG, DISA STIG, or an internal baseline) are supposed to
block or detect, and scores each attempt PASS (blocked) / FAIL (control was
bypassed) / SKIPPED using the platform's existing verdict taxonomy.

It complements `cis-ubuntu-l1.yaml` rather than replacing or modifying it.
Where a direct posture↔attack pairing exists, the new scenario deliberately
reuses `cis-ubuntu-l1.yaml`'s `technique_id` for that control (e.g. ASLR is
`T1055` in both), so a future combined report can cross-reference the two
scenarios' results per control without a remapping step.

**Naming is deliberately control-based, not benchmark-based.** The scenario
is organized around what it tests (kernel protections, audit protections,
etc.), not which specific benchmark first motivated it. Each step tags which
benchmark(s) it validates via a new `validates` field (see Architecture), so
the same attack content serves CIS L1 today and CIS L2 / STIG / an internal
baseline later without duplicating scenarios.

## Non-Goals (this round)

- **No combined Compliance % + Attack Resistance % report.** Explicitly
  deferred as a follow-on brainstorm, once this scenario has produced real
  execution data. Scoring-model questions (equal vs. weighted controls, how
  SKIPPED should affect a percentage, whether a control validated by three
  technique steps counts once or three times) can't be answered well without
  that data — see compliance-mapping.md's existing Coverage vs. Effectiveness
  framing for the closest current precedent.
- **No changes to `cis-ubuntu-l1.yaml`.** It keeps working exactly as today;
  this is a new, additional, standalone scenario.
- **No new UI.** Risk/Fidelity/Telemetry/etc. step metadata already has a
  generic display path from prior scenario work; this design doesn't assume
  any UI change beyond what already renders that metadata (see Testing for
  what needs verifying at implementation time).
- **No verified inventory of official Atomic Red Team Linux atomics for
  these 12 items.** That's real research, flagged for the implementation
  plan, not guessed at here.

## Architecture

### Execution mechanism

Steps use `framework: art` (the platform's existing mechanism for real,
scored attack execution — see `scenarios/ad-credential-access.yaml` for
precedent) wherever an official Atomic Red Team Linux atomic exists for the
technique. Where ART has no matching Linux atomic, steps fall back to
`framework: custom` with an explicit `cleanup:` command (an existing,
already-supported `Step` field) so the step is still fully reversible.
**Not** `local_check` — that path is read-only by design and cannot express
"attempt X and observe whether it succeeded."

### New field: `Step.Validates`

`orchestrator/internal/scenario/types.go`'s `Step` struct gets one new
optional field, alongside the existing Risk/BlastRadius/Telemetry block:

```go
// Validates lists which hardening baseline(s) this step's control maps to
// (e.g. "cis-ubuntu-l1", "cis-ubuntu-l2", "ubuntu-stig", "disa-stig"). Purely
// descriptive metadata for now — no scoring logic consumes it yet. Exists so
// a future combined compliance+attack-resistance report can group results
// by baseline without re-authoring scenario content.
Validates []string `yaml:"validates,omitempty" json:"validates,omitempty"`
```

Additive and backward-compatible — existing scenarios omit it and are
unaffected. Populated per-step based on which specific baseline(s) that
control genuinely belongs to (not uniformly copy-pasted across all steps).

### Safety / fidelity tiering

Reuses the existing `Fidelity` (`telemetry-safe` | `lab-only`),
`ProductionSafe`, `Reversible`, and `Cleanup` fields — no new gating
mechanism needed. The platform's Run-launch UI already has a Posture /
Telemetry / Lab mode selector with a hard confirmation warning for lab-only
content, so genuinely destructive steps (killing auditd, mounting removable
media) simply won't fire outside an isolated lab range.

### Content plan — 6 categories, 12 steps

| Category | Attack step | Technique | Fidelity |
|---|---|---|---|
| Kernel | Load unsigned kernel module | T1547.006 | lab-only |
| Kernel | Attempt to disable ASLR via `sysctl -w` | T1055 | telemetry-safe (self-reverting) |
| Kernel | Trigger a core dump, check for leaked data | T1003 | telemetry-safe |
| Audit | Stop/kill auditd | T1562.001 | lab-only |
| Audit | Tamper a protected binary (integrity check) | T1554 | lab-only |
| Authentication | SSH root-login / weak-auth attempt | T1078 | telemetry-safe |
| Network | Connect outbound through a policy-blocked port | T1046 | telemetry-safe |
| Filesystem | Mount removable media (if a USB policy exists) | T1200 | lab-only |
| Filesystem | Write into `/etc`, `/usr/bin` without privilege | T1222 | telemetry-safe |
| Filesystem | Drop + execute from `/tmp` (noexec bypass test) | T1059 | telemetry-safe |
| Privilege | GTFOBins-style SUID abuse (enumerate + safe test) | T1548.001 | telemetry-safe |
| Privilege | sudo/pkexec escalation probe | T1548.003 | lab-only |

Category grouping follows `cis-ubuntu-l1.yaml`'s existing convention (YAML
comment headers, e.g. `# -- Kernel Hardening --`) — no schema change needed
for that; it's a content-authoring convention, not a data model.

USB/removable-media is grouped under Filesystem here (device-mount context)
rather than as its own category — a judgment call, easy to split out later
if it deserves its own section once content exists.

## Testing

- `go build ./...` in `orchestrator/` — verifies the new `Step.Validates`
  field compiles cleanly and doesn't break existing scenario YAML parsing.
- Confirm `cis-ubuntu-l1.yaml` and all other existing scenarios parse and
  run completely unaffected (the only shared code touched is one additive
  struct field).
- Verify, at implementation time, whether `validates` needs any explicit UI
  wiring to be visible in step-result views, or whether it flows through the
  same generic metadata path already used for Risk/BlastRadius/Telemetry.
- Live verification: run the new scenario in Telemetry mode against a real
  hardened Ubuntu host (ideally the same lab target `cis-ubuntu-l1.yaml` was
  validated against) and confirm each step produces a sane PASS/FAIL/SKIPPED
  verdict; confirm lab-only steps refuse to run outside Lab mode.
- Per-step research task (implementation time, not this doc): confirm
  whether an official ART Linux atomic exists for each of the 12 items above,
  or whether it needs a `framework: custom` step with a hand-written
  `cleanup:`.

## Rollout

New scenario file lands in `scenarios/` unsigned; per the existing integrity
pipeline the server won't load it until the next `windows-build.ps1` signing
step runs — same as every other new builtin scenario (matches the
`os-patch-posture` precedent). No orchestrator server-side logic changes
beyond the one new optional `Step` field (additive, no DB migration).

## Follow-on (explicitly deferred, not part of this plan)

**Deliverable B** — a combined report showing Compliance % (from
`cis-ubuntu-l1.yaml`-style posture scenarios) and Attack Resistance % (from
this scenario and others like it) side by side per baseline, using the new
`validates` tags to group results. Explicitly deferred until this scenario
has produced real execution data, since the scoring-model questions above
can't be answered well in the abstract.
