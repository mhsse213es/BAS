# Ubuntu Hardening Validation Scenario Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a new BAS scenario, `scenarios/ubuntu-hardening-validation.yaml`, that actually attempts the attack techniques Ubuntu hardening controls (CIS L1, and later CIS L2/STIG/internal baselines) are supposed to block — complementing `cis-ubuntu-l1.yaml`, which only ever reads configuration state.

**Architecture:** Pure content authoring, zero Go code changes. The scenario uses the codebase's existing `executable: true` + scenario-level `art_techniques: [...]` mechanism (proven by `scenarios/linux-privilege-escalation.yaml` and `scenarios/linux-defense-evasion.yaml`) — the engine runs every available Linux Atomic Red Team atomic for each listed technique ID automatically. No `steps:` list, no new schema fields.

**Tech Stack:** YAML scenario content, Go (`orchestrator/internal/scenario` package, test-only), the existing RSA scenario-signing pipeline (`orchestrator/scripts/signer.go`), Postgres (`art_atomic_tests` table, read-only verification query).

## Global Constraints

- No changes to `scenarios/cis-ubuntu-l1.yaml` — it must keep working exactly as today.
- No new UI, no new API endpoints, no Go production-code changes — content only, per the corrected design (see conversation: the original spec's `Step.Validates` field is dropped; real attack execution here doesn't use per-step `framework: art`).
- Scenario id: `ubuntu-hardening-validation` (control-based name, not tied to one benchmark, per the approved spec).
- `supported_os: [linux]` — this round is Ubuntu/Linux-only, matching `cis-ubuntu-l1.yaml`'s scope.
- Deliverable B (combined Compliance % + Attack Resistance % report) is explicitly out of scope for this plan — deferred per the approved spec.

---

### Task 1: Author the scenario YAML with a regression test

**Files:**
- Create: `scenarios/ubuntu-hardening-validation.yaml`
- Modify: `orchestrator/internal/scenario/engine_test.go` (append a new test function)

**Interfaces:**
- Consumes: `scenario.ParseYAML(b []byte) (*Scenario, error)` — existing package-level function in `orchestrator/internal/scenario/engine.go:137`, parses and validates a single scenario file's bytes without touching the filesystem or signing state.
- Produces: `scenarios/ubuntu-hardening-validation.yaml` on disk, ready for Task 2's signing step.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/scenario/engine_test.go`:

```go
func TestParseYAML_UbuntuHardeningValidation(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", "ubuntu-hardening-validation.yaml"))
	if err != nil {
		t.Fatalf("read scenario file: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sc.ID != "ubuntu-hardening-validation" {
		t.Fatalf("id = %q, want ubuntu-hardening-validation", sc.ID)
	}
	if !sc.Executable {
		t.Fatalf("expected executable: true")
	}
	if sc.LocalCheck {
		t.Fatalf("expected local_check to be unset — this scenario runs real attack techniques, not posture checks")
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "linux" {
		t.Fatalf("supported_os = %v, want [linux]", sc.SupportedOS)
	}
	wantTechniques := []string{
		"T1547.006", "T1055", "T1003", "T1562.001", "T1554", "T1078",
		"T1046", "T1200", "T1222", "T1059", "T1548.001", "T1548.003",
	}
	if len(sc.ARTTechniques) != len(wantTechniques) {
		t.Fatalf("art_techniques count = %d, want %d (%v)", len(sc.ARTTechniques), len(wantTechniques), sc.ARTTechniques)
	}
	for i, want := range wantTechniques {
		if sc.ARTTechniques[i] != want {
			t.Fatalf("art_techniques[%d] = %q, want %q", i, sc.ARTTechniques[i], want)
		}
	}
}
```

**Files touched in this step:** `orchestrator/internal/scenario/engine_test.go`. Confirm `os` and `path/filepath` are already imported at the top of the file (they are — see the existing `TestSaveAndDelete` test using both).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scenario/... -run TestParseYAML_UbuntuHardeningValidation -v` from `orchestrator/`

Expected: FAIL with `read scenario file: open ../../../scenarios/ubuntu-hardening-validation.yaml: no such file or directory` (or equivalent OS path error) — the file doesn't exist yet.

- [ ] **Step 3: Write the scenario YAML**

Create `scenarios/ubuntu-hardening-validation.yaml`:

```yaml
id: ubuntu-hardening-validation
name: Ubuntu Hardening Validation — Attack Resistance Check
description: >
  Attempts real attack techniques that Ubuntu hardening baselines (CIS
  Ubuntu L1/L2, Ubuntu STIG, DISA STIG, or an internal baseline) are
  supposed to block or detect. Complements scenarios/cis-ubuntu-l1.yaml,
  which only reads configuration state — this scenario tests whether that
  configuration actually holds up under attack. Compliance answers "is the
  control configured?"; this scenario answers "does it actually resist an
  attack?"

  Covers: kernel module loading, process-injection resistance (exercises
  the same ASLR/ptrace-scope hardening cis-ubuntu-l1 checks — not a direct
  sysctl toggle, since Atomic Red Team's T1055 atomics test injection
  itself), core-dump credential exposure, auditd tamper resistance,
  protected-binary integrity, SSH authentication hardening, firewall
  egress control, removable-media policy, filesystem permission
  hardening, /tmp noexec enforcement, SUID/GTFOBins abuse resistance, and
  sudo/pkexec escalation resistance.

  Each technique runs ALL available Linux atomics (depth mode) so every
  variant is tested against your hardening controls. Some techniques below
  may execute zero tests if Atomic Red Team has not yet published a Linux
  atomic for that technique — that is a content-library gap, not a
  scenario defect (verified during authoring — see the design spec).

  Expected verdicts:
    PASS = the hardening control held; the attack was blocked or alerted
    FAIL = the attack succeeded despite the hardening control
    SKIP = the atomic requires a precondition not present on this host

  Safety: uses Atomic Red Team's benign demonstration commands, not
  destructive payloads. Several techniques (auditd stop, USB mount, sudo
  escalation) are lab-only in effect — expect service disruption if run
  outside an isolated test endpoint. Run only on dedicated test endpoints.
author: Audspect Research
executable: true
supported_os: [linux]
tags:
  - hardening
  - attack-validation
  - linux
  - ubuntu
  - art
  - atomic-red-team
  - cis
  - cis-ubuntu-l1
  - mitre-attack
mitre_phases:
  - initial-access
  - execution
  - persistence
  - privilege-escalation
  - defense-evasion
  - credential-access
  - discovery

art_techniques:
  - T1547.006   # Kernel Modules and Extensions (insmod/modprobe loading — CIS kernel-module restriction controls)
  - T1055       # Process Injection (ptrace/LD_PRELOAD — exercises ASLR/ptrace-scope hardening; cis-ubuntu-l1 tags its ASLR check the same technique_id)
  - T1003       # OS Credential Dumping (core-dump-based credential exposure — pairs with cis-ubuntu-l1's fs.suid_dumpable check)
  - T1562.001   # Disable or Modify Tools (auditd stop/disable — also covered by linux-defense-evasion.yaml; included here for a single hardening-focused run)
  - T1554       # Compromise Client Software Binary (protected-binary tamper / integrity monitoring)
  - T1078       # Valid Accounts (SSH root login / weak authentication — pairs with cis-ubuntu-l1's PermitRootLogin check)
  - T1046       # Network Service Discovery (port scan / firewall egress bypass — pairs with cis-ubuntu-l1's UFW check)
  - T1200       # Hardware Additions (removable media / USB mount policy bypass)
  - T1222       # File and Directory Permissions Modification (/etc, /usr/bin write attempts without privilege)
  - T1059       # Command and Scripting Interpreter (execute from /tmp — pairs with cis-ubuntu-l1's /tmp noexec check)
  - T1548.001   # Setuid and Setgid (SUID/GTFOBins abuse — also covered by linux-privilege-escalation.yaml; included here for a single hardening-focused run)
  - T1548.003   # Sudo and Sudo Caching (sudo/pkexec escalation — also covered by linux-privilege-escalation.yaml; included here for a single hardening-focused run)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scenario/... -run TestParseYAML_UbuntuHardeningValidation -v` from `orchestrator/`

Expected: PASS

- [ ] **Step 5: Run the full scenario package test suite to confirm nothing else broke**

Run: `go test ./internal/scenario/... -v` from `orchestrator/`

Expected: all tests PASS, including the pre-existing `TestSaveAndDelete`, `TestLoad_SourceClassification`, `TestLoad_UnsignedBuiltinRefused`, `TestLoad_SkipsMalformedFileWithoutBlockingOthers` (unaffected — this task added a new test and a new content file, no shared code touched).

- [ ] **Step 6: Commit**

```bash
git add scenarios/ubuntu-hardening-validation.yaml orchestrator/internal/scenario/engine_test.go
git commit -m "feat(scenarios): add Ubuntu Hardening Validation attack scenario"
```

---

### Task 2: Sign the new scenario

**Files:**
- Create: `scenarios/ubuntu-hardening-validation.yaml.sig` (generated by the signer tool, not hand-written)

**Interfaces:**
- Consumes: `orchestrator/scripts/signer.go`'s `sign` subcommand (existing tool, already used by every other builtin scenario — see `packaging/windows-build.ps1:111`), and `orchestrator/private_key.pem` (existing key on this host — see `[[project_signing_key]]`).
- Produces: `scenarios/ubuntu-hardening-validation.yaml.sig`, required before the orchestrator will load this file as a builtin scenario (per `TestLoad_UnsignedBuiltinRefused` in `engine_test.go` — unsigned builtin files are refused, not silently loaded).

- [ ] **Step 1: Confirm the private key exists**

Run: `ls "C:\Users\Administrator\Downloads\Audspect_Cloud\orchestrator\private_key.pem"` (or `Test-Path` in PowerShell)

Expected: file exists. If it does not, stop and ask — do not run `signer.go keygen`, since that would generate a *new* keypair and invalidate every other already-signed scenario in `scenarios/` (they'd all need re-signing, and any already-deployed orchestrator binary has the *old* public key compiled in).

- [ ] **Step 2: Sign the scenario**

Run from `orchestrator/`:

```bash
go run scripts/signer.go sign private_key.pem "C:\Users\Administrator\Downloads\Audspect_Cloud\scenarios\ubuntu-hardening-validation.yaml"
```

Expected: exit code 0, and a new file `scenarios/ubuntu-hardening-validation.yaml.sig` appears.

- [ ] **Step 3: Commit**

```bash
git add scenarios/ubuntu-hardening-validation.yaml.sig
git commit -m "chore(scenarios): sign ubuntu-hardening-validation.yaml"
```

---

### Task 3: Verify real ART Linux atomic coverage against the live content library

**Files:** none created or modified by default — this task may loop back and edit `scenarios/ubuntu-hardening-validation.yaml` (re-running Task 1's Step 3-6 and Task 2's Step 2-3) if it finds a technique with zero Linux atomic coverage.

**Interfaces:**
- Consumes: the running orchestrator's Postgres database (`art_atomic_tests` table, schema in `orchestrator/internal/db/content_schema.go:53-67`), reachable via the project's existing `docker-compose.yml` stack.
- Produces: confirmation (or a documented gap) for each of the 9 technique IDs not already proven by `linux-privilege-escalation.yaml`/`linux-defense-evasion.yaml` (T1548.001, T1548.003, T1562.001 are already known-good — real, shipped, working scenarios use them today).

- [ ] **Step 1: Confirm Docker is running**

Run: `docker info`

Expected: succeeds (shows server info). If it fails with a connection error, start Docker Desktop manually first (per `[[project_docker_windows]]` — it does not auto-start), then re-run `docker info` to confirm before continuing. Do not skip this verification silently — if Docker cannot be started in this environment, stop and report that Task 3 needs to run in an environment with Docker access, rather than marking it done unverified.

- [ ] **Step 2: Confirm the orchestrator + Postgres stack is up**

Run: `docker compose -f packaging/compose/docker-compose.yml ps`

Expected: `audspect-postgres` shows `Up` (healthy). If the stack isn't running, start it: `docker compose -f packaging/compose/docker-compose.yml up -d postgres` and wait for the healthcheck to pass (`docker compose -f packaging/compose/docker-compose.yml ps` again).

- [ ] **Step 3: Query real Linux atomic coverage for the 9 unverified technique IDs**

Run:

```bash
docker compose -f packaging/compose/docker-compose.yml exec postgres psql -U bas_user -d bas_platform -c "SELECT technique_id, test_index, name FROM art_atomic_tests WHERE technique_id = ANY('{T1547.006,T1055,T1003,T1554,T1078,T1046,T1200,T1222,T1059}') AND platform='linux' ORDER BY technique_id, test_index;"
```

Expected: a row for each atomic test found. Record which of the 9 IDs have **zero** rows returned — those are content-library gaps.

- [ ] **Step 4: For any technique ID with zero rows, document the gap in the scenario description**

If Step 3 found a gap (e.g., `T1200` returns zero rows), edit `scenarios/ubuntu-hardening-validation.yaml`'s `description:` block — append a line to the existing "content-library gap" sentence naming the specific ID(s), e.g.:

```
  As of this scenario's authoring, verified gaps with zero Linux atomics
  in the content library: T1200 (Hardware Additions). This technique
  remains listed for when Atomic Red Team publishes Linux coverage; until
  then it contributes no test results to this scenario's run.
```

If Step 3 found no gaps (all 9 IDs have ≥1 row), skip this step — no edit needed.

- [ ] **Step 5: If the YAML changed, re-run Task 1's parse test, re-sign, and commit**

Only if Step 4 made an edit:

```bash
cd orchestrator
go test ./internal/scenario/... -run TestParseYAML_UbuntuHardeningValidation -v
go run scripts/signer.go sign private_key.pem "C:\Users\Administrator\Downloads\Audspect_Cloud\scenarios\ubuntu-hardening-validation.yaml"
cd ..
git add scenarios/ubuntu-hardening-validation.yaml scenarios/ubuntu-hardening-validation.yaml.sig
git commit -m "docs(scenarios): document verified ART Linux content-library gaps in ubuntu-hardening-validation"
```

- [ ] **Step 6: Record findings for the reader**

No file output required — report back (in the session, not a new doc) which of the 12 technique IDs were confirmed with real Linux atomic content vs. which (if any) are gaps, so this is visible before anyone relies on the scenario's results in a customer-facing report.

---

## Self-Review Notes

- **Spec coverage:** The approved spec's core deliverable (a new attack-validation scenario, control-based naming, technique-ID reuse from `cis-ubuntu-l1.yaml` where a direct pairing exists, safety documentation) is fully covered by Task 1. The spec's `Step.Validates` field and per-step `framework: art` approach were dropped after Task 1's research showed they don't match how real attack scenarios work in this codebase — replaced with the simpler, already-proven `art_techniques:` mechanism, with benchmark-tagging carried at the scenario `tags:` level instead (matches `cis-ubuntu-l1.yaml`'s own convention). The spec's signing/rollout note is covered by Task 2. The spec's "confirm ART atomic availability" open item is covered by Task 3.
- **Placeholder scan:** No TBD/TODO. Task 3's Steps 4-5 are conditional ("if a gap is found") but give the exact edit and exact commands for both branches — not a placeholder, a real branch.
- **Type consistency:** `sc.ARTTechniques` (Task 1's test) matches the exact field name and YAML tag (`art_techniques`) already defined in `orchestrator/internal/scenario/types.go:201`. `sc.Executable`/`sc.LocalCheck`/`sc.SupportedOS` likewise match existing struct fields exactly — no new types introduced.
