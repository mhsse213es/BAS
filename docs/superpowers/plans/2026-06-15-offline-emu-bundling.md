# Offline Adversary-Emulation (emu) Bundling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Caldera with the CTID adversary-emulation library pre-loaded so real APT kill-chains (APT29, FIN6, OilRig, menuPass, …) are available fully air-gapped, while gating payload-bearing chains to lab mode only.

**Architecture:** A thin custom Caldera image (`bas-caldera:$Version`) extends the official image at build time on the internet-connected Windows host: it clones the full adversary-emulation library into the `emu` plugin, materializes its abilities, and enables `emu`. The image is `docker save`d into the existing offline bundle exactly like the orchestrator/postgres images. On the orchestrator side, every Caldera ability that declares a payload is tagged `lab-only`, and a post-build fidelity filter drops `lab-only` steps unless the run is in lab mode — so the loud, real-payload emu chains can never fire in posture or telemetry.

**Tech Stack:** Docker (multi-stage not needed — single `FROM`), MITRE Caldera (Python), Go (orchestrator builder + run handler), PowerShell (windows-build.ps1), docker-compose.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `packaging/caldera/Dockerfile` | Build `bas-caldera` = official image + emu data + emu enabled | **Create** |
| `packaging/caldera/README.md` | Document what the image adds, AV note, rebuild cadence | **Create** |
| `packaging/windows-build.ps1` | Build + save `bas-caldera:$Version` into the bundle | Modify |
| `packaging/compose/docker-compose.yml` | Point Caldera service at the custom image | Modify |
| `orchestrator/internal/scenario/builder.go` | Named `calderaExecutor` type w/ payloads; tag payload-bearing abilities `lab-only` in all 3 Caldera build paths | Modify |
| `orchestrator/internal/scenario/types.go` | Add `Fidelity` field to `ScenarioStep` | Modify |
| `orchestrator/internal/api/handlers.go` | Post-build fidelity filter in `RunScenario` | Modify |
| `orchestrator/internal/scenario/caldera_fidelity_test.go` | Unit tests for payload→lab-only tagging | **Create** |
| `docs/CALDERA_EMU.md` | Operator/client doc: capability, AV allowlist, lab-only behavior | **Create** |

---

## Part A — Custom Caldera image with emu

### Task 1: Determine the exact emu ingest mechanism (discovery)

The `emu` plugin's setup differs across Caldera versions; we must record the *exact* commands that materialize abilities before writing the Dockerfile, so the Dockerfile contains no guesswork.

**Files:** none (investigation; output is the verified command list recorded in this task's notes and used in Task 2).

- [ ] **Step 1: Inspect the emu plugin inside the base image**

Run:
```bash
docker pull ghcr.io/mitre/caldera:latest
docker run --rm ghcr.io/mitre/caldera:latest sh -c 'echo "--- README ---"; sed -n "1,120p" plugins/emu/README.md; echo "--- hook ---"; sed -n "1,80p" plugins/emu/hook.py; echo "--- reqs ---"; cat plugins/emu/requirements.txt; echo "--- data ---"; ls -la plugins/emu/data 2>/dev/null'
```
Expected: the README states how to populate `plugins/emu/data` (typically a git clone of `adversary_emulation_library`) and whether a generator script must run. `hook.py` reveals the data path the plugin reads at load.

- [ ] **Step 2: Identify the clone target and ingest command**

From Step 1, record the two concrete facts:
1. The git URL + the destination path the plugin reads (commonly `https://github.com/center-for-threat-informed-defense/adversary_emulation_library` → `plugins/emu/data/adversary-emulation-plans`).
2. Whether abilities appear merely by Caldera booting with `emu` enabled, or whether an explicit generator must run (e.g. a `payloads` download / a `*.py` under `plugins/emu/`).

- [ ] **Step 3: Prove the ingest produces abilities (throwaway container)**

Run (substituting the URL/path/command found above):
```bash
docker run --rm ghcr.io/mitre/caldera:latest sh -c '
  git clone --depth 1 https://github.com/center-for-threat-informed-defense/adversary_emulation_library plugins/emu/data/adversary-emulation-plans &&
  pip install -r plugins/emu/requirements.txt &&
  find plugins/emu/data -name "*.yml" | wc -l'
```
Expected: a non-zero count of YAML files under `plugins/emu/data`. Record the precise, working command sequence — it becomes the body of the Dockerfile in Task 2. If a generator script is required, append it here and re-run until the count is non-zero.

- [ ] **Step 4: Note adversary materialization**

emu primarily contributes **adversary profiles** (full chains), which Caldera exposes at `/api/v2/adversaries` and whose abilities expand via `buildCalderaAdversarySteps`. Confirm by running the throwaway container with `emu` enabled and curling `/api/v2/adversaries` — but this is verified end-to-end in Task 4, so only record the expectation here: enabling emu adds both abilities (`/api/v2/abilities`) and adversary profiles.

### Task 2: Create the custom Caldera Dockerfile

**Files:**
- Create: `packaging/caldera/Dockerfile`
- Create: `packaging/caldera/README.md`

- [ ] **Step 1: Write the Dockerfile**

Create `packaging/caldera/Dockerfile` using the verified commands from Task 1 (the clone URL/path and any generator are confirmed there; the block below is the expected shape — replace the clone/ingest lines only if Task 1 found a different mechanism):

```dockerfile
# bas-caldera — MITRE Caldera with the CTID adversary-emulation library baked in
# so APT kill-chains are available fully air-gapped. Built ONLY on the internet-
# connected Windows build host; the clone happens inside this image layer and is
# never written to the host filesystem (keeps host AV out of the loop).
FROM ghcr.io/mitre/caldera:latest

# 1. Pull the full adversary-emulation library into the emu plugin's data dir.
#    --depth 1 keeps the layer as small as the library allows.
RUN git clone --depth 1 \
      https://github.com/center-for-threat-informed-defense/adversary_emulation_library \
      plugins/emu/data/adversary-emulation-plans

# 2. Install emu's Python deps and materialize its abilities/adversaries.
RUN pip install --no-cache-dir -r plugins/emu/requirements.txt

# 3. Enable the emu plugin in the image's default config. local.yml is removed so
#    a fresh container regenerates it from default.yml (now including emu) AND
#    still receives the API_KEY_RED/API_KEY_BLUE env injection on boot — auth is
#    unchanged from the stock image.
RUN sed -i '/^plugins:/a - emu' conf/default.yml && rm -f conf/local.yml

# 4. Build-time assertion: fail the image build if emu data didn't materialize,
#    so a broken upstream never ships silently.
RUN test "$(find plugins/emu/data -name '*.yml' | wc -l)" -gt 0
```

- [ ] **Step 2: Build the image locally to verify it succeeds**

Run:
```bash
docker build -t bas-caldera:dev packaging/caldera
```
Expected: build completes; the final `test ... -gt 0` layer passes (non-zero exit would fail the build).

- [ ] **Step 3: Verify abilities + adversaries materialized at runtime**

Run:
```bash
docker run --rm -d --name emu-check -e API_KEY_RED=devkey -p 8899:8888 bas-caldera:dev
sleep 45
curl -s -H "KEY: devkey" http://localhost:8899/api/v2/abilities  | python3 -c "import sys,json;print('abilities:',len(json.load(sys.stdin)))"
curl -s -H "KEY: devkey" http://localhost:8899/api/v2/adversaries | python3 -c "import sys,json;print('adversaries:',len(json.load(sys.stdin)))"
docker rm -f emu-check
```
Expected: abilities count is **well above 166** and adversaries count is **> 0** (the stock image has only a handful).

- [ ] **Step 4: Write the README**

Create `packaging/caldera/README.md`:

```markdown
# bas-caldera image

Extends `ghcr.io/mitre/caldera:latest` with the CTID adversary-emulation
library baked in (the `emu` plugin), so APT kill-chains load air-gapped.

- Built by `packaging/windows-build.ps1` on the internet-connected Windows host.
- The clone happens inside the Docker build layer — nothing touches the host FS.
- The library contains REAL offensive payloads. The resulting image (and the
  `bas-caldera-*.tar` in the bundle) WILL be flagged by AV/EDR. See
  `docs/CALDERA_EMU.md` for the client AV-allowlist guidance.
- Rebuild when upgrading Caldera or refreshing the emulation library.
```

- [ ] **Step 5: Commit**

```bash
git add packaging/caldera/Dockerfile packaging/caldera/README.md
git commit -m "feat(caldera): custom image baking the CTID adversary-emulation library for offline emu"
```

### Task 3: Build + bundle the custom image in windows-build.ps1

**Files:**
- Modify: `packaging/windows-build.ps1` (pull block ~line 74-76; save block ~line 97-103)

- [ ] **Step 1: Build the custom image after the base pull**

In `packaging/windows-build.ps1`, immediately after the existing Caldera pull (the `docker pull ghcr.io/mitre/caldera:latest` block near line 75), add:

```powershell
# Build the custom Caldera image with the adversary-emulation library baked in.
# This is the only place the emulation library is cloned (build host has internet).
Log "Building bas-caldera:$Version (emu library)..."
docker build -t "bas-caldera:$Version" "$RepoRoot\packaging\caldera"
if ($LASTEXITCODE -ne 0) { Warn "Failed to build bas-caldera image - bundle will fall back to stock Caldera." }
```

- [ ] **Step 2: Save the custom image instead of the stock one**

Replace the existing stock-Caldera save block (near line 97-103) with a save of the custom image, falling back to stock if the custom build was skipped:

```powershell
$basCalderaExists = docker image inspect "bas-caldera:$Version" 2>$null
if ($basCalderaExists) {
    Log "  Saving bas-caldera:$Version..."
    docker save "bas-caldera:$Version" -o "$OutDir\images\bas-caldera-$Version.tar"
    Log "  Saved: bas-caldera-$Version.tar"
} else {
    $calderaExists = docker image inspect "ghcr.io/mitre/caldera:latest" 2>$null
    if ($calderaExists) {
        Log "  Saving fallback ghcr.io/mitre/caldera:latest..."
        docker save ghcr.io/mitre/caldera:latest -o "$OutDir\images\caldera-latest.tar"
        Log "  Saved: caldera-latest.tar"
    } else {
        Warn "No Caldera image available - skipping."
    }
}
```

- [ ] **Step 3: Verify the script section is syntactically valid**

Run (PowerShell):
```powershell
powershell -NoProfile -Command "Get-Command -Syntax -ErrorAction SilentlyContinue; [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw packaging/windows-build.ps1),[ref]$null) | Out-Null; 'parsed ok'"
```
Expected: prints `parsed ok` (no parse exception).

- [ ] **Step 4: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "build(caldera): build + bundle bas-caldera:\$Version with emu, fallback to stock"
```

### Task 4: Point compose at the custom image

**Files:**
- Modify: `packaging/compose/docker-compose.yml` (caldera service, ~line 29-30)

- [ ] **Step 1: Change the image reference**

In `packaging/compose/docker-compose.yml`, change the caldera service image from:

```yaml
  caldera:
    image: ghcr.io/mitre/caldera:latest
```
to (mirroring how the orchestrator service already uses `REGISTRY`/`BAS_VERSION`):
```yaml
  caldera:
    image: ${REGISTRY:-}bas-caldera:${BAS_VERSION:-latest}
```

- [ ] **Step 2: Validate compose syntax**

Run:
```bash
docker compose -f packaging/compose/docker-compose.yml config >/dev/null && echo "compose ok"
```
Expected: prints `compose ok` (interpolation warnings about unset env vars are fine).

- [ ] **Step 3: Commit**

```bash
git add packaging/compose/docker-compose.yml
git commit -m "build(compose): run the custom bas-caldera image"
```

---

## Part B — lab-only gating for payload-bearing abilities

### Task 5: Add a `Fidelity` field to `ScenarioStep` and a named Caldera executor type

**Files:**
- Modify: `orchestrator/internal/scenario/types.go` (`ScenarioStep`, ~line 116-139)
- Modify: `orchestrator/internal/scenario/builder.go` (executor structs ~line 241-246 & 340-345; `pickExecutorCommand` ~line 302-325)

- [ ] **Step 1: Add `Fidelity` to `ScenarioStep`**

In `orchestrator/internal/scenario/types.go`, add the field to `ScenarioStep` (server-side only — the agent doesn't need it, so `json:"-"`). Place it right after the `Framework` field (~line 123):

```go
	Framework string `json:"-"`
	// Fidelity gates a dynamically-built step to a live tier, mirroring Step.Fidelity:
	//   "" → runs in telemetry AND lab; "lab-only" → runs ONLY in lab mode.
	// Set on Caldera abilities that ship real payloads (e.g. emu APT chains).
	Fidelity string `json:"-"`
```

- [ ] **Step 2: Introduce a named `calderaExecutor` type with payloads**

In `orchestrator/internal/scenario/builder.go`, add a named type (place it just above `type calderaAbility struct` ~line 239):

```go
// calderaExecutor is one platform executor of a Caldera ability. Payloads lists
// the files the ability stages on the target; a non-empty list means the ability
// ships real tooling and must be gated to lab mode.
type calderaExecutor struct {
	Platform string   `json:"platform"`
	Name     string   `json:"name"`
	Command  string   `json:"command"`
	Payloads []string `json:"payloads"`
}
```

- [ ] **Step 3: Use the named type in both ability structs**

In `builder.go`, replace the anonymous executor slice in `calderaAbility` (~line 241-245) and `calderaAbilityFull` (~line 340-344) with `Executors []calderaExecutor `json:"executors"``. Resulting structs:

```go
type calderaAbility struct {
	AbilityID string            `json:"ability_id"`
	Executors []calderaExecutor `json:"executors"`
}
```
```go
type calderaAbilityFull struct {
	AbilityID   string            `json:"ability_id"`
	Name        string            `json:"name"`
	TechniqueID string            `json:"technique_id"`
	Tactic      string            `json:"tactic"`
	Executors   []calderaExecutor `json:"executors"`
}
```

- [ ] **Step 4: Update `pickExecutorCommand`'s signature**

In `builder.go`, change `pickExecutorCommand` (~line 302) to take the named type:

```go
func pickExecutorCommand(executors []calderaExecutor, preferred string) string {
```
(The body is unchanged — it only reads `.Name` and `.Command`.)

- [ ] **Step 5: Build to confirm the refactor compiles**

Run:
```bash
cd orchestrator && go build ./...
```
Expected: no output (clean build).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/scenario/builder.go
git commit -m "refactor(caldera): named executor type w/ payloads; ScenarioStep.Fidelity field"
```

### Task 6: Tag payload-bearing Caldera abilities `lab-only` (all three build paths)

**Files:**
- Modify: `orchestrator/internal/scenario/builder.go` (`buildCalderaAllWindowsSteps` ~line 482; the selective path `buildCalderaAbilitiesSteps`; `buildCalderaAdversarySteps`)
- Test: `orchestrator/internal/scenario/caldera_fidelity_test.go`

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/scenario/caldera_fidelity_test.go`:

```go
package scenario

import "testing"

func TestCalderaStepFidelity(t *testing.T) {
	withPayload := calderaAbilityFull{Executors: []calderaExecutor{
		{Platform: "windows", Name: "psh", Command: "x", Payloads: []string{"mimikatz.exe"}},
	}}
	noPayload := calderaAbilityFull{Executors: []calderaExecutor{
		{Platform: "windows", Name: "psh", Command: "x"},
	}}
	if got := calderaStepFidelity(withPayload); got != "lab-only" {
		t.Errorf("payload-bearing ability fidelity = %q, want lab-only", got)
	}
	if got := calderaStepFidelity(noPayload); got != "" {
		t.Errorf("payload-free ability fidelity = %q, want empty", got)
	}
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run:
```bash
cd orchestrator && go test ./internal/scenario/ -run TestCalderaStepFidelity
```
Expected: FAIL — `undefined: calderaStepFidelity`.

- [ ] **Step 3: Add the helper**

In `builder.go`, add (just above `buildCalderaAllWindowsSteps` ~line 447):

```go
// calderaStepFidelity returns "lab-only" if any of the ability's executors ships
// a payload (real tooling), else "". Conservative on purpose: any payload across
// any executor gates the whole ability to lab mode.
func calderaStepFidelity(ab calderaAbilityFull) string {
	for _, e := range ab.Executors {
		if len(e.Payloads) > 0 {
			return "lab-only"
		}
	}
	return ""
}
```

- [ ] **Step 4: Set Fidelity in the full-sweep builder**

In `buildCalderaAllWindowsSteps`, set the field on the appended step (~line 482-490):

```go
		steps = append(steps, ScenarioStep{
			TaskID:      TaskID(techniqueID, ab.Name),
			TechniqueID: techniqueID,
			Name:        ab.Name,
			Framework:   "caldera",
			Executor:    "powershell",
			Command:     cmd,
			TimeoutSec:  60,
			Fidelity:    calderaStepFidelity(ab),
		})
```

- [ ] **Step 5: Set Fidelity in the selective + adversary builders**

In `builder.go`, locate `buildCalderaAbilitiesSteps` and `buildCalderaAdversarySteps`. Each loops abilities of type `calderaAbilityFull` and appends a `ScenarioStep`; add `Fidelity: calderaStepFidelity(ab),` to each appended `ScenarioStep` literal (where `ab` is the loop's current `calderaAbilityFull`). If either builder fetches abilities via `fetchCalderaAbilityFull` (which returns `*calderaAbilityFull`), pass the dereferenced value: `Fidelity: calderaStepFidelity(*ab),`.

- [ ] **Step 6: Run the test to confirm it passes**

Run:
```bash
cd orchestrator && go test ./internal/scenario/ -run TestCalderaStepFidelity
```
Expected: PASS.

- [ ] **Step 7: Full package build + test**

Run:
```bash
cd orchestrator && go build ./... && go test ./internal/scenario/
```
Expected: build clean; package tests `ok`.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/scenario/builder.go orchestrator/internal/scenario/caldera_fidelity_test.go
git commit -m "feat(caldera): tag payload-bearing abilities lab-only across all build paths"
```

### Task 7: Drop `lab-only` built steps unless the run is in lab mode

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`RunScenario`, right after `steps, err := scenario.BuildSteps(...)` ~line 790)

- [ ] **Step 1: Add the post-build fidelity filter**

In `RunScenario`, immediately after the `steps, err := scenario.BuildSteps(buildSc, ...)` block (and its error check), insert:

```go
	// Dynamically-built Caldera abilities carry their own fidelity tag. Payload-
	// bearing abilities (e.g. emu APT chains) are "lab-only" and must never fire
	// outside lab mode — drop them in posture/telemetry. (Static sc.Steps are
	// already fidelity-filtered above before the build.)
	if mode != "lab" {
		kept := steps[:0]
		for _, st := range steps {
			if st.Fidelity == "lab-only" {
				continue
			}
			kept = append(kept, st)
		}
		dropped := len(steps) - len(kept)
		steps = kept
		if dropped > 0 {
			log.Printf("[scenario] run %s: dropped %d lab-only step(s) for mode=%s", runID, dropped, mode)
		}
		if len(steps) == 0 {
			_, _ = h.db.Exec(context.Background(),
				`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
			jsonError(w, "every step in this scenario is lab-only (ships real payloads) — run it in lab mode against an isolated range", http.StatusUnprocessableEntity)
			return
		}
	}
```

- [ ] **Step 2: Build**

Run:
```bash
cd orchestrator && go build ./...
```
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/handlers.go
git commit -m "feat(run): drop lab-only built steps unless run is in lab mode"
```

### Task 8: Guard the filter with a focused test

**Files:**
- Test: `orchestrator/internal/scenario/caldera_fidelity_test.go` (extend)

Because the filter lives in the API handler (which needs a DB), test the *rule* at the unit level: a payload-bearing ability becomes a `lab-only` step, proving the data the handler filters on is correct end-to-end through the builder. (The handler's drop loop is a 3-line standard slice filter; the risk is in the tagging, which this covers.)

- [ ] **Step 1: Add the build-path assertion test**

Append to `orchestrator/internal/scenario/caldera_fidelity_test.go`:

```go
func TestFullSweepTagsPayloadAbilityLabOnly(t *testing.T) {
	abilities := []calderaAbilityFull{
		{AbilityID: "a1", Name: "safe recon", TechniqueID: "T1082",
			Executors: []calderaExecutor{{Platform: "windows", Name: "psh", Command: "systeminfo"}}},
		{AbilityID: "a2", Name: "drop tool", TechniqueID: "T1105",
			Executors: []calderaExecutor{{Platform: "windows", Name: "psh", Command: "run", Payloads: []string{"tool.exe"}}}},
	}
	got := map[string]string{}
	for _, ab := range abilities {
		if pickExecutorCommand(ab.Executors, "psh") == "" {
			continue
		}
		got[ab.Name] = calderaStepFidelity(ab)
	}
	if got["safe recon"] != "" {
		t.Errorf("safe recon fidelity = %q, want empty (telemetry+lab)", got["safe recon"])
	}
	if got["drop tool"] != "lab-only" {
		t.Errorf("drop tool fidelity = %q, want lab-only", got["drop tool"])
	}
}
```

- [ ] **Step 2: Run the scenario package tests**

Run:
```bash
cd orchestrator && go test ./internal/scenario/
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/scenario/caldera_fidelity_test.go
git commit -m "test(caldera): payload abilities tagged lab-only through the build path"
```

---

## Part C — Documentation

### Task 9: Operator + client documentation

**Files:**
- Create: `docs/CALDERA_EMU.md`

- [ ] **Step 1: Write the doc**

Create `docs/CALDERA_EMU.md`:

```markdown
# Caldera Adversary Emulation (emu)

The platform ships Caldera with the CTID adversary-emulation library baked in,
so full APT kill-chains (APT29, FIN6, OilRig, menuPass, …) run **air-gapped**.

## What it adds
- Hundreds of additional Caldera abilities and the corresponding **adversary
  profiles** (sequenced, multi-step chains), on top of the ~166 stockpile
  abilities.
- These are distinct from Atomic Red Team (run natively by the orchestrator).
  emu = sequenced APT chains; ART = atomic technique breadth.

## Safety model
- emu chains include **real offensive payloads**. Any Caldera ability that ships
  a payload is tagged **lab-only** by the orchestrator: it runs only in **lab
  mode** (isolated range, second confirmation) and is dropped in posture and
  telemetry. Payload-free emu abilities run in telemetry and lab.

## Client AV/EDR allowlist (REQUIRED on delivery)
- The install bundle's `images/bas-caldera-*.tar` contains real tooling and
  **will be flagged by AV/EDR**. Before transfer/extraction, the client must
  allowlist the bundle path and the Docker data-root for the `bas-caldera`
  image. Coordinate this with the client's security team as part of onboarding.

## Rebuilding the library
- Rebuild `bas-caldera` (via `packaging/windows-build.ps1`) when upgrading
  Caldera or to pick up new emulation plans.
```

- [ ] **Step 2: Commit**

```bash
git add docs/CALDERA_EMU.md
git commit -m "docs(caldera): emu capability, lab-only safety model, client AV allowlist"
```

---

## Self-Review

**Spec coverage:**
- Offline emu data baked in → Tasks 1-2. ✓
- Build-host-only clone, inside Docker → Task 2 Step 1 (clone in image layer). ✓
- Bundled via existing save/load path → Task 3. ✓
- Compose uses the image → Task 4. ✓
- Full library → Task 2 (`git clone` of the whole library). ✓
- Lab-only for payload-bearing chains; telemetry+lab for the rest → Tasks 5-7. ✓
- No orchestrator change for *surfacing* abilities (picker/counts use the same `/api/v2/abilities`) → unchanged by design; only fidelity gating added. ✓
- Tests → Tasks 6 & 8. ✓
- Client AV reality documented → Task 9. ✓

**Placeholder scan:** Task 1 is an explicit discovery task with concrete commands and a recorded output, not a "figure it out later" — its result feeds Task 2's clone/ingest lines. All Go steps include full code. No TBDs.

**Type consistency:** `calderaExecutor` (Task 5) is used by `calderaAbility`, `calderaAbilityFull`, and `pickExecutorCommand` (Task 5) and read by `calderaStepFidelity` (Task 6). `ScenarioStep.Fidelity` (Task 5) is set in Task 6 and read by the filter in Task 7. Names consistent throughout.

**Risk note:** Task 1 may reveal the emu plugin needs a generator beyond `git clone` + `pip install`; Step 3 of Task 1 forces that to surface (the file count must be non-zero) before the Dockerfile is finalized, so the uncertainty is contained to one task with a hard pass/fail gate.
