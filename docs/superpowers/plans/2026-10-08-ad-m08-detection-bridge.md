# AD-M08 Detection-Verification Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give AD-M08 ("Detection & Prevention Validation") its extension point: a pure mapping function from `adprimitive.Primitive` to `detectverify.VerifyRequest` (the existing, generic, vendor-agnostic detection-verification request type), so a future run/exercise layer can check whether executing a given AD primitive was detected — without changing `detectverify` itself or adding any AD-awareness to it.

**Architecture:** New package `orchestrator/internal/addetect`, depending one-way on BOTH `adprimitive` and `detectverify` (downstream of both, neither depends back — same bridge shape as `adenv/fromattackpath.go` bridging `adenv`+`attackpath`). One function, `VerifyRequestFor`, maps a `Primitive`'s `TechniqueID` plus caller-supplied run/host/timing context (which the primitive itself has no notion of) into a `detectverify.VerifyRequest`. Returns `ok=false` for any primitive with an empty `TechniqueID` — `detectverify` is keyed on `TechniqueID`, so a primitive with no 1:1 MITRE mapping (6 of the current 14: all of `ACLAbuseCatalog` and `RBCDCatalog`) cannot be checked this way, and this plan does not invent a mapping for them. Pure field-mapping, no new behavior in either existing package.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task, following the user-approved wave process. Source: `orchestrator/internal/detectverify/connector.go`'s `VerifyRequest` (lines 69-78) and `orchestrator/internal/adprimitive/types.go`'s `Primitive.TechniqueID`.

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- `addetect` depends on `adprimitive` and `detectverify` only. Neither of those packages gains a dependency on `addetect` or on each other.
- No field is added to `detectverify.VerifyRequest`/`VerifyResult`/`Config`, and no new provider is added to `detectverify`'s existing switch. This phase bridges INTO the existing generic shape; it does not extend it.
- No field is added to `adprimitive.Primitive`. `TechniqueID` is read, never written, by this bridge.

## Review Focus

- A primitive with an empty `TechniqueID` (6 of the 14: `ACLAbuseCatalog`'s 4, `RBCDCatalog`'s 2) must return `ok=false` with a zero-value `VerifyRequest` — a caller that forgets to check `ok` and uses the zero-value request anyway would silently query a detection provider for technique `""`, which is a meaningless, possibly over-broad query. Tested in Task 1, Step 1.
- A primitive WITH a `TechniqueID` must carry every caller-supplied field (`runID`/`expectationID`/`hostName`/`hostIP`/timestamps) through UNCHANGED into the resulting `VerifyRequest` — a mapping bug that drops or mismatches one of these fields would silently break whichever field it mangled, and a test that only checks `TechniqueID` would miss it. Tested in Task 1, Step 1.

---

### Task 1: `VerifyRequestFor` bridge function

**Files:**
- Create: `orchestrator/internal/addetect/bridge.go`
- Test: `orchestrator/internal/addetect/bridge_test.go`

**Interfaces:**
- Consumes: `adprimitive.Primitive` (reads `.TechniqueID` only), `detectverify.VerifyRequest` (all 7 fields).
- Produces: `VerifyRequestFor(p adprimitive.Primitive, runID, expectationID, hostName, hostIP string, executedAt, windowStart, windowEnd time.Time) (detectverify.VerifyRequest, bool)` — a future run/exercise orchestration layer calls this exact function per executed AD primitive.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/addetect/bridge_test.go
package addetect

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/detectverify"
)

func TestVerifyRequestFor_NoTechniqueIDReturnsFalse(t *testing.T) {
	p := adprimitive.Primitive{ID: "acl-forcechangepassword-abuse"} // no TechniqueID
	_, ok := VerifyRequestFor(p, "run-1", "exp-1", "HOST01", "10.0.0.5", time.Time{}, time.Time{}, time.Time{})
	if ok {
		t.Fatal("expected ok=false for a primitive with no TechniqueID")
	}
}

func TestVerifyRequestFor_MapsEveryFieldUnchanged(t *testing.T) {
	p := adprimitive.Primitive{ID: "dcsync", TechniqueID: "T1003.006"}
	executedAt := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	windowStart := executedAt.Add(-5 * time.Minute)
	windowEnd := executedAt.Add(10 * time.Minute)

	got, ok := VerifyRequestFor(p, "run-1", "exp-42", "DC01", "10.0.0.10", executedAt, windowStart, windowEnd)
	if !ok {
		t.Fatal("expected ok=true for a primitive with a TechniqueID")
	}
	want := detectverify.VerifyRequest{
		RunID:          "run-1",
		ExpectationID:  "exp-42",
		TechniqueID:    "T1003.006",
		HostName:       "DC01",
		HostIP:         "10.0.0.10",
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/addetect/... -v`
Expected: FAIL — `undefined: VerifyRequestFor` (package doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/addetect/bridge.go

// Package addetect bridges AD-M08 ("Detection & Prevention Validation")
// into the existing, generic detectverify.Connector interface. Depends
// one-way on adprimitive and detectverify only; neither of those
// packages gains any AD-awareness.
package addetect

import (
	"time"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/detectverify"
)

// VerifyRequestFor builds a detectverify.VerifyRequest for checking
// whether executing p was detected, given caller-supplied run/host/
// timing context (p itself carries none of that -- it describes a
// technique, not an execution). Returns ok=false when p.TechniqueID is
// empty: detectverify is keyed on TechniqueID, so a primitive with no
// 1:1 MITRE mapping cannot be checked this way.
func VerifyRequestFor(p adprimitive.Primitive, runID, expectationID, hostName, hostIP string, executedAt, windowStart, windowEnd time.Time) (detectverify.VerifyRequest, bool) {
	if p.TechniqueID == "" {
		return detectverify.VerifyRequest{}, false
	}
	return detectverify.VerifyRequest{
		RunID:          runID,
		ExpectationID:  expectationID,
		TechniqueID:    p.TechniqueID,
		HostName:       hostName,
		HostIP:         hostIP,
		StepExecutedAt: executedAt,
		WindowStart:    windowStart,
		WindowEnd:      windowEnd,
	}, true
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/addetect/... -v`
Expected: PASS — both tests.

- [ ] **Step 5: Run gofmt, go vet, and the full build to confirm no existing package was touched**

Run: `cd orchestrator && gofmt -l internal/addetect/ && go vet ./internal/addetect/... && go build ./... && git status --short internal/detectverify internal/adprimitive`
Expected: gofmt/vet print nothing, build succeeds, `git status` on the two existing packages prints nothing (confirming this plan touched neither).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/addetect/bridge.go orchestrator/internal/addetect/bridge_test.go
git commit -m "$(cat <<'EOF'
feat(addetect): add adprimitive-to-detectverify bridge (AD-M08 extension)

VerifyRequestFor: pure mapping from a Primitive's TechniqueID plus
caller-supplied run/host/timing context into a
detectverify.VerifyRequest. ok=false for the 6 of 14 current
primitives with no TechniqueID (ACLAbuseCatalog + RBCDCatalog) --
detectverify is keyed on TechniqueID, so those cannot be checked this
way without inventing a mapping this plan deliberately does not add.

No change to detectverify or adprimitive themselves -- this bridges
into the existing generic, vendor-agnostic shape rather than adding
AD-awareness to either package.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, pure mapping function over two already-existing, already-tested types; proceeding directly to execution via `superpowers:executing-plans`.
