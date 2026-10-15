# Web Gateway BAS Mastery Phase 4 (Vendor Expansion and Regional Profiles) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Satisfy Phase 4's two exit criteria. (1) Mark at least one additional SWG vendor candidate (beyond Cloudflare) explicitly, visibly `Unsupported`, with the specific blocking gap documented — never silently dropped. (2) Map at least one regulatory obligation per jurisdiction (India, UAE) end-to-end from obligation to control to scenario to evidence, matching Network BAS Phase 7C's own bar.

**Scope note, decided before writing this plan:** Phase 4's own Goal text also names industry profiles (BFSI/NBFC, Healthcare, Manufacturing/OT-adjacent, MSP/shared-tenant) as configuration layered on the Phase 1-3 scenario library. Industry profiles are **not named in Phase 4's own Exit Criteria** (§3) — the same Goal-text-vs-binding-exit-criteria distinction Phase 1 and Phase 3 already drew correctly for their own out-of-scope Goal text. This plan does not build them; they remain available for a future round when the user asks for them.

**Architecture:** Two genuinely separate deliverables, neither of which needs the other:
- **Vendor status (Task 1):** documentation only. Per the master spec's own condition ("document the gap, never silently substitute a mock for a claim of real coverage"), marking a vendor `Unsupported` means recording *why*, not writing a connector stub against an API no one here has verified access to — a stub built on unverified assumptions would itself be the kind of silent-mock risk this initiative exists to avoid. Zscaler was chosen as the representative vendor for this round (see Task 1's own research) because it is the best-known of the 5 remaining, still-unresearched-in-depth candidates (Netskope, Forcepoint, Skyhigh, Broadcom, and FortiProxy were already found sales-gated or trial-limited during Phase 2's own vendor research).
- **Regulatory obligation mapping (Task 2):** new Go code in `internal/webgwefficacy`, following `internal/regobligation`'s established *pattern* (immutable evidence snapshots, versioned obligations) without importing its types — the same independence `webgwefficacy` already keeps from `internal/networkefficacy` and `internal/detectverify`. India's obligation reuses the real, already-verified citation already seeded in this repo at `internal/compliance/mappings/cert_in.yaml` (CERT-In Directions, MeitY No.20(3)/2022-CERT-In, control CI-13). UAE's obligation required fresh research this session (WebSearch/WebFetch against `government.ae`, `dionach.com`, `opensecurityarchitecture.org`) because no UAE regulatory data exists anywhere in this repo yet; that research found genuine disagreement between secondary sources about the UAE Information Assurance Regulation's exact family numbering for its Communications controls (T4 per one source, T8 per another), so the obligation cites the cross-referenced, independently-verifiable NIST SP 800-53 control (SC-07, Boundary Protection) instead of inventing UAE-specific control text this session could not verify from the primary document — and documents that disagreement openly in the obligation's own `Note` field rather than silently picking one.

**Tech Stack:** Go standard library only — no new dependency, no live vendor integration (same discipline as every prior phase).

**Spec:** `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` §3 Phase 4. Exit criteria: "at least one additional vendor adapter is either integrated end-to-end or explicitly, visibly marked `Unsupported` with the specific blocking gap documented (never silently dropped); at least one regulatory obligation per jurisdiction (India, UAE) is mapped end-to-end from obligation to control to scenario to evidence, matching Network BAS Phase 7C's own bar."

## Global Constraints

- `internal/webgwefficacy`'s production code still imports zero other `github.com/audspect/bas/...` package — unchanged since Phase 1, including the new `regulatory.go`. Verify with `go list -deps ./internal/webgwefficacy/...` after Task 2; exactly one `github.com/audspect/bas/...` entry (itself). It must not import `internal/regobligation`.
- `RegulatoryObligation.ControlLabel` is a plain string tag, never an imported type — mirroring `internal/regobligation`'s own `ControlMapping.CapabilityName` discipline (§1 of that package: "never an imported type, since this package has zero Go dependency on any Phase 1-6B package").
- The 5-state `WebGWVerdict` is reused as-is for `ObligationEvidenceSnapshot.CapturedVerdict` — never a new or narrower verdict type, same rule carried through every prior phase.
- `MapObligationToScenarioEvidence` takes `capturedAt time.Time` as an explicit parameter, never `time.Now()` read internally — the same determinism discipline `VerifyPolicyBaselineExpectation` already established in Phase 3.
- No fabricated regulatory citations anywhere in this plan or its code. Every `SourceReference` cites only facts independently verified this session (via WebSearch/WebFetch, or an existing in-repo compliance mapping already verified by an earlier session) — any genuine ambiguity between sources is documented in the obligation's own `Note` field, never silently resolved by invention.

## Review Focus

1. **An `Inconclusive` verdict must map to `Incomplete` status, never `Captured`** — a scenario whose evidence was missing must never be reported as if it proved the obligation met.
2. **An `Unsupported` verdict must also map to `Incomplete` status** — same reasoning, a structurally distinct verdict (per the package's own `Unsupported`/`Inconclusive` distinction), so both branches need their own test, not one standing in for the other.
3. **A `Fail` verdict must still map to `Captured` status, not `Incomplete`** — a fail is a genuine, evidence-backed finding that the control did not hold; collapsing it into "incomplete" would hide a real control gap behind "no data," the opposite of this package's whole purpose.
4. **`MapObligationToScenarioEvidence` never calls `time.Now()` internally** — read the function body, not just the signature, to confirm `capturedAt` is the only source of the timestamp.
5. **The UAE obligation's `SourceReference`/`Note` must not assert primary-document control text this session could not independently verify** — confirm the obligation cites only the cross-referenced NIST SP 800-53 control (SC-07) and documents the T4-vs-T8 secondary-source disagreement honestly, rather than picking a UAE-specific control ID or wording that was never confirmed against the actual regulation text.

---

### Task 1: Vendor status — mark Zscaler Unsupported with documented gap

**Files:**
- Modify: `docs/webgw-mastery-qa-log.md` (append new "Open items" entry)
- Modify: `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` (update the Vendors row in §5's Coverage Matrix)

**Interfaces:** None — this task produces no code, only documentation. There is no RED/GREEN cycle for a documentation-only change; verification is reading the committed text back, not running a test.

- [ ] **Step 1: Append a new QA log entry**

Append this to `docs/webgw-mastery-qa-log.md`, under "## Open items", after item 2:

```markdown
### 3. Additional SWG vendor access (Phase 4) — Zscaler marked Unsupported, documented gap

**Status:** Resolved for Phase 4's own exit criterion (the exit criterion only requires marking a gap, not closing it) — remains open if a live Zscaler adapter is ever wanted later.

**What was needed:** Phase 4's exit criterion requires at least one additional vendor adapter (beyond Cloudflare) either integrated end-to-end or explicitly, visibly marked Unsupported with the specific blocking gap documented.

**What was verified (2026-10-15):** Zscaler Internet Access has no public self-serve trial or signup flow. zscaler.com's own pages route every trial/demo path through "Request a Demo" / "Contact Us" -- a sales engagement, not an account a user can create unassisted. Secondary sources (G-Cloud procurement listings, pricing-review sites) describe it as an enterprise product sold via custom quote, with API access to `help.zscaler.com/zia/api` "available on request" -- no confirmed path to API credentials without going through that sales gate. This mirrors the same vendor-feasibility pattern already found for Netskope/Forcepoint/Skyhigh/Broadcom during Phase 2 research (all sales-gated) and FortiProxy-VM (a time-boxed trial dependent on Fortinet's own FDN phone-home infrastructure) -- none of the 6 Phase 4 vendor candidates offer genuine self-serve API trial access as of this date.

**Resolution path, if ever revisited:** would require the user (or Audspect) to go through Zscaler's sales/demo process and obtain a trial tenant with API credentials -- same shape as the Cloudflare blocker in item #1, but via a sales relationship rather than a missing payment method.
```

- [ ] **Step 2: Update the spec's Coverage Matrix vendor row**

In `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` §5, replace:

```markdown
| Zscaler / Netskope / Forcepoint / Skyhigh / Broadcom / FortiProxy | Planned candidates, access unverified | No commitment to order; each needs its own access/API/licensing verification before any claim of support (Phase 4). |
```

with:

```markdown
| Zscaler | **Unsupported (Phase 4, documented gap)** | No self-serve trial/signup exists; every path routes through Zscaler's own sales/demo gate. See `docs/webgw-mastery-qa-log.md` item #3. |
| Netskope / Forcepoint / Skyhigh / Broadcom / FortiProxy | Planned candidates, access unverified | Same sales-gated pattern found for the other 5 vendors during Phase 2 research; no commitment to order. |
```

- [ ] **Step 3: Verify by reading both files back**

Run: `grep -n "Zscaler" "docs/webgw-mastery-qa-log.md" "docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md"`
Expected: the QA log entry and the updated spec row both appear, with no leftover unedited "Zscaler / Netskope / ..." combined row.

- [ ] **Step 4: Commit**

```bash
git add docs/webgw-mastery-qa-log.md docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md
git commit -m "docs(webgw): mark Zscaler Unsupported with documented gap (Phase 4 vendor exit criterion)"
```

---

### Task 2: Regulatory obligation mapping — India CERT-In and UAE Information Assurance

**Files:**
- Create: `orchestrator/internal/webgwefficacy/regulatory.go`
- Test: `orchestrator/internal/webgwefficacy/regulatory_test.go`

**Interfaces:**
- Consumes: `WebGWVerdict`, `VerdictPass`, `VerdictFail`, `VerdictInconclusive`, `VerdictUnsupported`, `TimeWindow`, `SourceFixture` (Phase 1); `FailureModeExpectation`, `ExpectedFailClosed`, `NewFixtureFailureModeProvider`, `FailureModeEvidence`, `VerifyFailureModeExpectation` (Phase 3, for the India scenario); `HTTPExpectation`, `HTTPObservation`, `ExpectedBlock`, `NewFixtureGatewayProvider`, `GatewayEvidence`, `VerifyHTTPExpectation` (Phase 1, for the UAE scenario).
- Produces: `RegulatoryObligation{ID, Jurisdiction, Regulator, Title, SourceReference, Version, EffectiveDate, ControlLabel, Note}`, `ObligationSnapshotStatus` (`ObligationSnapshotCaptured`, `ObligationSnapshotIncomplete`), `ObligationEvidenceSnapshot{ObligationID, ScenarioLabel, CapturedVerdict, Status, CapturedAt}`, `MapObligationToScenarioEvidence(obligation RegulatoryObligation, scenarioLabel string, verdict WebGWVerdict, capturedAt time.Time) ObligationEvidenceSnapshot` — this is this plan's terminal capability; no later task in this plan consumes it further.

- [ ] **Step 1: Write the failing tests**

```go
package webgwefficacy

import (
	"testing"
	"time"
)

// TestMapObligationToScenarioEvidence_IndiaCERTIn_NetworkSecurityControls
// maps domain 11 end-to-end: obligation -> control -> scenario ->
// evidence, for India's real CERT-In Directions on Information
// Security Practices (MeitY No.20(3)/2022-CERT-In, control CI-13,
// "Network security controls -- firewall, IDS/IPS, network
// segmentation", also seeded in
// internal/compliance/mappings/cert_in.yaml). The scenario is a real
// execution of Phase 3's fail-closed check -- a firewall-class
// control that fails open during an outage is exactly the gap CI-13
// exists to catch.
func TestMapObligationToScenarioEvidence_IndiaCERTIn_NetworkSecurityControls(t *testing.T) {
	obligation := RegulatoryObligation{
		ID:              "cert-in-ci-13",
		Jurisdiction:    "India",
		Regulator:       "CERT-In / MeitY",
		Title:           "Network security controls -- firewall, IDS/IPS, network segmentation",
		SourceReference: "CERT-In Directions on Information Security Practices, MeitY No.20(3)/2022-CERT-In",
		Version:         "2022",
		EffectiveDate:   time.Date(2022, 4, 28, 0, 0, 0, 0, time.UTC),
		ControlLabel:    "webgwefficacy.failuremode",
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := FailureModeExpectation{ScenarioLabel: "gateway-outage-datacenter-failover", ExpectedBehavior: ExpectedFailClosed}
	provider := NewFixtureFailureModeProvider([]FailureModeEvidence{
		{ScenarioLabel: exp.ScenarioLabel, ObservedBehavior: ExpectedFailClosed, Timestamp: now, Source: SourceFixture},
	})
	verdict := VerifyFailureModeExpectation(exp, provider, window)

	snapshot := MapObligationToScenarioEvidence(obligation, exp.ScenarioLabel, verdict.Verdict, now)

	if snapshot.ObligationID != obligation.ID {
		t.Errorf("ObligationID = %q, want %q", snapshot.ObligationID, obligation.ID)
	}
	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q -- the scenario genuinely passed", snapshot.Status, ObligationSnapshotCaptured)
	}
	if snapshot.CapturedVerdict != VerdictPass {
		t.Errorf("CapturedVerdict = %q, want %q", snapshot.CapturedVerdict, VerdictPass)
	}
}

// TestMapObligationToScenarioEvidence_UAEInformationAssurance_BoundaryProtection
// maps domain 08 end-to-end for the UAE's Information Assurance
// Regulation (TDRA, v1.1, Communications control family --
// independent secondary sources disagree on its exact T-number, T4
// vs T8, so this cites the cross-referenced NIST SP 800-53 control it
// corresponds to, SC-07 Boundary Protection, rather than inventing
// UAE-specific control text this session could not independently
// verify from the primary document). The scenario is a real execution
// of Phase 3's proxy-bypass check -- a DNS-over-HTTPS bypass getting
// caught is a direct instance of monitoring and controlling
// communications at the external boundary.
func TestMapObligationToScenarioEvidence_UAEInformationAssurance_BoundaryProtection(t *testing.T) {
	obligation := RegulatoryObligation{
		ID:              "uae-ia-sc-07",
		Jurisdiction:    "UAE",
		Regulator:       "TDRA (UAE Information Assurance Regulation)",
		Title:           "Boundary protection -- monitor and control communications at external boundaries",
		SourceReference: "UAE Information Assurance Regulation v1.1, Communications control family (cross-referenced to NIST SP 800-53 SC-07)",
		Version:         "1.1",
		ControlLabel:    "webgwefficacy.proxybypass",
		Note:            "Secondary sources disagree on this family's T-number (T4 per one source, T8 per another); SC-07 is cited as the verifiable anchor rather than unverified primary-document control text.",
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	exp := HTTPExpectation{RequestURL: "https://dns.google/dns-query", ExpectedAction: ExpectedBlock}
	provider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, HTTPObservation{}, provider, window)

	snapshot := MapObligationToScenarioEvidence(obligation, "doh-bypass-caught", result.Prevention.Verdict, now)

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotCaptured)
	}
	if snapshot.CapturedVerdict != VerdictPass {
		t.Errorf("CapturedVerdict = %q, want %q", snapshot.CapturedVerdict, VerdictPass)
	}
}

// TestMapObligationToScenarioEvidence_InconclusiveVerdict_StatusIncomplete
// proves missing evidence is captured as Incomplete, never silently
// treated as if the obligation had been proven met.
func TestMapObligationToScenarioEvidence_InconclusiveVerdict_StatusIncomplete(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictInconclusive, time.Now())

	if snapshot.Status != ObligationSnapshotIncomplete {
		t.Errorf("Status = %q, want %q -- an Inconclusive verdict must never be captured as if proven", snapshot.Status, ObligationSnapshotIncomplete)
	}
}

func TestMapObligationToScenarioEvidence_UnsupportedVerdict_StatusIncomplete(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictUnsupported, time.Now())

	if snapshot.Status != ObligationSnapshotIncomplete {
		t.Errorf("Status = %q, want %q", snapshot.Status, ObligationSnapshotIncomplete)
	}
}

// TestMapObligationToScenarioEvidence_FailVerdict_StatusCaptured confirms
// a Fail is still a genuinely captured result -- the obligation's
// control was tested and found NOT to hold, which is itself a real,
// capturable finding, not an incomplete one.
func TestMapObligationToScenarioEvidence_FailVerdict_StatusCaptured(t *testing.T) {
	obligation := RegulatoryObligation{ID: "test-obligation"}
	snapshot := MapObligationToScenarioEvidence(obligation, "some-scenario", VerdictFail, time.Now())

	if snapshot.Status != ObligationSnapshotCaptured {
		t.Errorf("Status = %q, want %q -- a Fail is a genuine captured finding, not missing evidence", snapshot.Status, ObligationSnapshotCaptured)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -run TestMapObligationToScenarioEvidence -v`
Expected: FAIL — `undefined: RegulatoryObligation` (and related types/functions).

- [ ] **Step 3: Write the implementation**

```go
package webgwefficacy

import "time"

// RegulatoryObligation is one regulatory requirement from a named
// jurisdiction's regulator, together with the single WebGW capability
// (ControlLabel, a plain string tag -- never an imported type) that
// evidences it. This package has zero Go dependency on
// internal/regobligation; it imitates that package's PATTERN
// (immutable evidence snapshots, versioned obligations) without
// importing its types, the same independence webgwefficacy already
// keeps from internal/networkefficacy and internal/detectverify.
type RegulatoryObligation struct {
	ID              string    `json:"id"`
	Jurisdiction    string    `json:"jurisdiction"`
	Regulator       string    `json:"regulator"`
	Title           string    `json:"title"`
	SourceReference string    `json:"sourceReference"`
	Version         string    `json:"version"`
	EffectiveDate   time.Time `json:"effectiveDate"`
	ControlLabel    string    `json:"controlLabel"`
	Note            string    `json:"note,omitempty"`
}

// ObligationSnapshotStatus distinguishes a snapshot that genuinely
// captured a scenario's verdict from one that could not -- the same
// "nothing here means inconclusive, not failing" discipline this
// package already applies everywhere else.
type ObligationSnapshotStatus string

const (
	ObligationSnapshotCaptured   ObligationSnapshotStatus = "captured"
	ObligationSnapshotIncomplete ObligationSnapshotStatus = "incomplete"
)

// ObligationEvidenceSnapshot is an immutable, point-in-time record
// that a specific webgwefficacy scenario's own verdict was captured
// as evidence for a regulatory obligation. It is never re-executed or
// re-derived -- only ever created fresh by
// MapObligationToScenarioEvidence.
type ObligationEvidenceSnapshot struct {
	ObligationID    string                   `json:"obligationId"`
	ScenarioLabel   string                   `json:"scenarioLabel"`
	CapturedVerdict WebGWVerdict             `json:"capturedVerdict"`
	Status          ObligationSnapshotStatus `json:"status"`
	CapturedAt      time.Time                `json:"capturedAt"`
}

// MapObligationToScenarioEvidence captures one already-computed
// scenario verdict as an immutable evidence snapshot for the given
// obligation. capturedAt is an explicit parameter, never time.Now()
// read internally, matching VerifyPolicyBaselineExpectation's own
// determinism discipline. An Inconclusive or Unsupported verdict is
// captured as Incomplete, never silently treated as if the obligation
// had been proven met; a Fail is still Captured, since a failed
// control is a genuine finding, not missing evidence.
func MapObligationToScenarioEvidence(
	obligation RegulatoryObligation,
	scenarioLabel string,
	verdict WebGWVerdict,
	capturedAt time.Time,
) ObligationEvidenceSnapshot {
	status := ObligationSnapshotCaptured
	if verdict == VerdictInconclusive || verdict == VerdictUnsupported {
		status = ObligationSnapshotIncomplete
	}
	return ObligationEvidenceSnapshot{
		ObligationID:    obligation.ID,
		ScenarioLabel:   scenarioLabel,
		CapturedVerdict: verdict,
		Status:          status,
		CapturedAt:      capturedAt,
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webgwefficacy/... -v`
Expected: PASS, every test from Phases 1-3 (62) plus Task 2's 5 new tests (67 total).

- [ ] **Step 5: Verify the zero-import-dependency constraint**

Run: `cd orchestrator && go list -deps ./internal/webgwefficacy/... | grep "audspect/bas"`
Expected: exactly one line, `github.com/audspect/bas/internal/webgwefficacy` itself — confirms no accidental import of `internal/regobligation`.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/webgwefficacy/regulatory.go internal/webgwefficacy/regulatory_test.go
git commit -m "feat(webgwefficacy): add India/UAE regulatory obligation mapping end-to-end"
```

---

## Execution Handoff

Please review this plan. Does it capture what you want? Given Task 1 is documentation-only (no code, no RED/GREEN cycle) and Task 2 is a single self-contained Go file with no dependency on Task 1, I'd recommend **Native** execution — same as Phase 3 — since the two tasks are independent and small enough that a fresh subagent per task would mostly re-read context Task 2 doesn't need. Which execution approach would you prefer?

- **Subagent-driven** — a fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end.
- **Native** — I implement both tasks myself in this session, then one fresh reviewer on the most capable model checks the whole branch at the end.
