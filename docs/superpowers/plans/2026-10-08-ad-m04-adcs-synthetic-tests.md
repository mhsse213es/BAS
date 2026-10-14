# AD-M04 ADCS Synthetic Environment Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the "graph relationship" half of ADCS modeling — a CA's `PublishedTemplates` linked to the actual `CertTemplate` entries it names, evaluated together over a synthetic `Environment` — closing the last of the user's 4 ADCS sub-phases (ontology → predicates → primitive integration → **synthetic tests**). Sub-phase 2 already unit-tested each predicate in isolation against standalone `CertTemplate` literals; this sub-phase proves they work correctly when evaluated over a realistic multi-template environment, with no live AD access at any point.

**Architecture:** One new test file, `orchestrator/internal/adenv/adcs_environment_test.go`, building a synthetic `Environment` with one CA publishing 2 templates (one ESC1-vulnerable, one safely configured) and asserting that walking `env.PKI` and evaluating each template against the sub-phase-2 predicates identifies exactly the vulnerable one. No new production code — this sub-phase is tests only.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task, the last of the user's own 4-sub-phase ADCS breakdown. Source: `orchestrator/internal/adenv/types.go` (`Environment`/`PKI`, sub-phase 1) and `adcs_predicates.go` (sub-phase 2).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- This sub-phase adds NO production code, only tests — the ontology (sub-phase 1), predicates (sub-phase 2), and primitive integration (sub-phase 3) are all already complete and committed.
- The synthetic environment must include at least one SAFE template alongside the vulnerable one, so the test proves discrimination (correctly identifying the vulnerable one AND correctly clearing the safe one), not just "the predicate returns true on a template built to be vulnerable."

## Review Focus

- A template NOT listed in any `CA.PublishedTemplates`, but otherwise matching ESC1's other conditions, must be excluded by TWO independent, consistent signals: `IsESC1Vulnerable`'s own `PublishedToCA` field check, AND a CA-linkage walk that never reaches it in the first place. The test must confirm both agree, not assume either one alone is sufficient proof. Tested in Task 1, Step 1.
- Walking all of `env.PKI.Templates` and checking each against the 3 vulnerability predicates must correctly find ONLY the genuinely vulnerable one in a multi-template environment — not flag the safe template as a false positive, and not silently skip the vulnerable one. Tested in Task 1, Step 1.

---

### Task 1: Add the synthetic environment test

**Files:**
- Create: `orchestrator/internal/adenv/adcs_environment_test.go`

**Interfaces:**
- Consumes: `Environment`, `PKI`, `CertificateAuthority`, `CertTemplate` (sub-phase 1) and `IsESC1Vulnerable`/`IsESC2Vulnerable`/`IsESC3Vulnerable` (sub-phase 2).
- Produces: nothing new — this is a test-only sub-phase.

- [ ] **Step 1: Write the test**

```go
// orchestrator/internal/adenv/adcs_environment_test.go
package adenv

import "testing"

// TestADCSEnvironment_IdentifiesVulnerableTemplateAmongPublishedOnes
// proves the "graph relationship" half of ADCS modeling: a CA's
// PublishedTemplates linked to the actual CertTemplate entries it names,
// walked together to find exactly the vulnerable one in a realistic
// multi-template environment -- not a predicate exercised against one
// isolated struct literal (sub-phase 2 already covers that case).
func TestADCSEnvironment_IdentifiesVulnerableTemplateAmongPublishedOnes(t *testing.T) {
	env := Environment{
		PKI: PKI{
			CAs: []CertificateAuthority{{
				Name:               "CORP-CA",
				PublishedTemplates: []string{"VulnerableWebAuth", "StandardUser"},
			}},
			Templates: []CertTemplate{
				{
					Name:                    "VulnerableWebAuth",
					EKUs:                    []string{"Client Authentication"},
					EnrolleeSuppliesSubject: true,
					ManagerApprovalRequired: false,
					PublishedToCA:           true,
				},
				{
					Name:                    "StandardUser",
					EKUs:                    []string{"Client Authentication"},
					EnrolleeSuppliesSubject: false, // the mitigating difference
					ManagerApprovalRequired: false,
					PublishedToCA:           true,
				},
				{
					// Exists in the environment but is NOT in any CA's
					// PublishedTemplates -- vulnerable in isolation, but
					// unreachable, so a "what can actually be requested"
					// query must exclude it.
					Name:                    "UnpublishedLegacyTemplate",
					EKUs:                    []string{"Client Authentication"},
					EnrolleeSuppliesSubject: true,
					ManagerApprovalRequired: false,
					PublishedToCA:           false,
				},
			},
		},
	}

	ca := env.PKI.CAs[0]
	templatesByName := map[string]CertTemplate{}
	for _, t := range env.PKI.Templates {
		templatesByName[t.Name] = t
	}

	var reachableVulnerable []string
	for _, name := range ca.PublishedTemplates {
		tmpl, ok := templatesByName[name]
		if !ok {
			continue
		}
		if IsESC1Vulnerable(tmpl) || IsESC2Vulnerable(tmpl) || IsESC3Vulnerable(tmpl) {
			reachableVulnerable = append(reachableVulnerable, name)
		}
	}

	if len(reachableVulnerable) != 1 || reachableVulnerable[0] != "VulnerableWebAuth" {
		t.Fatalf("expected exactly [VulnerableWebAuth] reachable-and-vulnerable, got %v", reachableVulnerable)
	}

	// IsESC1Vulnerable's own definition includes PublishedToCA (an
	// unpublished template cannot actually be requested at all, so it is
	// correctly excluded by the predicate itself, not merely by the
	// CA-linkage check above) -- two consistent signals, not a
	// predicate/reachability split.
	if IsESC1Vulnerable(templatesByName["UnpublishedLegacyTemplate"]) {
		t.Fatal("expected UnpublishedLegacyTemplate to be excluded by IsESC1Vulnerable itself (PublishedToCA is part of ESC1's own definition)")
	}
	for _, name := range reachableVulnerable {
		if name == "UnpublishedLegacyTemplate" {
			t.Fatal("UnpublishedLegacyTemplate must not appear in the CA-reachable vulnerable set -- it is not in any CA's PublishedTemplates")
		}
	}
}
```

- [ ] **Step 2: Run the test**

Run: `cd orchestrator && go test ./internal/adenv/... -run TestADCSEnvironment -v`
Expected: PASS immediately (this sub-phase adds no production code — the test exercises types and predicates already shipped in sub-phases 1-2). If it fails, that means sub-phase 1 or 2's shipped code has a real bug this test newly exposes; use `systematic-debugging` on the actual code, not the test.

- [ ] **Step 3: Run the full adenv suite to confirm nothing else is affected**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: PASS — all tests in the package (8 pre-existing plus 1 new).

- [ ] **Step 4: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adenv/ && go vet ./internal/adenv/...`
Expected: both print nothing.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/adenv/adcs_environment_test.go
git commit -m "$(cat <<'EOF'
test(adenv): prove ADCS graph relationships over a synthetic environment (AD-M04 sub-phase 4 of 4)

Walks a synthetic Environment's CA->PublishedTemplates linkage
against the actual CertTemplate entries, proving the 3 vulnerability
predicates correctly identify ONE genuinely vulnerable, reachable
template among a safe one and an unpublished-but-vulnerable one --
not just a predicate exercised against an isolated struct literal
(sub-phase 2 already covers that case). Test-only; no production
code changes. Closes out the full AD-M04 ADCS pass (ontology,
predicates, primitive integration, synthetic tests).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single test-only task over already-shipped, already-tested code; proceeding directly to execution via `superpowers:executing-plans`.
