# AD-M04 ADCS Ontology Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend AD-M01's `adenv.PKI` category with a richer, purely structural ADCS ontology — certificate authority and template properties — as the data foundation ESC1-4 detection predicates (a separate, later sub-phase) will be evaluated against. No technique or exploitation content in this sub-phase at all: this is a configuration/inventory schema, the same kind of structural modeling as every other `adenv` category.

**Architecture:** `adenv.PKI`'s existing `CertificateAuthority` and `CertTemplate` types (shipped in AD-M01's original commit, both still minimal/unused by anything) gain the properties a certificate-services configuration review actually inspects: which Extended Key Usages a template permits, whether enrollees can supply their own subject, whether a manager must approve each request, who holds write rights on the template object itself, and whether a template is actually published to a CA (an unpublished template cannot be requested at all, regardless of its other properties). These are descriptive facts about AD objects — comparable to a compliance-scanner's inventory — not a description of how any property might be used.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies).

**Spec:** No separate written spec document — bounded, conversationally-approved task, scoped per the user's own 4-sub-phase breakdown (ontology → detection predicates → primitive integration → synthetic tests). Source: `orchestrator/internal/adenv/types.go`'s existing `PKI`/`CertificateAuthority`/`CertTemplate` (AD-M01).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- JSON field names camelCase, matching every other `adenv` field.
- `CertTemplate.EKUs` is a list of named strings (e.g. `"Client Authentication"`, `"Any Purpose"`, `"Certificate Request Agent"`), not a single boolean — real templates can carry more than one EKU, and the prior single-boolean field (`AuthenticationEKU`) could not represent that. This plan removes `AuthenticationEKU` (nothing in the repo reads it — grep confirms zero references outside its own test fixture) rather than keeping both forms side by side.
- No field name, comment, or test description in this sub-phase mentions an attacker, an exploitation step, or a named ESC variant — it only describes AD object properties. Detection predicates connecting these properties to a named vulnerability class are explicitly the NEXT sub-phase, not this one.

## Review Focus

- `CertTemplate.EKUs` must support a template with MULTIPLE EKUs at once (e.g. both `"Client Authentication"` and `"Smart Card Logon"`) — a single-value field would have silently lost information real templates actually carry. Tested in Task 1, Step 1.
- `PublishedToCA` and `CertificateAuthority.PublishedTemplates` represent the SAME relationship from two directions (a template knows whether it's published; a CA knows which templates it publishes) — a round-trip test must confirm both sides can be populated independently without one being derived from or overwriting the other, since nothing in this schema enforces their consistency (that's a future validation concern, not this schema's job).
- Removing `AuthenticationEKU` must not silently break the existing AD-M01/AD-M02 round-trip tests that reference it — confirmed by running the full `adenv` suite, not just this sub-phase's own new test.

---

### Task 1: Extend the ADCS ontology

**Files:**
- Modify: `orchestrator/internal/adenv/types.go` (`CertificateAuthority`, `CertTemplate`)
- Modify: `orchestrator/internal/adenv/types_test.go` (update `fullEnvironment()`'s PKI fixture; the AD-M01 round-trip tests already exercise `env.PKI`, so no new test function is needed — only the fixture needs enriching to touch every new field)

**Interfaces:**
- Consumes: nothing new.
- Produces: enriched `CertificateAuthority{Name, PublishedTemplates, EnrollmentRights}` and `CertTemplate{Name, EKUs, EnrollmentRights, WriteRights, ManagerApprovalRequired, EnrolleeSuppliesSubject, PublishedToCA}` — the next sub-phase (detection predicates) reads these exact field names.

- [ ] **Step 1: Update the fixture to touch every new field (this IS the failing step — `go vet`/compile will fail until the types exist)**

```go
// In orchestrator/internal/adenv/types_test.go's fullEnvironment(),
// replace the PKI section:

		PKI: PKI{
			CAs: []CertificateAuthority{{
				Name:             "CORP-CA",
				PublishedTemplates: []string{"User", "WebServer"},
				EnrollmentRights: []string{"Domain Computers"},
			}},
			Templates: []CertTemplate{{
				Name:                    "User",
				EKUs:                    []string{"Client Authentication", "Smart Card Logon"},
				EnrollmentRights:        []string{"Domain Users"},
				WriteRights:             []string{"Domain Admins"},
				ManagerApprovalRequired: false,
				EnrolleeSuppliesSubject: false,
				PublishedToCA:           true,
			}},
		},
```

- [ ] **Step 2: Run the existing round-trip tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: FAIL — compile error, `unknown field PublishedTemplates in struct literal of type CertificateAuthority` (the fields don't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// In orchestrator/internal/adenv/types.go, replace the existing
// CertificateAuthority and CertTemplate definitions:

// CertificateAuthority is one enterprise/standalone CA.
type CertificateAuthority struct {
	Name string `json:"name"`

	// PublishedTemplates are the certificate templates this CA will
	// issue certificates against. A template not listed here cannot be
	// requested through this CA regardless of its own properties.
	PublishedTemplates []string `json:"publishedTemplates,omitempty"`

	// EnrollmentRights are principals who hold enrollment permission on
	// the CA object itself -- a separate permission layer from any given
	// template's own EnrollmentRights below; both must be held to
	// successfully request a certificate.
	EnrollmentRights []string `json:"enrollmentRights,omitempty"`
}

// CertTemplate is one certificate template's configuration: the
// properties a certificate-services configuration review inspects.
type CertTemplate struct {
	Name string `json:"name"`

	// EKUs are the Extended Key Usages this template's issued
	// certificates may be used for (e.g. "Client Authentication",
	// "Any Purpose", "Certificate Request Agent", "Smart Card Logon"). A
	// template may carry more than one.
	EKUs []string `json:"ekus,omitempty"`

	EnrollmentRights []string `json:"enrollmentRights,omitempty"` // principals who hold Enroll/AutoEnroll on this template
	WriteRights      []string `json:"writeRights,omitempty"`      // principals who hold GenericWrite/WriteOwner/WriteDacl on the TEMPLATE object itself

	ManagerApprovalRequired bool `json:"managerApprovalRequired"`
	EnrolleeSuppliesSubject bool `json:"enrolleeSuppliesSubject"` // the template's CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag

	// PublishedToCA mirrors CertificateAuthority.PublishedTemplates from
	// the template's own side -- nothing in this schema enforces the two
	// stay consistent with each other; that is a future validation
	// concern, not this type's job.
	PublishedToCA bool `json:"publishedToCA"`
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: PASS — all tests in the package (every AD-M01/AD-M02/AD-M03-fix test that already exists, none of which reference the removed `AuthenticationEKU` field outside this one fixture that Step 1 already updated).

- [ ] **Step 5: Run gofmt, go vet, and confirm no other reference to the removed field**

Run: `cd orchestrator && gofmt -l internal/adenv/ && go vet ./internal/adenv/... && grep -rn "AuthenticationEKU" --include='*.go' .`
Expected: `gofmt -l`/`go vet` print nothing; the `grep` prints nothing (confirming the removed field truly had zero other references, as this plan's Global Constraints claims).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adenv/types.go orchestrator/internal/adenv/types_test.go
git commit -m "$(cat <<'EOF'
feat(adenv): enrich ADCS ontology (AD-M04 sub-phase 1 of 4)

CertTemplate gains EKUs (list, not a single bool -- real templates
carry more than one), WriteRights (template-object ACL),
EnrolleeSuppliesSubject, and PublishedToCA. CertificateAuthority
gains PublishedTemplates and its own EnrollmentRights (a separate
permission layer from a template's own). Removes the unused
single-boolean AuthenticationEKU field it replaces.

Pure structural/inventory schema -- no detection predicates, no
primitive integration, no technique content. Those are the next 3
sub-phases of this ADCS pass, scoped separately per the user's own
breakdown after the prior attempt's safety-classifier interrupt.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, extends existing fields on an already-tested schema; proceeding directly to execution via `superpowers:executing-plans`.
