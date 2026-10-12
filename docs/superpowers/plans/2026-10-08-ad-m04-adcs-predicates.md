# AD-M04 ADCS Detection Predicates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define ESC1-4 as pure boolean configuration predicates over `adenv.CertTemplate`/`CertificateAuthority` — the same kind of check a certificate-services configuration review already runs, expressed as a function rather than a manual checklist. No procedural or exploitation content: each function takes a template's properties and reports whether a named, well-documented configuration weakness is present.

**Architecture:** 4 pure functions in a new file, `orchestrator/internal/adenv/adcs_predicates.go`, each named for the configuration class it checks (not narrated as an attack): `IsESC1Vulnerable`, `IsESC2Vulnerable`, `IsESC3Vulnerable` (each takes one `CertTemplate`), and `HasTemplateWriteAccess` (takes a `CertTemplate` and a principal name — ESC4 is parameterized by WHICH principal holds the write right, since every template has SOME legitimate owner; the configuration weakness is a specific, unintended principal holding it, which this schema cannot determine on its own — the caller supplies the principal to check, the same "caller resolves the specific case" pattern already used for the ACL-abuse/RBCD/DCSync primitives' `"acl_right_held"` Conditions). Each predicate is a conjunction of the template's own fields — no network calls, no live AD access, no simulated requests.

**Tech Stack:** Go (matches `orchestrator`'s existing stdlib-only convention; no new dependencies — `slices.Contains` from the standard library).

**Spec:** No separate written spec document — bounded, conversationally-approved task, the 2nd of the user's own 4-sub-phase ADCS breakdown (ontology → **predicates** → primitive integration → synthetic tests). Source: `orchestrator/internal/adenv/types.go`'s `CertTemplate`/`CertificateAuthority` (just enriched in sub-phase 1).

## Global Constraints

- Go stdlib only — no new third-party dependencies.
- `go 1.26.6`, module path `github.com/audspect/bas`.
- Every predicate is a pure function of its inputs — no I/O, no global state, no reference to any other package.
- Function and variable names describe the CONFIGURATION STATE being checked (`IsESC1Vulnerable`, `EnrolleeSuppliesSubject`), never a narrated action against a target.
- ESC1 and ESC2 are kept as genuinely distinct checks (matching how certificate-services configuration review tooling already separates them): ESC1 checks for an explicit client-authentication-capable EKU; ESC2 checks for the "Any Purpose" EKU or an empty EKU list (which behaves as Any Purpose on older template schema versions) — the same template cannot simultaneously be flagged by both unless it genuinely carries both EKU shapes, which this plan does not force.

## Review Focus

- A template with ZERO EKUs listed must be flagged by `IsESC2Vulnerable` (an empty EKU list behaves as Any Purpose on schema-version-1 templates — a real, historically-documented default, not an edge case to ignore) but NOT by `IsESC1Vulnerable` (which requires an EXPLICIT client-auth-capable EKU to be present, not merely absent restriction). Tested in Task 1, Step 1.
- `ManagerApprovalRequired: true` must make BOTH `IsESC1Vulnerable` and `IsESC2Vulnerable` return `false`, even when every other condition is met — a reasonable reader must be able to trust that approval alone is a complete mitigation for these two checks, and a predicate that ORs instead of ANDs this condition in would silently misreport a mitigated template as vulnerable. Tested in Task 1, Step 1.
- `HasTemplateWriteAccess` must return `false` for a principal NOT in `WriteRights`, not just `true` for one that is — asserting the negative, since a predicate that always returns `true` once `WriteRights` is non-empty (ignoring the `principal` argument entirely) would pass every "is this principal flagged" test that only checks the positive case. Tested in Task 1, Step 1.

---

### Task 1: Define the 4 ADCS predicates

**Files:**
- Create: `orchestrator/internal/adenv/adcs_predicates.go`
- Test: `orchestrator/internal/adenv/adcs_predicates_test.go`

**Interfaces:**
- Consumes: `CertTemplate` (from `types.go`, enriched in sub-phase 1).
- Produces: `IsESC1Vulnerable(t CertTemplate) bool`, `IsESC2Vulnerable(t CertTemplate) bool`, `IsESC3Vulnerable(t CertTemplate) bool`, `HasTemplateWriteAccess(t CertTemplate, principal string) bool` — the next sub-phase (M04 primitive integration) calls these exact functions from `adprimitive`'s future ADCS primitives (or a connecting layer between the two packages) to resolve whether a given template satisfies a primitive's prerequisite.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adenv/adcs_predicates_test.go
package adenv

import "testing"

func TestIsESC1Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		tmpl CertTemplate
		want bool
	}{
		{
			name: "vulnerable: published, enrollee SAN, client auth EKU, no approval",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: true,
		},
		{
			name: "mitigated by manager approval",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: true},
			want: false,
		},
		{
			name: "not vulnerable: enrollee cannot supply subject",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: false, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: false,
		},
		{
			name: "empty EKU list is ESC2's shape, not ESC1's",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: nil, ManagerApprovalRequired: false},
			want: false,
		},
		{
			name: "not published to any CA -- cannot be requested at all",
			tmpl: CertTemplate{PublishedToCA: false, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: false,
		},
	}
	for _, c := range cases {
		if got := IsESC1Vulnerable(c.tmpl); got != c.want {
			t.Errorf("%s: IsESC1Vulnerable() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsESC2Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		tmpl CertTemplate
		want bool
	}{
		{
			name: "vulnerable: any-purpose EKU",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Any Purpose"}, ManagerApprovalRequired: false},
			want: true,
		},
		{
			name: "vulnerable: empty EKU list behaves as any-purpose",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: nil, ManagerApprovalRequired: false},
			want: true,
		},
		{
			name: "mitigated by manager approval",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: nil, ManagerApprovalRequired: true},
			want: false,
		},
		{
			name: "a specific client-auth EKU alone is ESC1's shape, not ESC2's",
			tmpl: CertTemplate{PublishedToCA: true, EnrolleeSuppliesSubject: true, EKUs: []string{"Client Authentication"}, ManagerApprovalRequired: false},
			want: false,
		},
	}
	for _, c := range cases {
		if got := IsESC2Vulnerable(c.tmpl); got != c.want {
			t.Errorf("%s: IsESC2Vulnerable() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsESC3Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		tmpl CertTemplate
		want bool
	}{
		{
			name: "vulnerable: published, Certificate Request Agent EKU",
			tmpl: CertTemplate{PublishedToCA: true, EKUs: []string{"Certificate Request Agent"}},
			want: true,
		},
		{
			name: "not published to any CA",
			tmpl: CertTemplate{PublishedToCA: false, EKUs: []string{"Certificate Request Agent"}},
			want: false,
		},
		{
			name: "no agent EKU",
			tmpl: CertTemplate{PublishedToCA: true, EKUs: []string{"Client Authentication"}},
			want: false,
		},
	}
	for _, c := range cases {
		if got := IsESC3Vulnerable(c.tmpl); got != c.want {
			t.Errorf("%s: IsESC3Vulnerable() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHasTemplateWriteAccess(t *testing.T) {
	tmpl := CertTemplate{WriteRights: []string{"Domain Admins", "PKI Admins"}}
	if !HasTemplateWriteAccess(tmpl, "PKI Admins") {
		t.Error("expected HasTemplateWriteAccess to return true for a listed principal")
	}
	if HasTemplateWriteAccess(tmpl, "Domain Users") {
		t.Error("expected HasTemplateWriteAccess to return false for a principal NOT in WriteRights")
	}
	if HasTemplateWriteAccess(CertTemplate{}, "Domain Admins") {
		t.Error("expected HasTemplateWriteAccess to return false when WriteRights is empty")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adenv/... -run "TestIsESC|TestHasTemplateWriteAccess" -v`
Expected: FAIL — `undefined: IsESC1Vulnerable` (the predicates don't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adenv/adcs_predicates.go
package adenv

import "slices"

// clientAuthEKUs are the Extended Key Usages that let a certificate be
// used for Kerberos/TLS client authentication (distinct from "Any
// Purpose", checked separately by IsESC2Vulnerable).
var clientAuthEKUs = []string{"Client Authentication", "Smart Card Logon", "PKINIT Client Authentication"}

func hasAnyEKU(ekus []string, want ...string) bool {
	for _, e := range ekus {
		if slices.Contains(want, e) {
			return true
		}
	}
	return false
}

// IsESC1Vulnerable reports whether t's configuration matches ESC1: it is
// published to a CA, lets the enrollee supply their own certificate
// subject, carries a client-authentication-capable EKU, and does not
// require manager approval. Any one of these being false means the
// configuration does not match this specific weakness.
func IsESC1Vulnerable(t CertTemplate) bool {
	return t.PublishedToCA &&
		t.EnrolleeSuppliesSubject &&
		!t.ManagerApprovalRequired &&
		hasAnyEKU(t.EKUs, clientAuthEKUs...)
}

// IsESC2Vulnerable reports whether t's configuration matches ESC2: the
// same enrollee-supplied-subject and no-approval conditions as ESC1, but
// with the "Any Purpose" EKU (or an empty EKU list, which behaves as Any
// Purpose on schema-version-1 templates) instead of a single named
// client-auth EKU.
func IsESC2Vulnerable(t CertTemplate) bool {
	return t.PublishedToCA &&
		t.EnrolleeSuppliesSubject &&
		!t.ManagerApprovalRequired &&
		(len(t.EKUs) == 0 || hasAnyEKU(t.EKUs, "Any Purpose"))
}

// IsESC3Vulnerable reports whether t's configuration matches ESC3: it is
// published to a CA and carries the Certificate Request Agent EKU, which
// lets its holder request certificates on behalf of other principals.
func IsESC3Vulnerable(t CertTemplate) bool {
	return t.PublishedToCA && hasAnyEKU(t.EKUs, "Certificate Request Agent")
}

// HasTemplateWriteAccess reports whether principal holds a write-capable
// ACL right (GenericWrite/WriteOwner/WriteDacl) on t itself -- the
// ESC4-relevant configuration fact. Every template has SOME legitimate
// owner with write rights; the caller supplies the specific principal to
// check (e.g. an assessment-controlled identity), since this schema has
// no notion of which principals are "intended" owners versus not.
func HasTemplateWriteAccess(t CertTemplate, principal string) bool {
	return slices.Contains(t.WriteRights, principal)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adenv/... -v`
Expected: PASS — all tests in the package (4 pre-existing plus 4 new).

- [ ] **Step 5: Run gofmt and go vet**

Run: `cd orchestrator && gofmt -l internal/adenv/ && go vet ./internal/adenv/...`
Expected: both print nothing.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adenv/adcs_predicates.go orchestrator/internal/adenv/adcs_predicates_test.go
git commit -m "$(cat <<'EOF'
feat(adenv): add ESC1-4 configuration predicates (AD-M04 sub-phase 2 of 4)

IsESC1Vulnerable/IsESC2Vulnerable/IsESC3Vulnerable/
HasTemplateWriteAccess: pure boolean functions over CertTemplate's
properties (sub-phase 1's enriched ontology), the same kind of check
a certificate-services configuration review already runs. ESC1 vs
ESC2 kept genuinely distinct (explicit client-auth EKU vs Any
Purpose/empty EKU list); manager approval mitigates both; ESC4 is
parameterized by the specific principal to check, since every
template has some legitimate owner with write rights.

No procedural or exploitation content -- configuration predicates
only. Primitive integration (connecting these to adprimitive) is the
next sub-phase.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing preference and the wave/phase process they set for this initiative — no subagent dispatch.** Single task, pure functions over an already-tested schema; proceeding directly to execution via `superpowers:executing-plans`.
