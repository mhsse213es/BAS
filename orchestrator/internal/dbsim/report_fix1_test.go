package dbsim

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dlpreport"
)

// Fix round 1 tests (written before the fixes).

func TestDetectionPassesOnlyOnExactOrStrongMatch(t *testing.T) {
	for _, m := range []MatchGrade{"", "bogus", "EXACT_MARKER", "Exact_Marker", MatchAmbiguous, MatchNone} {
		o := denied()
		o.Corr.Match = m
		if got := ToRunResult(meta(), o); got == ResultPass {
			t.Errorf("match %q graded PASS", m)
		}
		r, err := ToRecord(meta(), o)
		if err != nil {
			t.Fatal(err)
		}
		want := "none"
		if m == MatchAmbiguous {
			want = "ambiguous"
		}
		if r.Confidence != want {
			t.Errorf("match %q: confidence %q, want %q", m, r.Confidence, want)
		}
	}
	for _, m := range []MatchGrade{MatchExactMarker, MatchStrongContextual} {
		o := denied()
		o.Corr.Match = m
		if got := ToRunResult(meta(), o); got != ResultPass {
			t.Errorf("match %q graded %s, want PASS", m, got)
		}
		r, _ := ToRecord(meta(), o)
		if r.Confidence != string(m) {
			t.Errorf("confidence %q for %q", r.Confidence, m)
		}
	}
}

func TestRedactSecretShapes(t *testing.T) {
	secrets := []string{
		"db_password=Zx1", "PGPASSWORD=Zx2", "access_token=Zx3", "client_secret=Zx4", "api_key=Zx5",
		"apikey: Zx6", `{"password":"Zx7"}`, `{"secret": "Zx8 Zx8b"}`, "password: 'Zx9'",
		`password = "Za Zb Zc"`, "Authorization: Bearer Zq.Zr.Zs", "sent Bearer ZtokenZ now",
		"postgres://user:Zp@ssZ@host/db", "mysql://u:ZpwZ@tcp(h:3306)/d", "mysql -p'ZcliZ' -h x",
		"psql --password=ZlongZ", "mysql -pZshortZ",
	}
	for _, s := range secrets {
		out := redact("ctx " + s + " end")
		for _, frag := range []string{"Zx", "Za Zb", "Zq", "ZtokenZ", "Zp@ssZ", "ZpwZ", "ZcliZ", "ZlongZ", "ZshortZ", "Za", "Zb", "Zc"} {
			if strings.Contains(out, frag) && strings.Contains(s, frag) {
				t.Errorf("%q -> %q still contains %q", s, out, frag)
			}
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("%q not redacted: %q", s, out)
		}
	}
	// Negative control: ordinary prose is untouched. Intentionally
	// over-redacted: any "<key-with-password/secret/token/...> [:=] value"
	// even if benign, and "-p<word>" CLI-looking tokens.
	for _, s := range []string{"password policy enforced", "passwords expire in 90 days", "the token bucket is full"} {
		if got := redact(s); got != s {
			t.Errorf("mangled %q -> %q", s, got)
		}
	}
}

func TestRedactAdversarialInputIsFast(t *testing.T) {
	inputs := []string{
		strings.Repeat("password", 12500),
		strings.Repeat("a", 100000),
		"://" + strings.Repeat("u:", 50000),
		"password=" + strings.Repeat(" ", 100000),
		strings.Repeat("@", 100000),
	}
	start := time.Now()
	for _, in := range inputs {
		redact(in)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("redaction took %v", d)
	}
}

func TestRedactAppliesToEveryStoredFreeText(t *testing.T) {
	o := succeeded()
	o.ExecutionError = "e password=SECRETE1"
	o.Skipped = "s password=SECRETS1"
	o.GateRefusal = "g password=SECRETG1"
	o.Probe.ErrorClass = "c password=SECRETC1"
	o.Probe.Notes = []string{"n password=SECRETN1"}
	o.Principal = "p password=SECRETP1"
	o.Corr.Limitations = "l password=SECRETL1"
	m := meta()
	m.ControlObjective, m.Preconditions, m.SyntheticDataManifest, m.ActionAttempted =
		"co password=SECRETA1", "pre password=SECRETA2", "syn password=SECRETA3", "act password=SECRETA4"
	rep, err := BuildReport(m, o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := rep.JSON()
	if strings.Contains(string(b), "SECRET") {
		t.Fatalf("leak: %s", b)
	}
}

func TestProbeRanWithSkipOrGateRefusalIsErrorNotSkipped(t *testing.T) {
	for _, mod := range []func(*Outcome){
		func(o *Outcome) { o.Skipped = "audit plugin missing" },
		func(o *Outcome) { o.GateRefusal = "out of scope" },
	} {
		o := denied()
		mod(&o)
		if got := ToRunResult(meta(), o); got != ResultError {
			t.Errorf("got %s, want ERROR", got)
		}
		r, err := ToRecord(meta(), o)
		if err != nil || !strings.Contains(r.Limitations, "probe ran") {
			t.Errorf("limitations %q err %v", r.Limitations, err)
		}
	}
}

func TestUnknownExpectedPreventionIsError(t *testing.T) {
	for _, v := range []string{"Deny", "block", "DENY", " deny"} {
		m := meta()
		m.ExpectedPrevention = v
		if got := ToRunResult(m, denied()); got != ResultError {
			t.Errorf("%q graded %s, want ERROR", v, got)
		}
	}
}

func TestDeniedWithNonDenialErrorClassIsUnknownNotBlocked(t *testing.T) {
	for _, ec := range []string{"timeout", "canceled", "mysql_error_2003", "connection_refused"} {
		o := denied()
		o.Probe = DBProbeResult{Denied: true, ErrorClass: ec}
		r, err := ToRecord(meta(), o)
		if err != nil {
			t.Fatal(err)
		}
		if r.Enforcement != dlpreport.EnforcementUnknown {
			t.Errorf("%s: enforcement %s", ec, r.Enforcement)
		}
		if got := ToRunResult(meta(), o); got != ResultError {
			t.Errorf("%s: graded %s, want ERROR", ec, got)
		}
	}
	for _, ec := range []string{"", "permission_denied", "auth_failed"} {
		o := denied()
		o.Probe = DBProbeResult{Denied: true, ErrorClass: ec}
		if r, _ := ToRecord(meta(), o); r.Enforcement != dlpreport.EnforcementBlocked {
			t.Errorf("%q: enforcement %s", ec, r.Enforcement)
		}
	}
}

func TestRowLimitExceededIsAllowed(t *testing.T) {
	o := denied()
	o.Probe = DBProbeResult{RowsRead: 5, ErrorClass: "row_limit_exceeded"}
	if r, _ := ToRecord(meta(), o); r.Enforcement != dlpreport.EnforcementAllowed {
		t.Fatalf("enforcement %s", r.Enforcement)
	}
	if got := ToRunResult(meta(), o); got != ResultFail {
		t.Fatalf("deny expectation graded %s, want FAIL", got)
	}
	m := meta()
	m.ExpectedPrevention = "allow"
	if got := ToRunResult(m, o); got != ResultPass {
		t.Fatalf("allow expectation graded %s, want PASS", got)
	}
}
