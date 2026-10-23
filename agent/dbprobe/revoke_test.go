package dbprobe

import (
	"regexp"
	"strings"
	"testing"
)

func TestTask14ProbesAreCataloged(t *testing.T) {
	ar, ok := LookupProbe(ProbeAuthAfterRevoke)
	if !ok || ar.Class != ClassBoundedSynthetic || ar.RequiredFixture != RevokeFixtureKind || len(ar.ParamSchema) != 0 || ar.FixtureParam != "" {
		t.Fatalf("auth_after_revoke: %+v ok=%v", ar, ok)
	}
	rc, ok := LookupProbe(ProbeReadClassifiedFixture)
	if !ok || rc.Class != ClassBoundedSynthetic || rc.RequiredFixture != ClassifiedFixtureKind || rc.FixedTable != ClassifiedFixtureTable ||
		len(rc.ParamSchema) != 0 || rc.FixtureParam != "" {
		t.Fatalf("read_classified_fixture: %+v ok=%v", rc, ok)
	}
	for _, d := range []ProbeDef{ar, rc} {
		if len(d.Engines) != 2 {
			t.Errorf("%s must support both engines: %v", d.ID, d.Engines)
		}
	}
}

func TestRequiredFixtureProbesNeedExactlyTheirFixtureInLabMode(t *testing.T) {
	for _, c := range []struct{ probe, fixture string }{
		{ProbeAuthAfterRevoke, RevokeFixtureKind},
		{ProbeReadClassifiedFixture, ClassifiedFixtureKind},
	} {
		s := validSpec()
		s.ProbeID, s.Mode, s.FixtureID = c.probe, ModeLab, c.fixture
		if err := ValidateSpec(s); err != nil {
			t.Fatalf("%s: valid spec rejected: %v", c.probe, err)
		}
		bad := s
		bad.FixtureID = ""
		if ValidateSpec(bad) == nil {
			t.Errorf("%s without a fixture id accepted", c.probe)
		}
		bad = s
		bad.FixtureID = "accounts"
		if ValidateSpec(bad) == nil {
			t.Errorf("%s with the wrong fixture accepted", c.probe)
		}
		bad = s
		bad.Mode = ModeClient
		if ValidateSpec(bad) == nil {
			t.Errorf("%s in client mode accepted", c.probe)
		}
		bad = s
		bad.Params = map[string]string{"table": "customers_pii"}
		if ValidateSpec(bad) == nil {
			t.Errorf("%s accepted a free-form table param", c.probe)
		}
	}
}

func TestTask14ProbesGate(t *testing.T) {
	all := Policy{ClientEnabled: true, LabMutationAllowed: true}
	for _, c := range []struct{ probe, fixture string }{
		{ProbeAuthAfterRevoke, RevokeFixtureKind},
		{ProbeReadClassifiedFixture, ClassifiedFixtureKind},
	} {
		d, _ := LookupProbe(c.probe)
		s := validSpec()
		s.ProbeID, s.Mode, s.FixtureID = c.probe, ModeLab, c.fixture
		if err := CheckSpec(s, d, "7001", "7001", Policy{}); err == nil {
			t.Errorf("%s: lab mode without the agent-local mutation allowance accepted", c.probe)
		}
		if err := CheckSpec(s, d, "7001", "7001", Policy{LabMutationAllowed: true}); err != nil {
			t.Errorf("%s: lab + allowance refused: %v", c.probe, err)
		}
		s.Mode = ModeClient
		if err := CheckSpec(s, d, "7001", "7001", all); err == nil {
			t.Errorf("%s: client mode accepted", c.probe)
		}
	}
}

func TestFixtureTableFor(t *testing.T) {
	sr, _ := LookupProbe(ProbeSuspiciousRead)
	if got := FixtureTableFor(sr, DBProbeSpec{Params: map[string]string{"table": "accounts"}}); got != "accounts" {
		t.Errorf("param probe: %q", got)
	}
	rc, _ := LookupProbe(ProbeReadClassifiedFixture)
	// A param must never override the fixed table.
	if got := FixtureTableFor(rc, DBProbeSpec{Params: map[string]string{"table": "other"}}); got != ClassifiedFixtureTable {
		t.Errorf("fixed table probe: %q", got)
	}
	if got := FixtureTableFor(ProbeDef{}, DBProbeSpec{Params: map[string]string{"table": "x"}}); got != "" {
		t.Errorf("a probe without a fixture table must resolve nothing: %q", got)
	}
	if !IsFixtureRead(sr) || !IsFixtureRead(rc) {
		t.Error("both read probes are fixture reads")
	}
	ar, _ := LookupProbe(ProbeAuthAfterRevoke)
	if IsFixtureRead(ar) {
		t.Error("auth_after_revoke reads no fixture table")
	}
	if FixtureReadRowCap(ProbeReadClassifiedFixture, 100) != SuspiciousReadMaxRows {
		t.Error("read_classified_fixture is hard capped at 25 rows")
	}
}

func TestActiveFixtureCurrent(t *testing.T) {
	var a ActiveFixture
	if _, err := a.Current(); err == nil {
		t.Fatal("no fixture bound must fail closed")
	}
	if err := a.BindFixture(fixtureWith("customers_pii")); err != nil {
		t.Fatal(err)
	}
	f, err := a.Current()
	if err != nil || f.ID != "abc123def456" {
		t.Fatalf("%+v %v", f, err)
	}
	a.UnbindFixture()
	if _, err := a.Current(); err == nil {
		t.Fatal("unbound fixture must fail closed")
	}
}

func TestThrowawayPassword(t *testing.T) {
	a, err := NewThrowawayPassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewThrowawayPassword()
	if a == b || len(a) < 32 || !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(a) {
		t.Fatalf("password must be long, random, hex-only: %q %q", a, b)
	}
}

func TestThrowawayAccountName(t *testing.T) {
	n, err := ThrowawayAccountName("abc123def456")
	if err != nil || n != "dbsim_abc123def456_acct" {
		t.Fatalf("%q %v", n, err)
	}
	if len(n) > 32 {
		t.Fatalf("must fit MySQL's 32 character user limit: %q", n)
	}
	for _, bad := range []string{"", "a'b", "a b", "a;drop", strings.Repeat("a", 21), "a%"} {
		if _, err := ThrowawayAccountName(bad); err == nil {
			t.Errorf("fixture id %q accepted", bad)
		}
	}
	// Same normalisation as the adapters' fixture names.
	if n, err := ThrowawayAccountName("Ab-12"); err != nil || n != "dbsim_ab_12_acct" {
		t.Errorf("normalisation: %q %v", n, err)
	}
}

func TestRevokeStepsNote(t *testing.T) {
	got := RevokeStepsNote(RevokeStepOK, RevokeStepOK, RevokeStepOK, RevokeReconnectDenied)
	if got != "revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied" {
		t.Fatal(got)
	}
	if !strings.HasPrefix(RevokeStepsNote(RevokeStepFailed, RevokeStepSkipped, RevokeStepSkipped, RevokeStepSkipped), "revoke_steps=create=failed,baseline=skipped") {
		t.Fatal("skipped steps are reported, not omitted")
	}
}
