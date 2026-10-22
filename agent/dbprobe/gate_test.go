package dbprobe

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

// registerTestProbe temporarily adds a probe to the catalog so non-read-only
// classes can be exercised. Test-only and unexported; removed on cleanup.
func registerTestProbe(t *testing.T, id string, class ProbeClass) ProbeDef {
	t.Helper()
	if _, exists := catalog[id]; exists {
		t.Fatalf("test probe %q collides with a real probe", id)
	}
	def := ProbeDef{ID: id, Class: class, Engines: []string{"postgresql", "mysql"}, ParamSchema: map[string]ParamKind{}}
	catalog[id] = def
	t.Cleanup(func() { delete(catalog, id) })
	return def
}

func specFor(probeID string, mode ExecMode) DBProbeSpec {
	s := validSpec()
	s.ProbeID = probeID
	s.Mode = mode
	return s
}

var (
	clientOn  = Policy{ClientEnabled: true}
	labMutOK  = Policy{LabMutationAllowed: true}
	noPolicy  = Policy{}
	bothFlags = Policy{ClientEnabled: true, LabMutationAllowed: true}
)

func TestCheckSpecRejectsIdentityMismatch(t *testing.T) {
	def, _ := LookupProbe("read_roles")
	s := validSpec()
	if err := CheckSpec(s, def, "7001", "7002", noPolicy); err == nil {
		t.Fatal("identity mismatch must be rejected")
	}
	if err := CheckSpec(s, def, "7001 ", "7001", noPolicy); err == nil {
		t.Fatal("identity compare must be exact")
	}
	if err := CheckSpec(s, def, "7001", "7001", noPolicy); err != nil {
		t.Fatalf("matching identity in lab mode must pass for read-only probe: %v", err)
	}
}

func TestCheckSpecRejectsEmptyIdentityInEveryMode(t *testing.T) {
	def, _ := LookupProbe("read_roles")
	for _, mode := range []ExecMode{ModeLab, ModeClient} {
		if err := CheckSpec(specFor("read_roles", mode), def, "", "", bothFlags); err == nil {
			t.Fatalf("empty observed == empty expected must not pass in %s mode", mode)
		}
		if err := CheckSpec(specFor("read_roles", mode), def, "", "7001", bothFlags); err == nil {
			t.Fatalf("empty observed must not pass in %s mode", mode)
		}
		if err := CheckSpec(specFor("read_roles", mode), def, "7001", "", bothFlags); err == nil {
			t.Fatalf("empty expected must not pass in %s mode", mode)
		}
	}
}

func TestCheckSpecRejectsUnknownProbeInEveryMode(t *testing.T) {
	forged := ProbeDef{ID: "x", Class: ClassReadOnly, Engines: []string{"postgresql"}}
	for _, mode := range []ExecMode{ModeLab, ModeClient} {
		if err := CheckSpec(specFor("x", mode), forged, "7001", "7001", bothFlags); err == nil {
			t.Fatalf("forged unknown probe id must be rejected in %s mode", mode)
		}
	}
}

func TestCheckSpecClientModeRejectsMutationProbe(t *testing.T) {
	def := registerTestProbe(t, "t_mut", ClassMutation)
	if err := CheckSpec(specFor("t_mut", ModeClient), def, "7001", "7001", bothFlags); err == nil {
		t.Fatal("client mode must reject mutation probe")
	}
}

func TestCheckSpecClientModeRejectsBoundedSyntheticProbe(t *testing.T) {
	def := registerTestProbe(t, "t_bounded", ClassBoundedSynthetic)
	if err := CheckSpec(specFor("t_bounded", ModeClient), def, "7001", "7001", bothFlags); err == nil {
		t.Fatal("client mode must reject bounded_synthetic probe")
	}
}

func TestCheckSpecClientModeRejectsMislabelledScenarioByProbeID(t *testing.T) {
	for _, class := range []ProbeClass{ClassMutation, ClassBoundedSynthetic} {
		id := "t_real_" + string(class)
		registerTestProbe(t, id, class)
		// The scenario/def claims read_only for a probe whose real class is not.
		label := ProbeDef{ID: id, Class: ClassReadOnly, Engines: []string{"postgresql"}}
		err := CheckSpec(specFor(id, ModeClient), label, "7001", "7001", bothFlags)
		if err == nil {
			t.Fatalf("mislabelled %s probe must be rejected", class)
		}
		// Even with a truthful def, the catalog class decides.
		real, _ := LookupProbe(id)
		err = CheckSpec(specFor(id, ModeClient), real, "7001", "7001", bothFlags)
		if err == nil || !strings.Contains(err.Error(), string(class)) {
			t.Fatalf("want rejection citing real class %s, got %v", class, err)
		}
	}
	other, _ := LookupProbe("auth_check")
	if err := CheckSpec(specFor("read_roles", ModeClient), other, "7001", "7001", clientOn); err == nil {
		t.Fatal("def/spec probe id mismatch must be rejected")
	}
}

func TestCheckSpecLabModeMutationNeedsLocalAllow(t *testing.T) {
	for _, class := range []ProbeClass{ClassMutation, ClassBoundedSynthetic} {
		id := "t_lab_" + string(class)
		def := registerTestProbe(t, id, class)
		if err := CheckSpec(specFor(id, ModeLab), def, "7001", "7001", noPolicy); err == nil {
			t.Fatalf("lab %s probe must be refused without the agent-local allow flag", class)
		}
		if err := CheckSpec(specFor(id, ModeLab), def, "7001", "7001", clientOn); err == nil {
			t.Fatalf("clientEnabled must not authorise lab %s probe", class)
		}
		if err := CheckSpec(specFor(id, ModeLab), def, "7001", "7001", labMutOK); err != nil {
			t.Fatalf("lab %s probe with local allow must pass: %v", class, err)
		}
	}
}

func TestCheckSpecRejectsEmptyAndUnknownMode(t *testing.T) {
	def, _ := LookupProbe("read_roles")
	for _, m := range []ExecMode{"", "prod", "LAB"} {
		if err := CheckSpec(specFor("read_roles", m), def, "7001", "7001", bothFlags); err == nil {
			t.Fatalf("mode %q must be refused", m)
		}
	}
}

func TestCheckSpecClientModeRequiresEnabledAndRegisteredIdentity(t *testing.T) {
	def, _ := LookupProbe("read_roles")
	s := specFor("read_roles", ModeClient)
	if err := CheckSpec(s, def, "7001", "7001", noPolicy); err == nil {
		t.Fatal("client mode must be refused when not enabled")
	}
	if err := CheckSpec(s, def, "7001", "", clientOn); err == nil {
		t.Fatal("client mode must not trust-on-first-use (empty expected identity)")
	}
	if err := CheckSpec(s, def, "7001", "7001", clientOn); err != nil {
		t.Fatalf("enabled client read-only with matching identity must pass: %v", err)
	}
}

func TestBudgetChargeExceedsMaxRows(t *testing.T) {
	b := NewBudget(Limits{MaxRows: 10, TimeoutSec: 5, MaxConns: 1})
	if err := b.Charge(6); err != nil {
		t.Fatal(err)
	}
	if err := b.Charge(4); err != nil {
		t.Fatalf("exactly at limit must pass: %v", err)
	}
	if err := b.Charge(1); err == nil {
		t.Fatal("exceeding max rows must fail")
	}
	if err := NewBudget(Limits{MaxRows: 10}).Charge(-1); err == nil {
		t.Fatal("negative charge must fail")
	}
}

func TestBudgetChargeOverflowIsRejected(t *testing.T) {
	b := NewBudget(Limits{MaxRows: math.MaxInt})
	if err := b.Charge(math.MaxInt - 1); err != nil {
		t.Fatal(err)
	}
	if err := b.Charge(math.MaxInt); err == nil {
		t.Fatal("charge that would wrap used+rows must fail")
	}
	if err := b.Charge(2); err == nil {
		t.Fatal("charge past MaxInt total must fail")
	}
	if b.Used() != math.MaxInt-1 {
		t.Fatalf("failed charges must not be recorded, used=%d", b.Used())
	}
}

func TestWithDeadlineUsesTimeoutSec(t *testing.T) {
	ctx, cancel := WithDeadline(context.Background(), Limits{MaxRows: 1, TimeoutSec: 30, MaxConns: 1})
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) > 40*time.Second || time.Until(dl) < 5*time.Second {
		t.Fatalf("deadline not roughly 30s out: %v %v", dl, ok)
	}
}

func TestWithDeadlineNonPositiveTimeoutIsExpired(t *testing.T) {
	for _, sec := range []int{0, -5} {
		ctx, cancel := WithDeadline(context.Background(), Limits{MaxRows: 1, TimeoutSec: sec, MaxConns: 1})
		if ctx.Err() == nil {
			t.Fatalf("TimeoutSec=%d must yield an already-expired context", sec)
		}
		cancel()
	}
}
