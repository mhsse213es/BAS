package scenario

import (
	"strings"
	"testing"
)

func okDBStep() Step {
	return Step{
		Name: "auth check", TechniqueID: "T1078", Executor: "dbprobe",
		DBTarget: "lab-pg", DBProbe: "auth_check",
	}
}

func okDBScenario(steps ...Step) *Scenario {
	return &Scenario{ID: "dbsim-x", Name: "x", ProductLine: "dbsim", Steps: steps}
}

func TestValidateDBProbeStepsAcceptsWellFormed(t *testing.T) {
	if err := okDBScenario(okDBStep()).ValidateDBProbeSteps(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDBProbeStepsRejectsShellBaggage(t *testing.T) {
	cases := map[string]func(*Step){
		"command text": func(s *Step) { s.Command = "select 1" },
		"payload":      func(s *Step) { s.Payloads = []YAMLPayload{{Name: "a", Content: "Yg=="}} },
		"cleanup":      func(s *Step) { s.Cleanup = "drop table x" },
		"host marker":  func(s *Step) { s.Marker = "abcdefgh-1234" },
		"no target":    func(s *Step) { s.DBTarget = "" },
		"no probe":     func(s *Step) { s.DBProbe = "" },
		"bad limits":   func(s *Step) { s.DBLimits = &StepDBLimits{MaxRows: -1, TimeoutSec: 5, MaxConns: 1} },
		"huge limits":  func(s *Step) { s.DBLimits = &StepDBLimits{MaxRows: 1 << 30, TimeoutSec: 5, MaxConns: 1} },
	}
	for name, mut := range cases {
		st := okDBStep()
		mut(&st)
		if err := okDBScenario(st).ValidateDBProbeSteps(); err == nil {
			t.Errorf("%s: dbprobe step accepted", name)
		}
	}
}

func TestValidateDBProbeStepsRequiresDBSimProductLine(t *testing.T) {
	sc := okDBScenario(okDBStep())
	sc.ProductLine = "dlp"
	if err := sc.ValidateDBProbeSteps(); err == nil {
		t.Fatal("dbprobe step accepted in a non-dbsim scenario")
	}
}

func TestDBFieldsWithoutDBProbeExecutorRejected(t *testing.T) {
	st := Step{Name: "x", TechniqueID: "T1078", Executor: "bash", Command: "id", DBTarget: "lab-pg"}
	if err := okDBScenario(st).ValidateDBProbeSteps(); err == nil {
		t.Fatal("db_target on a shell step accepted")
	}
}

func TestDBFixtureFieldIsADBFieldAndShapeChecked(t *testing.T) {
	ok := okDBStep()
	ok.DBFixture = "classified-pii"
	if err := okDBScenario(ok).ValidateDBProbeSteps(); err != nil {
		t.Fatalf("db_fixture on a dbprobe step rejected: %v", err)
	}
	if !stepsUseDBFields([]Step{{DBFixture: "accounts"}}) {
		t.Fatal("db_fixture must count as a db_* field (custom scenarios may not carry it)")
	}
	shell := Step{Name: "x", TechniqueID: "T1078", Executor: "bash", Command: "id", DBFixture: "accounts"}
	if err := okDBScenario(shell).ValidateDBProbeSteps(); err == nil {
		t.Fatal("db_fixture on a shell step accepted")
	}
	for _, bad := range []string{"Accounts", "a b", "../x", "a;b", "x'y", "-lead", strings.Repeat("a", 40), "a/b", "a.b"} {
		st := okDBStep()
		st.DBFixture = bad
		if err := okDBScenario(st).ValidateDBProbeSteps(); err == nil {
			t.Errorf("fixture name %q accepted", bad)
		}
	}
}

func TestCustomSaveRejectsDBProbeSteps(t *testing.T) {
	sc := okDBScenario(okDBStep())
	if err := sc.Validate(); err == nil || !strings.Contains(err.Error(), "dbprobe") {
		t.Fatalf("Validate must refuse dbprobe steps in operator-authored scenarios, got %v", err)
	}
}

func TestBuildStepsRefusesDBProbeWithoutResolver(t *testing.T) {
	if _, _, err := BuildSteps(okDBScenario(okDBStep()), "", "", nil, "linux"); err == nil {
		t.Fatal("BuildSteps built a dbprobe step without a target resolver")
	}
}

func TestDBProbeCatalogClasses(t *testing.T) {
	for _, tech := range []string{"T1078", "T1087", "T1213", "T1562"} {
		for key, want := range map[string]ExecutionClass{
			"dbprobe_read_only":         ClassNonDestructive,
			"dbprobe_bounded_synthetic": ClassPotentiallyDestructive,
			"dbprobe_mutation":          ClassDestructive,
		} {
			if got := ResolveExecutionClass(tech, key).Class; got != want {
				t.Errorf("%s/%s = %s, want %s", tech, key, got, want)
			}
		}
	}
	// Unregistered pair still fails closed.
	if ResolveExecutionClass("T1078", "dbprobe_nonsense").Class != ClassDestructive {
		t.Fatal("unregistered dbprobe action must fail closed")
	}
}
