package dbbuild

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

var fixedNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func labTarget() dbsim.Target {
	return dbsim.Target{
		ID: "lab-db", Engine: "postgresql", Host: "10.20.30.40", Port: 5432, Database: "appdb",
		TLSMode: "require", CredentialRef: "dbcred:lab-pg", Mode: dbsim.ModeLab,
		ExpectedIdentity: "7312345678901234567", LabConfirmed: true, AgentID: "0123456789abcdef",
	}
}

func opts(ts ...dbsim.Target) Options {
	return Options{
		Resolver:  dbsim.NewMemoryResolver(ts...),
		RunExpiry: fixedNow.Add(time.Hour),
		Now:       func() time.Time { return fixedNow },
	}
}

func oneStepScenario(probe string, params map[string]string) *scenario.Scenario {
	return &scenario.Scenario{ID: "dbsim-t", Name: "t", ProductLine: "dbsim", Steps: []scenario.Step{{
		Name: "s1", TechniqueID: "T1078", Executor: "dbprobe", DBTarget: "lab-db", DBProbe: probe, DBParams: params,
	}}}
}

var (
	markerRe = regexp.MustCompile(`^bas-dbsim:[A-Za-z0-9._:-]+$`)
	runIDRe  = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

// The emitted step must satisfy the exact rules the agent enforces
// (agent/exec_dbprobe.go dbprobeStepShapeRefusal, expectedExecClass, and
// dbprobe.ValidateSpec); this test re-states them field by field.
func TestBuildEmitsStepTheAgentAccepts(t *testing.T) {
	steps, err := BuildSteps(context.Background(), oneStepScenario("auth_check", nil), opts(labTarget()))
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 {
		t.Fatalf("steps = %d", len(steps))
	}
	st := steps[0]
	if st.Executor != "dbprobe" {
		t.Errorf("Executor = %q, want exactly dbprobe", st.Executor)
	}
	if st.Command != "auth_check" {
		t.Errorf("Command = %q, want the probe id", st.Command)
	}
	if len(st.Payloads) != 0 || st.Cleanup != "" {
		t.Errorf("payloads %v / cleanup %q must be empty", st.Payloads, st.Cleanup)
	}
	if st.ExecutionClass != scenario.ClassNonDestructive {
		t.Errorf("ExecutionClass = %q, want non_destructive for a read_only probe", st.ExecutionClass)
	}
	// Wire form: no shell baggage keys at all.
	wire, _ := json.Marshal(st)
	for _, k := range []string{`"payloads"`, `"cleanup"`} {
		if bytes.Contains(wire, []byte(k)) {
			t.Errorf("wire step carries %s: %s", k, wire)
		}
	}
	// The spec decodes strictly into the mirror type and carries every field
	// ValidateSpec / CheckSpec need.
	var spec dbsim.DBProbeSpec
	dec := json.NewDecoder(bytes.NewReader(st.DBProbe))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		t.Fatalf("spec does not decode strictly: %v (%s)", err, st.DBProbe)
	}
	if spec.ProbeID != st.Command {
		t.Errorf("spec.ProbeID %q != Command %q", spec.ProbeID, st.Command)
	}
	if spec.Engine != "postgresql" || spec.TargetID != "lab-db" || spec.Host != "10.20.30.40" || spec.Port != 5432 ||
		spec.Database != "appdb" || spec.TLSMode != "require" || spec.ExpectedIdentity != "7312345678901234567" ||
		spec.Mode != dbsim.ModeLab {
		t.Errorf("spec target fields not taken from the registry: %+v", spec)
	}
	if !strings.HasPrefix(spec.CredentialRef, "dbcred:") {
		t.Errorf("CredentialRef = %q", spec.CredentialRef)
	}
	if !markerRe.MatchString(spec.Marker) || len(spec.Marker) > 63 {
		t.Errorf("Marker %q outside the sanitizer alphabet / prefix / length", spec.Marker)
	}
	if spec.RunID == "" || !runIDRe.MatchString(spec.RunID) {
		t.Errorf("RunID %q", spec.RunID)
	}
	if spec.Limits.MaxRows <= 0 || spec.Limits.TimeoutSec <= 0 || spec.Limits.MaxConns <= 0 {
		t.Errorf("limits must all be > 0: %+v", spec.Limits)
	}
	// Every wire key emitted is a key of the golden vector (the agent's shape).
	golden, err := os.ReadFile("../testdata/dbprobe_spec.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var gk, sk map[string]json.RawMessage
	if err := json.Unmarshal(golden, &gk); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(st.DBProbe, &sk); err != nil {
		t.Fatal(err)
	}
	for k := range sk {
		if _, ok := gk[k]; !ok {
			t.Errorf("emitted key %q is not in the agent golden vector", k)
		}
	}
	for _, k := range []string{"engine", "probeId", "targetId", "host", "port", "expectedIdentity", "credentialRef", "runId", "marker", "mode", "limits"} {
		if _, ok := sk[k]; !ok {
			t.Errorf("required key %q missing from emitted spec", k)
		}
	}
}

func TestBuildUnknownTargetIsAnError(t *testing.T) {
	sc := oneStepScenario("auth_check", nil)
	sc.Steps[0].DBTarget = "nope"
	steps, err := BuildSteps(context.Background(), sc, opts(labTarget()))
	if err == nil || steps != nil {
		t.Fatalf("unknown target built: %v %v", steps, err)
	}
}

func TestBuildUnknownProbeAndUndeclaredParamAreErrors(t *testing.T) {
	if _, err := BuildSteps(context.Background(), oneStepScenario("drop_everything", nil), opts(labTarget())); err == nil {
		t.Fatal("unknown probe built")
	}
	if _, err := BuildSteps(context.Background(), oneStepScenario("auth_check", map[string]string{"sql": "select 1"}), opts(labTarget())); err == nil {
		t.Fatal("undeclared param built")
	}
}

func TestBuildClientModeNeedsEnableAndVerifiedReadOnlyIdentity(t *testing.T) {
	c := labTarget()
	c.Mode = dbsim.ModeClient
	c.LabConfirmed = false
	c.ReadOnlyIdentityVerified = false
	o := opts(c)
	o.ClientGate = dbsim.StaticClientGate(true)
	if _, err := BuildSteps(context.Background(), oneStepScenario("auth_check", nil), o); err == nil {
		t.Fatal("client target without verified read-only identity built")
	}
	c.ReadOnlyIdentityVerified = true
	o = opts(c) // ClientGate nil (default off)
	if _, err := BuildSteps(context.Background(), oneStepScenario("auth_check", nil), o); err == nil {
		t.Fatal("client mode built while disabled")
	}
	o.ClientGate = dbsim.StaticClientGate(true)
	if _, err := BuildSteps(context.Background(), oneStepScenario("auth_check", nil), o); err != nil {
		t.Fatalf("fully authorised client target refused: %v", err)
	}
}

func TestBuildRefusesMissingExpiryAndMissingIdentityAndBadCredentialRef(t *testing.T) {
	o := opts(labTarget())
	o.RunExpiry = time.Time{}
	if _, err := BuildSteps(context.Background(), oneStepScenario("auth_check", nil), o); err == nil {
		t.Fatal("built without a run expiry")
	}
	noID := labTarget()
	noID.ExpectedIdentity = ""
	if _, err := BuildSteps(context.Background(), oneStepScenario("auth_check", nil), opts(noID)); err == nil {
		t.Fatal("built for a target with no registered identity")
	}
	for _, ref := range []string{"", "plain-password", "dbcred:"} {
		bad := labTarget()
		bad.CredentialRef = ref
		if _, err := BuildSteps(context.Background(), oneStepScenario("auth_check", nil), opts(bad)); err == nil {
			t.Fatalf("built with credential ref %q", ref)
		}
	}
}

// The resolver is the only source of target facts: a scenario cannot supply or
// override identity, host or mode (there is no field for it), and a step that
// tries to smuggle one is rejected by the validator.
func TestResolverSuppliesIdentityYAMLCannotOverride(t *testing.T) {
	var sc scenario.Scenario
	if err := yamlUnmarshal([]byte(`
id: dbsim-t
name: t
product_line: dbsim
steps:
  - name: s1
    technique_id: T1078
    executor: dbprobe
    db_target: lab-db
    db_probe: auth_check
    expected_identity: attacker-chosen
    host: evil.example
    mode: client
`), &sc); err != nil {
		t.Fatal(err)
	}
	steps, err := BuildSteps(context.Background(), &sc, opts(labTarget()))
	if err != nil {
		t.Fatal(err)
	}
	var spec dbsim.DBProbeSpec
	if err := json.Unmarshal(steps[0].DBProbe, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.ExpectedIdentity != "7312345678901234567" || spec.Host != "10.20.30.40" || spec.Mode != dbsim.ModeLab {
		t.Fatalf("YAML influenced target facts: %+v", spec)
	}
}

func TestEveryDispatchGetsAFreshMarkerAndRunID(t *testing.T) {
	sc := &scenario.Scenario{ID: "dbsim-t", Name: "t", ProductLine: "dbsim", Steps: []scenario.Step{
		{Name: "a", TechniqueID: "T1078", Executor: "dbprobe", DBTarget: "lab-db", DBProbe: "auth_check"},
		{Name: "b", TechniqueID: "T1087", Executor: "dbprobe", DBTarget: "lab-db", DBProbe: "read_roles"},
	}}
	seen := map[string]bool{}
	runs := map[string]bool{}
	for i := 0; i < 50; i++ {
		steps, err := BuildSteps(context.Background(), sc, opts(labTarget()))
		if err != nil {
			t.Fatal(err)
		}
		var runID string
		for _, st := range steps {
			var spec dbsim.DBProbeSpec
			if err := json.Unmarshal(st.DBProbe, &spec); err != nil {
				t.Fatal(err)
			}
			if seen[spec.Marker] {
				t.Fatalf("marker %q reused", spec.Marker)
			}
			seen[spec.Marker] = true
			if runID != "" && runID != spec.RunID {
				t.Fatalf("steps of one dispatch disagree on RunID")
			}
			runID = spec.RunID
		}
		if runs[runID] {
			t.Fatalf("run id %q reused across dispatches", runID)
		}
		runs[runID] = true
	}
}

func TestBuildRefusesNonDBProbeStepsInDBSimScenario(t *testing.T) {
	sc := oneStepScenario("auth_check", nil)
	sc.Steps = append(sc.Steps, scenario.Step{Name: "sh", TechniqueID: "T1059", Executor: "bash", Command: "id"})
	if _, err := BuildSteps(context.Background(), sc, opts(labTarget())); err == nil {
		t.Fatal("mixed scenario built")
	}
}
