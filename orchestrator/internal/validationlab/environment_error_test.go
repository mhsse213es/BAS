package validationlab

import "testing"

// A factory validation answers "does this content execute cleanly?" An errored
// step whose ExecutionFailure.owner is "environment" (the lab box lacked a tool,
// a prerequisite, DNS, etc.) is NOT a content defect — it must not FAIL the
// validation. Only owner="audspect" errors (content defect, our-side problem)
// or unattributed errors FAIL. This is what keeps a bare lab box from marking
// good content broken, now that missing-tool/prereq stay ERROR (owner=environment)
// rather than being collapsed to SKIPPED.
func TestClassifyCompletedRun_EnvironmentErrorDoesNotFail(t *testing.T) {
	cases := []struct {
		name, json, want string
	}{
		{"env error + clean exec still passes",
			`[{"result":"pass"},{"result":"error","executionFailure":{"owner":"environment"}}]`, "PASS"},
		{"content defect (audspect) fails",
			`[{"result":"pass"},{"result":"error","executionFailure":{"owner":"audspect"}}]`, "FAIL"},
		{"all environment-blocked, nothing executed -> no data",
			`[{"result":"error","executionFailure":{"owner":"environment"}}]`, "NO_DATA"},
		{"unattributed error is treated as a content error",
			`[{"result":"error"}]`, "FAIL"},
	}
	for _, c := range cases {
		if got, _ := classifyCompletedRun([]byte(c.json)); got != c.want {
			t.Errorf("%s: outcome = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestCountRunResults_SeparatesEnvironmentErrors(t *testing.T) {
	c, ok := countRunResults([]byte(`[
		{"result":"pass"},
		{"result":"error","executionFailure":{"owner":"environment"}},
		{"result":"error","executionFailure":{"owner":"audspect"}},
		{"result":"skipped"}
	]`))
	if !ok {
		t.Fatal("countRunResults ok = false")
	}
	if c.Executed != 1 || c.Errored != 1 || c.EnvErrored != 1 || c.Skipped != 1 {
		t.Errorf("got %+v, want Executed=1 Errored=1 EnvErrored=1 Skipped=1", c)
	}
}
