package dbsim

import (
	"strings"
	"testing"
	"time"
)

func TestJobStatusTransitions(t *testing.T) {
	all := []JobStatus{JobPending, JobRunning, JobCompleted, JobFailed, JobPartial, JobCancelled}
	allowed := map[JobStatus][]JobStatus{
		JobPending: {JobRunning, JobFailed, JobCancelled},
		JobRunning: {JobCompleted, JobFailed, JobPartial, JobCancelled},
	}
	for _, from := range all {
		for _, to := range all {
			want := false
			for _, a := range allowed[from] {
				want = want || a == to
			}
			if got := from.CanTransitionTo(to); got != want {
				t.Errorf("%s -> %s = %v, want %v", from, to, got, want)
			}
		}
		if from.Terminal() == from.Active() {
			t.Errorf("%s: Terminal and Active must differ", from)
		}
	}
	if JobStatus("bogus").CanTransitionTo(JobRunning) || JobStatus("bogus").Valid() {
		t.Error("unknown status must be inert and invalid")
	}
}

func TestDeadlineFor(t *testing.T) {
	c := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	if got := DeadlineFor(c, 3); !got.Equal(c.Add(390 * time.Second)) {
		t.Errorf("3 scenarios = %v, want +390s", got.Sub(c))
	}
	if got := DeadlineFor(c, 0); !got.Equal(c.Add(210 * time.Second)) {
		t.Errorf("0 scenarios must budget one: %v", got.Sub(c))
	}
}

func TestJobsSchemaHasPartialUniqueIndexes(t *testing.T) {
	ddl := strings.Join(strings.Fields(strings.Join(JobsSchemaSQL, "\n")), " ")
	for _, w := range []string{"UNIQUE INDEX IF NOT EXISTS dbsim_run_jobs_one_active_target", "(target_id) WHERE status IN ('pending','running')",
		"UNIQUE INDEX IF NOT EXISTS dbsim_run_jobs_one_active_agent", "(agent_id) WHERE status IN ('pending','running')"} {
		if !strings.Contains(ddl, w) {
			t.Errorf("schema lacks %q", w)
		}
	}
	for _, s := range JobsSchemaSQL {
		if !strings.Contains(s, "IF NOT EXISTS") {
			t.Errorf("statement not idempotent: %.60s", s)
		}
	}
}
