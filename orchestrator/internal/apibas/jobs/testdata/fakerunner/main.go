// fakerunner is a test stand-in for apibas-runner. It reads the job request named on its command line and behaves as the
// request's fixture field says. Tests use it to drive every outcome the service must handle. It is never built into a product.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/audspect/bas/internal/apibas/runnerproto"
)

func main() {
	reqPath := flag.String("job-request", "", "")
	flag.Parse()
	raw, err := os.ReadFile(*reqPath)
	if err != nil {
		os.Exit(3)
	}
	var req struct {
		SchemaVersion int      `json:"schema_version"`
		JobID         string   `json:"job_id"`
		TargetBaseURL string   `json:"target_base_url"`
		Fixture       string   `json:"fixture"`
		ScenarioIDs   []string `json:"scenario_ids"`
		Credentials   string   `json:"credentials_file"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		os.Exit(3)
	}

	behaviour, arg, _ := strings.Cut(req.Fixture, ":")
	switch behaviour {
	case "complete":
		emit(req.JobID, req.TargetBaseURL, req.ScenarioIDs, "completed", "")
	case "malformed":
		fmt.Print("this is not a result document")
	case "wrong-job":
		emit("some-other-job-id", req.TargetBaseURL, req.ScenarioIDs, "completed", "")
	case "runner-failed":
		emit(req.JobID, req.TargetBaseURL, req.ScenarioIDs, "failed", "fixture refused by runner")
	case "exit-nonzero":
		// A complete-looking document from a process that then exits with an error must not be trusted.
		emit(req.JobID, req.TargetBaseURL, req.ScenarioIDs, "completed", "")
		os.Exit(2)
	case "hang":
		time.Sleep(time.Minute)
	case "env-check":
		if leaked := leakedEnv(); leaked != "" {
			emit(req.JobID, req.TargetBaseURL, req.ScenarioIDs, "failed", "parent environment leaked: "+leaked)
			return
		}
		emit(req.JobID, req.TargetBaseURL, req.ScenarioIDs, "completed", "")
	case "creds-check":
		// arg is a marker file path. Record the credentials file path there, then check the file holds the expected secret.
		if arg != "" {
			_ = os.WriteFile(arg, []byte(req.Credentials), 0o600)
		}
		cred, err := os.ReadFile(req.Credentials)
		if err != nil || !strings.Contains(string(cred), "expected-secret-value") {
			emit(req.JobID, req.TargetBaseURL, req.ScenarioIDs, "failed", "credentials missing or wrong")
			return
		}
		emit(req.JobID, req.TargetBaseURL, req.ScenarioIDs, "completed", "")
	default:
		os.Exit(3)
	}
}

// leakedEnv names any variable the parent set for the test and the child must not see.
func leakedEnv() string {
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "APIBAS_TEST_PARENT_SECRET=") {
			return "APIBAS_TEST_PARENT_SECRET"
		}
	}
	return ""
}

func emit(jobID, target string, scenarios []string, status, reason string) {
	type outcome struct {
		Result, Exploitability, Control, Detection, Reason string
	}
	type report struct {
		ScenarioID string
		RunTag     string
		Outcome    outcome
	}
	doc := map[string]any{
		"schema_version":  runnerproto.SchemaVersion,
		"job_id":          jobID,
		"target_base_url": target,
		"status":          status,
		"scenario_ids":    scenarios,
	}
	if status == "completed" {
		reps := make([]report, 0, len(scenarios))
		for _, s := range scenarios {
			reps = append(reps, report{ScenarioID: s, RunTag: "tag-" + s,
				Outcome: outcome{Result: "FAIL", Exploitability: "exploitable", Control: "absent", Detection: "missed", Reason: "fixture"}})
		}
		doc["reports"] = reps
	} else {
		doc["error"] = reason
	}
	out, _ := json.Marshal(doc)
	fmt.Print(string(out))
	if status == "failed" {
		os.Exit(1)
	}
}
