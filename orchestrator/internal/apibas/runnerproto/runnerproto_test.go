package runnerproto

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/runner"
)

const goodRequest = `{
  "schema_version": 1,
  "job_id": "job-20261104-0001",
  "target_base_url": "http://127.0.0.1:8099",
  "fixture": "orders-two-tenant",
  "scenario_ids": ["API-BAS-AUTHZ-001"],
  "credentials_file": "/run/apibas/job.json"
}`

func validReq(t *testing.T) JobRequest {
	t.Helper()
	req, err := DecodeJobRequest(strings.NewReader(goodRequest))
	if err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	return req
}

func TestDecodeJobRequestAcceptsValid(t *testing.T) {
	validReq(t)
}

func TestDecodeJobRequestRefusesBadInput(t *testing.T) {
	cases := map[string]string{
		"unknown field":     strings.Replace(goodRequest, `"fixture"`, `"fixture_typo_scope": "x", "fixture"`, 1),
		"wrong schema":      strings.Replace(goodRequest, `"schema_version": 1`, `"schema_version": 2`, 1),
		"bad job id":        strings.Replace(goodRequest, "job-20261104-0001", "../etc", 1),
		"non-http target":   strings.Replace(goodRequest, "http://127.0.0.1:8099", "file:///etc/passwd", 1),
		"no scenarios":      strings.Replace(goodRequest, `["API-BAS-AUTHZ-001"]`, `[]`, 1),
		"repeated scenario": strings.Replace(goodRequest, `["API-BAS-AUTHZ-001"]`, `["API-BAS-AUTHZ-001","API-BAS-AUTHZ-001"]`, 1),
		"no credentials":    strings.Replace(goodRequest, `"/run/apibas/job.json"`, `""`, 1),
	}
	for name, body := range cases {
		if _, err := DecodeJobRequest(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func completedFor(req JobRequest) JobResult {
	reps := make([]runner.Report, len(req.ScenarioIDs))
	for i, id := range req.ScenarioIDs {
		reps[i] = runner.Report{ScenarioID: id, RunTag: "tag-" + id}
	}
	return JobResult{SchemaVersion: SchemaVersion, JobID: req.JobID, TargetBaseURL: req.TargetBaseURL,
		Status: StatusCompleted, ScenarioIDs: req.ScenarioIDs, Reports: reps}
}

func TestValidateResultAcceptsMatchingCompletion(t *testing.T) {
	req := validReq(t)
	if err := ValidateResult(req, completedFor(req)); err != nil {
		t.Fatalf("matching result refused: %v", err)
	}
}

// A crash or a malformed document must never become a successful run.
func TestValidateResultRefusesFalseSuccess(t *testing.T) {
	req := validReq(t)
	base := completedFor(req)

	mismatchJob := base
	mismatchJob.JobID = "job-other-0002"

	mismatchTarget := base
	mismatchTarget.TargetBaseURL = "http://10.0.0.5:8099"

	wrongScenario := base
	wrongScenario.Reports = []runner.Report{{ScenarioID: "API-BAS-AUTHZ-002", RunTag: "t"}}

	missingReports := base
	missingReports.Reports = nil

	noRunTag := base
	noRunTag.Reports = []runner.Report{{ScenarioID: req.ScenarioIDs[0]}}

	failedWithReports := JobResult{SchemaVersion: SchemaVersion, JobID: req.JobID, TargetBaseURL: req.TargetBaseURL,
		Status: StatusFailed, ScenarioIDs: req.ScenarioIDs, Error: "crashed", Reports: base.Reports}

	failedNoReason := JobResult{SchemaVersion: SchemaVersion, JobID: req.JobID, TargetBaseURL: req.TargetBaseURL,
		Status: StatusFailed, ScenarioIDs: req.ScenarioIDs}

	completedWithError := base
	completedWithError.Error = "partial"

	unknownStatus := base
	unknownStatus.Status = "succeeded"

	cases := map[string]JobResult{
		"job mismatch":           mismatchJob,
		"target mismatch":        mismatchTarget,
		"wrong scenario":         wrongScenario,
		"missing reports":        missingReports,
		"no run tag":             noRunTag,
		"failed carries reports": failedWithReports,
		"failed without reason":  failedNoReason,
		"completed with error":   completedWithError,
		"unknown status":         unknownStatus,
	}
	for name, res := range cases {
		if err := ValidateResult(req, res); err == nil {
			t.Errorf("%s: accepted as valid", name)
		}
	}
}

func TestDecodeResultRefusesUnknownFields(t *testing.T) {
	if _, err := DecodeResult([]byte(`{"schema_version":1,"status":"completed","extra":true}`)); err == nil {
		t.Fatal("result with an unknown field was accepted")
	}
	if _, err := DecodeResult([]byte(`{"schema_version":1,"status":`)); err == nil {
		t.Fatal("truncated result was accepted")
	}
}

func TestLoadCredentialsChecksFormatAndPermissions(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"apibas/lab/customer-a":"tok-a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadCredentials(good)
	if err != nil || m["apibas/lab/customer-a"] != "tok-a" {
		t.Fatalf("LoadCredentials = %v, %v", m, err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`[not an object`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadCredentials(bad)
	if err == nil || strings.Contains(err.Error(), "not an object") && strings.Contains(err.Error(), "[") {
		t.Fatalf("malformed credentials: err = %v; must refuse without echoing the file", err)
	}

	if runtime.GOOS != "windows" {
		open := filepath.Join(dir, "open.json")
		if err := os.WriteFile(open, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCredentials(open); err == nil {
			t.Fatal("a credentials file readable by others was accepted")
		}
	}
}
