// Package runnerproto is the contract between the orchestrator and the API BAS runner child process.
//
// The runner reads one JobRequest from a file and writes one JobResult to stdout. It holds no database credential and
// makes no database connection. The orchestrator validates the result before it persists anything (see ValidateResult).
// Credentials never appear in the request: the request names a credentials file, which the orchestrator writes for one job
// and deletes afterwards.
package runnerproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/openapi"
	"github.com/audspect/bas/internal/apibas/runner"
	"github.com/audspect/bas/internal/apibas/scope"
)

// SchemaVersion is the only contract version accepted by both sides. A change to either struct bumps it.
const SchemaVersion = 2

// Result statuses. A runner that cannot finish reports StatusFailed with no reports.
const (
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

var jobIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// JobRequest is the scoped input to one runner process.
type JobRequest struct {
	SchemaVersion int      `json:"schema_version"`
	JobID         string   `json:"job_id"`
	TargetBaseURL string   `json:"target_base_url"`
	Fixture       string   `json:"fixture"`
	ScenarioIDs   []string `json:"scenario_ids"`
	// AllowedHosts are the hosts, besides the target itself, the runner may reach.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// AllowedPaths are the path prefixes (whole segments) the runner may request. Empty means no path restriction.
	AllowedPaths []string `json:"allowed_paths,omitempty"`
	// CredentialsFile is the path of a JSON object mapping secret reference to value. It must be readable by the owner only.
	CredentialsFile string `json:"credentials_file"`
	// Bound carries the test data and inventory a customer-bound job runs from. The runner rebuilds the scenarios from it with
	// the same code the orchestrator used at submission. Present exactly when Fixture is BoundFixture(Bound).
	Bound *BoundPlan `json:"bound,omitempty"`
}

// BoundPlan is the input of a customer-bound job: the target's inventory and the test data bound against it.
type BoundPlan struct {
	InventoryVersion int               `json:"inventory_version"`
	Inventory        openapi.Inventory `json:"inventory"`
	Spec             binding.Spec      `json:"spec"`
}

// BoundFixturePrefix starts the fixture name of every customer-bound job. The rest is the SHA-256 of the plan, so an approval
// bound to the fixture name is bound to the exact test data and inventory.
const BoundFixturePrefix = "bound:"

// IsBoundFixture reports whether a fixture name denotes a customer-bound job.
func IsBoundFixture(name string) bool { return strings.HasPrefix(name, BoundFixturePrefix) }

// BoundFixture returns the fixture name for a plan.
func BoundFixture(b BoundPlan) (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("runnerproto: encode bound plan: %w", err)
	}
	sum := sha256.Sum256(raw)
	return BoundFixturePrefix + hex.EncodeToString(sum[:]), nil
}

// BoundScenarioIDs rebuilds a plan's scenarios and returns their ids in order, so the orchestrator and the runner agree on
// what the job runs. It fails when the test data no longer binds.
func BoundScenarioIDs(b BoundPlan) (*binding.Plan, []string, error) {
	plan, err := binding.Bind(&b.Inventory, b.Spec)
	if err != nil {
		return nil, nil, err
	}
	ids := make([]string, 0, len(plan.Scenarios))
	for _, s := range plan.Scenarios {
		ids = append(ids, s.ID)
	}
	if len(ids) == 0 {
		return nil, nil, errors.New("runnerproto: the test data binds no scenario")
	}
	return plan, ids, nil
}

// CheckBound verifies that a bound request is internally consistent: the plan is present, it hashes to the fixture name, and it
// rebuilds exactly the scenario ids requested. A request whose fixture is not bound must not carry a plan.
func (q JobRequest) CheckBound() (*binding.Plan, error) {
	if !IsBoundFixture(q.Fixture) {
		if q.Bound != nil {
			return nil, errors.New("runnerproto: a plan is present but the fixture is not a bound fixture")
		}
		return nil, nil
	}
	if q.Bound == nil {
		return nil, errors.New("runnerproto: a bound fixture needs its plan")
	}
	want, err := BoundFixture(*q.Bound)
	if err != nil {
		return nil, err
	}
	if want != q.Fixture {
		return nil, errors.New("runnerproto: the plan does not match the fixture hash")
	}
	plan, ids, err := BoundScenarioIDs(*q.Bound)
	if err != nil {
		return nil, fmt.Errorf("runnerproto: the plan does not bind: %w", err)
	}
	if !slices.Equal(ids, q.ScenarioIDs) {
		return nil, errors.New("runnerproto: the plan does not produce the requested scenarios")
	}
	return plan, nil
}

// JobResult is the runner's only output. The orchestrator validates it against the request before persisting.
type JobResult struct {
	SchemaVersion int             `json:"schema_version"`
	JobID         string          `json:"job_id"`
	TargetBaseURL string          `json:"target_base_url"`
	Status        string          `json:"status"`
	ScenarioIDs   []string        `json:"scenario_ids"`
	Reports       []runner.Report `json:"reports"`
	Error         string          `json:"error,omitempty"`
}

// DecodeJobRequest reads and validates one request. Unknown fields are refused, so a typo cannot silently widen scope.
func DecodeJobRequest(r io.Reader) (JobRequest, error) {
	var req JobRequest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return JobRequest{}, fmt.Errorf("runnerproto: decode request: %w", err)
	}
	if err := req.Validate(); err != nil {
		return JobRequest{}, err
	}
	return req, nil
}

// Validate checks every field the runner relies on.
func (q JobRequest) Validate() error {
	if q.SchemaVersion != SchemaVersion {
		return fmt.Errorf("runnerproto: schema_version %d, want %d", q.SchemaVersion, SchemaVersion)
	}
	if !jobIDRE.MatchString(q.JobID) {
		return errors.New("runnerproto: job_id must be 8 to 64 letters, digits, '_' or '-'")
	}
	u, err := url.Parse(q.TargetBaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("runnerproto: target_base_url must be an absolute http or https URL")
	}
	if q.Fixture == "" {
		return errors.New("runnerproto: fixture is required")
	}
	if len(q.ScenarioIDs) == 0 {
		return errors.New("runnerproto: at least one scenario_id is required")
	}
	seen := map[string]bool{}
	for _, id := range q.ScenarioIDs {
		if id == "" || seen[id] {
			return fmt.Errorf("runnerproto: scenario_id %q is empty or repeated", id)
		}
		seen[id] = true
	}
	if q.CredentialsFile == "" {
		return errors.New("runnerproto: credentials_file is required")
	}
	return nil
}

// EncodeResult writes the result as the runner's stdout document.
func EncodeResult(w io.Writer, res JobResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// ValidateResult checks a result against the request that produced it. It is the orchestrator's gate before persistence:
// a crash, a malformed document, a mismatched job, or a partial success all fail here and never become a run record.
func ValidateResult(req JobRequest, res JobResult) error {
	if res.SchemaVersion != SchemaVersion {
		return fmt.Errorf("runnerproto: result schema_version %d, want %d", res.SchemaVersion, SchemaVersion)
	}
	if res.JobID != req.JobID {
		return errors.New("runnerproto: result job_id does not match the request")
	}
	if res.TargetBaseURL != req.TargetBaseURL {
		return errors.New("runnerproto: result target does not match the request")
	}
	if !slices.Equal(res.ScenarioIDs, req.ScenarioIDs) {
		return errors.New("runnerproto: result scenario set does not match the request")
	}
	switch res.Status {
	case StatusFailed:
		if res.Error == "" {
			return errors.New("runnerproto: failed result carries no reason")
		}
		if len(res.Reports) != 0 {
			return errors.New("runnerproto: failed result must not carry reports")
		}
		return nil
	case StatusCompleted:
		if res.Error != "" {
			return errors.New("runnerproto: completed result must not carry an error")
		}
		if len(res.Reports) != len(req.ScenarioIDs) {
			return fmt.Errorf("runnerproto: %d reports for %d scenarios", len(res.Reports), len(req.ScenarioIDs))
		}
		seenTags := map[string]bool{}
		for i, rep := range res.Reports {
			if rep.ScenarioID != req.ScenarioIDs[i] {
				return fmt.Errorf("runnerproto: report %d is for %q, want %q", i, rep.ScenarioID, req.ScenarioIDs[i])
			}
			if err := validateEvidence(req, rep, seenTags); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("runnerproto: unknown status %q", res.Status)
	}
}

var runTagRE = regexp.MustCompile(`^[A-Za-z0-9_-]{6,64}$`)

// validateEvidence checks the references one report carries. Each report needs a well-formed run tag that no other report in
// the job uses, and every recorded exchange must be a complete, plausible record: a step ID, a known method, a status that is
// either 0 (no response) or a real HTTP status, a non-negative leak count and, when the job has a path scope, a request path
// inside it. A result that fails any of these is not stored, so the stored evidence references always resolve to a valid exchange.
func validateEvidence(req JobRequest, rep runner.Report, seenTags map[string]bool) error {
	if !runTagRE.MatchString(rep.RunTag) {
		return fmt.Errorf("runnerproto: report for %q has a missing or malformed run tag", rep.ScenarioID)
	}
	if seenTags[rep.RunTag] {
		return fmt.Errorf("runnerproto: run tag %q is used by more than one report", rep.RunTag)
	}
	seenTags[rep.RunTag] = true
	for i, ex := range rep.Exchanges {
		switch {
		case ex.StepID == "":
			return fmt.Errorf("runnerproto: %s exchange %d has no step id", rep.RunTag, i)
		case !slices.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}, ex.Method):
			return fmt.Errorf("runnerproto: %s exchange %d has method %q", rep.RunTag, i, ex.Method)
		case ex.Status != 0 && (ex.Status < 100 || ex.Status > 599):
			return fmt.Errorf("runnerproto: %s exchange %d has status %d", rep.RunTag, i, ex.Status)
		case ex.Leaked < 0:
			return fmt.Errorf("runnerproto: %s exchange %d has a negative leak count", rep.RunTag, i)
		case len(req.AllowedPaths) > 0 && !scope.Allowed(req.AllowedPaths, ex.Path):
			return fmt.Errorf("runnerproto: %s exchange %d requested a path outside the job's allowed paths", rep.RunTag, i)
		}
	}
	return nil
}

// DecodeResult parses a runner's stdout document. Unknown fields are refused.
func DecodeResult(raw []byte) (JobResult, error) {
	var res JobResult
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return JobResult{}, fmt.Errorf("runnerproto: decode result: %w", err)
	}
	return res, nil
}

// LoadCredentials reads the job's credentials file. The file must be readable by its owner only on Unix, because the
// runner is the only reader. On Windows the ACL is not expressed in mode bits, so only the format is checked.
func LoadCredentials(path string) (runner.MapSecrets, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("runnerproto: credentials file: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("runnerproto: credentials file must not be readable by group or others")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("runnerproto: credentials file: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		// The parser error can echo part of the file. Report only that the format is wrong.
		return nil, errors.New("runnerproto: credentials file is not a JSON object of strings")
	}
	return runner.MapSecrets(m), nil
}
