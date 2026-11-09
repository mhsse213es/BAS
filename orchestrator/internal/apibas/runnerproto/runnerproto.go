// Package runnerproto is the contract between the orchestrator and the API BAS runner child process.
//
// The runner reads one JobRequest from a file and writes one JobResult to stdout. It holds no database credential and
// makes no database connection. The orchestrator validates the result before it persists anything (see ValidateResult).
// Credentials never appear in the request: the request names a credentials file, which the orchestrator writes for one job
// and deletes afterwards.
package runnerproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"slices"

	"github.com/audspect/bas/internal/apibas/runner"
	"github.com/audspect/bas/internal/apibas/scope"
)

// SchemaVersion is the only contract version accepted by both sides. A change to either struct bumps it.
const SchemaVersion = 1

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
