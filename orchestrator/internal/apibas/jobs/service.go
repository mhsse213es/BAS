// Package jobs is the orchestrator's API BAS execution service. It owns a job's lifecycle: submission, idempotent dispatch,
// running the runner as a child process, validating what the runner returns, and persisting the result. It is separate from
// the normal scenario engine (see docs/api-bas-assessment-design.md).
package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/audspect/bas/internal/apibas/runner"
	"github.com/audspect/bas/internal/apibas/runnerproto"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/secretstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrEnvironmentNotPermitted means the target's environment is not one this release executes. Production targets are refused
// here, in the service, whatever the UI or API sends (design section 5, requirement 8).
var ErrEnvironmentNotPermitted = errors.New("apibas: environment not permitted for execution in this release")

// Spec is one requested assessment. Key makes the request idempotent: the same key always yields the same job.
type Spec struct {
	Key           string
	RequestedBy   string
	TargetBaseURL string
	Environment   string
	Fixture       string
	ScenarioIDs   []string
	AllowedHosts  []string
	// Credentials maps each runner secret name to a D4 secret-store reference. Only references are stored on the job.
	Credentials map[string]string
}

// Config bounds one execution. Zero values take the defaults shown.
type Config struct {
	RunnerPath     string        // required: absolute path to the apibas-runner binary
	Timeout        time.Duration // default 15 minutes
	MaxOutputBytes int64         // default 32 MiB
	WorkDir        string        // parent of per-job private directories; default os.TempDir()
}

// Service executes jobs. It holds the database pool and the secret store, and nothing that the runner child process receives.
type Service struct {
	pool    *pgxpool.Pool
	secrets secretstore.Store
	cfg     Config
}

// New returns a service. It rejects a missing runner path or a missing secret store, because a job cannot run without either.
func New(pool *pgxpool.Pool, secrets secretstore.Store, cfg Config) (*Service, error) {
	if cfg.RunnerPath == "" {
		return nil, errors.New("apibas jobs: runner path is required")
	}
	// Fail at startup, not at the first job, when the runner is missing or is not a regular file.
	if fi, err := os.Stat(cfg.RunnerPath); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("apibas jobs: runner binary not found or not a regular file")
	}
	if secrets == nil {
		return nil, errors.New("apibas jobs: a secret store is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Minute
	}
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = 32 << 20
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = os.TempDir()
	}
	return &Service{pool: pool, secrets: secrets, cfg: cfg}, nil
}

// Submit records a queued job. It does not execute anything. A repeated Submit with the same Key returns the existing job
// and created=false.
func (s *Service) Submit(ctx context.Context, sp Spec) (db.APIBASJob, bool, error) {
	switch sp.Environment {
	case "lab", "staging":
	default:
		return db.APIBASJob{}, false, ErrEnvironmentNotPermitted
	}
	if sp.Key == "" || sp.RequestedBy == "" {
		return db.APIBASJob{}, false, errors.New("apibas jobs: key and requester are required")
	}
	for name, ref := range sp.Credentials {
		if name == "" || !secretstore.ValidRef(ref) {
			return db.APIBASJob{}, false, fmt.Errorf("apibas jobs: credential %q must reference the secret store", name)
		}
	}
	// Validate the request shape now, so a job that could never run is refused at submission. The job ID and credentials
	// file are filled in at dispatch.
	probe := runnerproto.JobRequest{
		SchemaVersion: runnerproto.SchemaVersion, JobID: "probe-job-id", TargetBaseURL: sp.TargetBaseURL,
		Fixture: sp.Fixture, ScenarioIDs: sp.ScenarioIDs, AllowedHosts: sp.AllowedHosts, CredentialsFile: "probe",
	}
	if err := probe.Validate(); err != nil {
		return db.APIBASJob{}, false, err
	}
	return db.CreateAPIBASJob(ctx, s.pool, db.APIBASJob{
		JobKey: sp.Key, RequestedBy: sp.RequestedBy, TargetBaseURL: sp.TargetBaseURL, Environment: sp.Environment,
		Fixture: sp.Fixture, ScenarioIDs: sp.ScenarioIDs, CredentialRefs: sp.Credentials,
	})
}

// Dispatch executes a queued job. It returns started=false, with no error, when the job is not queued: a repeated dispatch
// never starts a second execution.
func (s *Service) Dispatch(ctx context.Context, jobID string) (started bool, err error) {
	// Database writes use a context that a cancelled job cannot cancel. Otherwise recording the 'cancelled' outcome would fail
	// and leave the job running.
	dbCtx := context.WithoutCancel(ctx)
	job, err := db.GetAPIBASJob(dbCtx, s.pool, jobID)
	if err != nil {
		return false, err
	}
	if job.Status != "queued" {
		return false, nil
	}
	ok, err := db.StartAPIBASJob(dbCtx, s.pool, jobID)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	outcome := s.execute(ctx, job)
	if ferr := db.FinishAPIBASJob(dbCtx, s.pool, jobID, outcome.status, outcome.reason, outcome.reports); ferr != nil {
		// The job stays 'running' until ReconcileStaleAPIBASJobs fails it. Say so in the log, without the report content.
		log.Printf("[apibas] job %s: could not record its outcome: %v", jobID, ferr)
		return true, ferr
	}
	return true, nil
}

type outcome struct {
	status  string
	reason  string
	reports []db.APIBASJobReport
}

// execute runs the child process and turns what it returns into an outcome. Every path that does not produce a validated
// completed result yields a failed or cancelled outcome, never a success.
func (s *Service) execute(parent context.Context, job db.APIBASJob) outcome {
	creds, err := s.resolveCredentials(parent, job.CredentialRefs)
	if err != nil {
		return outcome{status: "failed", reason: "target credential unavailable"}
	}

	dir, err := os.MkdirTemp(s.cfg.WorkDir, "apibas-job-")
	if err != nil {
		return outcome{status: "failed", reason: "job workspace unavailable"}
	}
	defer os.RemoveAll(dir) // removes the credentials file with the workspace, on every path

	credsPath := filepath.Join(dir, "credentials.json")
	if err := writePrivate(credsPath, creds); err != nil {
		return outcome{status: "failed", reason: "job workspace unavailable"}
	}
	req := runnerproto.JobRequest{
		SchemaVersion: runnerproto.SchemaVersion, JobID: job.ID, TargetBaseURL: job.TargetBaseURL,
		Fixture: job.Fixture, ScenarioIDs: job.ScenarioIDs, CredentialsFile: credsPath,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return outcome{status: "failed", reason: "job request could not be encoded"}
	}
	reqPath := filepath.Join(dir, "request.json")
	if err := writePrivate(reqPath, reqBytes); err != nil {
		return outcome{status: "failed", reason: "job workspace unavailable"}
	}

	ctx, cancel := context.WithTimeout(parent, s.cfg.Timeout)
	defer cancel()
	stdout := &cappedBuffer{limit: s.cfg.MaxOutputBytes}
	cmd := exec.CommandContext(ctx, s.cfg.RunnerPath, "-job-request", reqPath)
	cmd.Env = childEnv()
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard // runner diagnostics may echo target content; they are not stored
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()

	switch {
	case errors.Is(parent.Err(), context.Canceled):
		return outcome{status: "cancelled", reason: "cancelled by request"}
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return outcome{status: "failed", reason: "execution timed out"}
	case stdout.overflow:
		return outcome{status: "failed", reason: "runner output exceeded the size limit"}
	}

	res, derr := runnerproto.DecodeResult(stdout.buf.Bytes())
	if derr != nil {
		return outcome{status: "failed", reason: "malformed runner output"}
	}
	if verr := runnerproto.ValidateResult(req, res); verr != nil {
		return outcome{status: "failed", reason: "runner result rejected: " + verr.Error()}
	}
	if res.Status == runnerproto.StatusFailed {
		return outcome{status: "failed", reason: res.Error}
	}
	if runErr != nil {
		// A completed document from a process that exited non-zero is not trusted.
		return outcome{status: "failed", reason: "runner exited with an error"}
	}
	reports, rerr := toReports(res.Reports)
	if rerr != nil {
		return outcome{status: "failed", reason: rerr.Error()}
	}
	return outcome{status: "completed", reports: reports}
}

func toReports(in []runner.Report) ([]db.APIBASJobReport, error) {
	out := make([]db.APIBASJobReport, 0, len(in))
	for _, r := range in {
		switch string(r.Outcome.Result) {
		case "PASS", "FAIL", "ERROR", "SKIPPED":
		default:
			return nil, fmt.Errorf("runner result rejected: verdict for %q is not a grade", r.ScenarioID)
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("runner result rejected: report for %q cannot be stored", r.ScenarioID)
		}
		out = append(out, db.APIBASJobReport{
			ScenarioID: r.ScenarioID, RunTag: r.RunTag, Result: string(r.Outcome.Result),
			Exploitability: string(r.Outcome.Exploitability), Control: string(r.Outcome.Control),
			Detection: r.Outcome.Detection, Reason: string(r.Outcome.Reason), Report: raw,
		})
	}
	return out, nil
}

// resolveCredentials reads each reference at dispatch. A failure to resolve any one of them fails the whole job, so a run never
// starts with a partial credential set.
func (s *Service) resolveCredentials(ctx context.Context, refs map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(refs))
	for name, ref := range refs {
		v, err := s.secrets.Get(ctx, ref)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// childEnv is the child process's whole environment: an explicit allow-list, never the parent's. On Windows the Go runtime
// needs SYSTEMROOT and TEMP; nothing else is passed through.
func childEnv() []string {
	if runtime.GOOS == "windows" {
		var env []string
		for _, k := range []string{"SYSTEMROOT", "TEMP", "TMP"} {
			if v, ok := os.LookupEnv(k); ok {
				env = append(env, k+"="+v)
			}
		}
		return env
	}
	return []string{}
}

// writePrivate writes a file readable by its owner only.
func writePrivate(path string, data any) error {
	var b []byte
	switch v := data.(type) {
	case []byte:
		b = v
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// cappedBuffer keeps at most limit bytes and records whether more was written. Output past the limit is dropped, and the run fails.
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int64
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.limit - int64(c.buf.Len())
	if int64(len(p)) > room {
		c.overflow = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// ReconcileStale fails jobs left running by an earlier orchestrator process. Call it at startup and periodically.
func (s *Service) ReconcileStale(ctx context.Context, olderThan time.Duration) (int64, error) {
	return db.ReconcileStaleAPIBASJobs(ctx, s.pool, olderThan)
}
