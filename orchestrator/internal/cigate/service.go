package cigate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/validationlab"
)

// Dispatcher starts a factory-validation run on the lab agent. The API handler implements it, the same way the
// validation lab does.
type Dispatcher interface {
	DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (runID, skipReason string, err error)
}

var (
	// ErrNoLab means no factory lab agent is configured, so CI validation is off.
	ErrNoLab = errors.New("CI validation is disabled: no factory lab agent is configured")
	// ErrUnknownContent means the content id is not in the registry.
	ErrUnknownContent = errors.New("unknown content id")
	// ErrNoRun means no run has that id.
	ErrNoRun = errors.New("no such validation run")
)

// RefusedError is a start that the lab declined for now (agent busy or offline, or a safety re-check). The caller
// can retry later. Reason is the lab's own words.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "validation refused: " + e.Reason }

// Status is a run's progress and, once it has finished, its verdict.
type Status struct {
	RunID   string `json:"runId"`
	State   string `json:"state"`             // "running" or "completed"
	Verdict string `json:"verdict,omitempty"` // "pass", "fail", "no_data" or "error" once completed
	Reason  string `json:"reason,omitempty"`
}

// Service starts validation runs for CI and reports their verdicts.
type Service struct {
	pool       *pgxpool.Pool
	reg        *contentregistry.Registry
	dispatcher Dispatcher
	labAgentID string
}

func NewService(pool *pgxpool.Pool, reg *contentregistry.Registry, d Dispatcher, labAgentID string) *Service {
	return &Service{pool: pool, reg: reg, dispatcher: d, labAgentID: labAgentID}
}

// Start dispatches one factory-validation run for a registered content version and returns its run id.
func (s *Service) Start(ctx context.Context, contentID string) (string, error) {
	if s.labAgentID == "" {
		return "", ErrNoLab
	}
	// A pipeline knows the content id; validate its newest version, the one a new build just produced.
	versions, err := s.reg.ListVersions(ctx, contentID)
	if err != nil {
		return "", fmt.Errorf("content lookup failed: %w", err)
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("%w: %s", ErrUnknownContent, contentID)
	}
	v := versions[0]
	if v.Lifecycle == contentregistry.LifecycleRetired || v.Lifecycle == contentregistry.LifecycleRejected {
		return "", &RefusedError{Reason: "newest version of " + contentID + " is " + string(v.Lifecycle)}
	}
	if err := s.reg.DispatchSafetyRecheck(ctx, v); err != nil {
		return "", &RefusedError{Reason: "safety re-check: " + err.Error()}
	}
	sc, err := v.Parse()
	if err != nil {
		return "", fmt.Errorf("content does not parse: %w", err)
	}
	runID, skip, err := s.dispatcher.DispatchFactoryValidation(ctx, sc, s.labAgentID)
	if err != nil {
		return "", err
	}
	if runID == "" {
		if skip == "" {
			skip = "not dispatched"
		}
		return "", &RefusedError{Reason: skip}
	}
	return runID, nil
}

// Status reports a run. A run that is still going has no verdict yet.
func (s *Service) Status(ctx context.Context, runID string) (Status, error) {
	var state string
	var results []byte
	err := s.pool.QueryRow(ctx,
		`SELECT status, results FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&state, &results)
	if errors.Is(err, pgx.ErrNoRows) {
		return Status{}, ErrNoRun
	}
	if err != nil {
		return Status{}, err
	}
	return statusFor(runID, state, results), nil
}

// statusFor maps a run's stored state and results to a Status. It is kept free of the database so it can be tested.
func statusFor(runID, state string, results []byte) Status {
	if state == "running" {
		return Status{RunID: runID, State: "running"}
	}
	outcome, reason := validationlab.VerdictForRun(results)
	return Status{RunID: runID, State: "completed", Verdict: verdictName(outcome), Reason: reason}
}

func verdictName(outcome string) string {
	switch outcome {
	case "PASS":
		return "pass"
	case "FAIL":
		return "fail"
	case "NO_DATA":
		return "no_data"
	default:
		return "error"
	}
}
