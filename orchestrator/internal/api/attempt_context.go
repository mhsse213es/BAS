package api

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rwdetect"
	"github.com/audspect/bas/internal/rwevidence"
)

// attemptContextSource is the production rwdetect.ContextSource. Host identity
// comes from the agent's registration record. Event time comes only from a
// stored agent-supplied execution timestamp, and only when exactly one distinct
// such timestamp exists for the attempt. Anything else is reported as a
// problem, never guessed.
type attemptContextSource struct {
	pool *pgxpool.Pool
}

var _ rwdetect.ContextSource = attemptContextSource{}

func (s attemptContextSource) AttemptContextFor(ctx context.Context, key rwevidence.AttemptKey) (rwdetect.AttemptContext, error) {
	rec, found, err := db.LoadAttemptRecord(ctx, s.pool, key.RunID, key.Action)
	if err != nil {
		return rwdetect.AttemptContext{}, err
	}
	return resolveAttemptContext(rec, found), nil
}

func resolveAttemptContext(rec db.AttemptRecord, found bool) rwdetect.AttemptContext {
	var out rwdetect.AttemptContext
	if !found {
		out.HostProblem = "run not found"
		out.TimeProblem = "run not found"
		return out
	}

	switch {
	case !rec.AgentFound:
		out.HostProblem = "agent registration record missing"
	case rec.Hostname == "" && rec.IPAddress == "":
		out.HostProblem = "agent registration record has no hostname or IP"
	default:
		out.HostName = rec.Hostname
		out.HostIP = rec.IPAddress
	}

	if !rec.StepMetaFound {
		out.TimeProblem = "step metadata missing for this attempt"
		return out
	}
	if len(rec.Executions) == 0 {
		out.TimeProblem = "no execution recorded for this technique and step"
		return out
	}

	agentTimes := map[string]bool{}
	var fallback, unknown bool
	for _, e := range rec.Executions {
		switch e.Source {
		case models.ExecutedAtSourceAgent:
			agentTimes[e.ExecutedAt] = true
		case models.ExecutedAtSourceOrchestratorFallback:
			fallback = true
		default:
			unknown = true
		}
	}
	// Any non-agent provenance makes the attempt ambiguous, even alongside a
	// valid agent timestamp: the fallback could be a second, unobserved run.
	if fallback {
		out.TimeProblem = "orchestrator fallback timestamp recorded for this step; it is submission time, not agent-observed execution time"
		return out
	}
	if unknown {
		out.TimeProblem = "result with unknown timestamp provenance (legacy); not treated as agent-observed"
		return out
	}
	if len(agentTimes) != 1 {
		out.TimeProblem = fmt.Sprintf("%d distinct execution timestamps recorded for this step; the event cannot be identified", len(agentTimes))
		return out
	}
	for raw := range agentTimes {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			out.TimeProblem = "recorded execution timestamp is unparseable"
			return out
		}
		out.ExecutedAt = t.UTC()
	}
	return out
}
