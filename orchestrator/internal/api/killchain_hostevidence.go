package api

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
)

// hostEventReader is the slice of the kill-chain store that stage collection reads
// for a run's host events.
type hostEventReader interface {
	HostEventsForRun(ctx context.Context, runID string) ([]killchain.HostEvent, killchain.AuditState, db.HostEventWindow, bool, error)
}

// agentHostReader resolves the hostname an agent reports. Host events are matched on
// it.
type agentHostReader interface {
	AgentHostname(ctx context.Context, agentID string) (string, error)
}

// scenarioLookup returns a scenario by ID. The engine satisfies it.
type scenarioLookup interface {
	Get(id string) (*scenario.Scenario, bool)
}

// AgentHostname returns the hostname the agent registered. Unknown agents return "",
// which means nothing can be matched.
func (p poolRunReader) AgentHostname(ctx context.Context, agentID string) (string, error) {
	var name string
	err := p.pool.QueryRow(ctx, `SELECT COALESCE(hostname, '') FROM agents WHERE agent_id = $1`, agentID).Scan(&name)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return name, err
}

// hostGroundTruth turns a run's host events into a ground-truth candidate. It is
// used only when the scenario has markers, its source policy accepts event logs,
// and every marker is proven by a process creation record in the window. Otherwise
// it returns nothing, so the stage keeps the gap.
func (x EngineStageExecutor) hostGroundTruth(ctx context.Context, snap runSnapshot) (killchain.GroundTruthRecordFor, bool, []string, error) {
	if !killchain.SourceClassAllowed(snap.ScenarioID, killchain.SourceEventLog) {
		return killchain.GroundTruthRecordFor{}, false, nil, nil
	}
	sc, ok := x.Scenarios.Get(snap.ScenarioID)
	if !ok {
		return killchain.GroundTruthRecordFor{}, false, nil, nil
	}
	var markers []string
	for _, st := range sc.Steps {
		if st.Marker != "" {
			markers = append(markers, st.Marker)
		}
	}
	if len(markers) == 0 {
		return killchain.GroundTruthRecordFor{}, false, nil, nil
	}
	events, audit, win, found, err := x.HostEvents.HostEventsForRun(ctx, snap.ExecutionID)
	if err != nil {
		return killchain.GroundTruthRecordFor{}, false, nil, err
	}
	if !found {
		return killchain.GroundTruthRecordFor{}, false, nil, nil
	}
	host, err := x.Hosts.AgentHostname(ctx, snap.AgentID)
	if err != nil {
		return killchain.GroundTruthRecordFor{}, false, nil, err
	}
	if host == "" {
		return killchain.GroundTruthRecordFor{}, false, nil, nil
	}
	var first killchain.HostFinding
	var gaps []string
	proven := true
	for i, m := range markers {
		f := killchain.EvaluateHostEvents(killchain.ExecutionMatch{
			Marker: m, Host: host, WindowStart: win.From, WindowEnd: win.To,
		}, events, audit)
		if f.Executed != killchain.TriYes {
			// Keep every marker's gap, so the reason names each step that is unproven.
			gaps = append(gaps, f.Gaps...)
			proven = false
			continue
		}
		if i == 0 {
			first = f
		}
	}
	if !proven {
		return killchain.GroundTruthRecordFor{}, false, gaps, nil
	}
	rec, ok := killchain.GroundTruthFromFinding(first)
	return rec, ok, nil, nil
}
