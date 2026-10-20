package main

import (
	"log"
	"time"

	"audspect/agent/protocol"
)

// hostEventMaxEvents caps one run's collection. It matches the server's batch bound.
const hostEventMaxEvents = 2000

// submitHostEvents collects the run's required Security events and audit state, then
// posts them. The payload is separate from detections, because it is execution
// evidence, not alert evidence. A collection failure is logged and not sent. An
// empty result is sent as empty, with its audit state, so the server can tell "no
// events" from "never looked".
func (a *Agent) submitHostEvents(runID string, runStart time.Time) {
	from := runStart.Add(-5 * time.Second)
	to := time.Now()
	recs, truncated, err := collectHostEvents(from, to, hostEventMaxEvents)
	if err != nil {
		log.Printf("[hostevents] run %s: collection failed, not submitted: %v", runID, err)
		return
	}
	payload := protocol.RunHostEvents{
		RunID: runID, AgentID: a.id.AgentID, Events: recs, Audit: probeAudit(),
		WindowFrom: from, WindowTo: to, Truncated: truncated,
	}
	if err := a.postJSON("/api/scenarios/runs/"+runID+"/host-events", payload); err != nil {
		log.Printf("[hostevents] run %s: submit failed: %v", runID, err)
		return
	}
	log.Printf("[hostevents] run %s: submitted %d event(s), truncated=%v", runID, len(recs), truncated)
}
