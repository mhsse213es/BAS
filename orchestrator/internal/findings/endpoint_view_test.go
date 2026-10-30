package findings

import "testing"

// GroupByEndpoint is the Phase 1 endpoint-wise remediation view. It is built only
// from open findings and the agent table. A remediation request never changes the
// open-finding count, and no execution status is invented: a request only moves an
// endpoint to the Phase 2 label.

func TestGroupByEndpoint_GroupsMultipleFindingsPerEndpoint(t *testing.T) {
	agents := []EndpointAgent{{AgentID: "a1", Hostname: "FINANCE-PC-01"}, {AgentID: "a2", Hostname: "HR-LAPTOP-03"}}
	findings := []EndpointFinding{
		{ID: "f1", AgentID: "a1", TechniqueID: "T1003", Severity: "Critical"},
		{ID: "f2", AgentID: "a1", TechniqueID: "T1003", Severity: "High"}, // same technique, second finding
		{ID: "f3", AgentID: "a1", TechniqueID: "T1486", Severity: "Low"},
		{ID: "f4", AgentID: "a2", TechniqueID: "T1566", Severity: "Medium"},
	}
	got := GroupByEndpoint(agents, findings, nil)
	if len(got) != 2 {
		t.Fatalf("endpoints = %d, want 2", len(got))
	}
	// Sorted by open findings, most first.
	if got[0].AgentID != "a1" || got[0].OpenFindings != 3 {
		t.Fatalf("first endpoint = %+v, want a1 with 3 open findings", got[0])
	}
	if got[0].Hostname != "FINANCE-PC-01" {
		t.Fatalf("hostname = %q, want FINANCE-PC-01", got[0].Hostname)
	}
	if got[0].Severity["critical"] != 1 || got[0].Severity["high"] != 1 || got[0].Severity["low"] != 1 || got[0].Severity["medium"] != 0 {
		t.Fatalf("severity breakdown = %v", got[0].Severity)
	}
	// Two findings share T1003, so the endpoint affects two distinct techniques.
	if got[0].TechniqueCount != 2 {
		t.Fatalf("technique count = %d, want 2", got[0].TechniqueCount)
	}
	if len(got[0].Findings) != 3 || got[0].Findings[0].ID != "f1" {
		t.Fatalf("findings = %+v, want the three findings, most severe first", got[0].Findings)
	}
}

func TestGroupByEndpoint_StatusRules(t *testing.T) {
	agents := []EndpointAgent{{AgentID: "open", Hostname: "A"}, {AgentID: "requested", Hostname: "B"}, {AgentID: "clean", Hostname: "C"}}
	findings := []EndpointFinding{
		{ID: "1", AgentID: "open", TechniqueID: "T1", Severity: "High"},
		{ID: "2", AgentID: "requested", TechniqueID: "T1", Severity: "High"},
	}
	got := GroupByEndpoint(agents, findings, map[string]bool{"requested": true})
	status := map[string]string{}
	open := map[string]int{}
	for _, e := range got {
		status[e.AgentID] = e.Status
		open[e.AgentID] = e.OpenFindings
	}
	if status["open"] != StatusOpen {
		t.Fatalf("open endpoint status = %q, want %q", status["open"], StatusOpen)
	}
	if status["requested"] != StatusPhase2 {
		t.Fatalf("requested endpoint status = %q, want %q", status["requested"], StatusPhase2)
	}
	if status["clean"] != StatusNoneRequired {
		t.Fatalf("clean endpoint status = %q, want %q", status["clean"], StatusNoneRequired)
	}
	// A request must not change the finding count: finding closure is verified separately.
	if open["requested"] != 1 {
		t.Fatalf("requested endpoint open findings = %d, want 1 (a request is not proof of a fix)", open["requested"])
	}
}

func TestGroupByEndpoint_UnresolvedEndpointIsKeptWithoutHostname(t *testing.T) {
	// A finding whose agent is not in the agent table still shows, so it can't vanish.
	got := GroupByEndpoint(nil, []EndpointFinding{{ID: "1", AgentID: "ghost", TechniqueID: "T1", Severity: "Low"}}, nil)
	if len(got) != 1 || got[0].AgentID != "ghost" || got[0].Hostname != "" || got[0].OpenFindings != 1 {
		t.Fatalf("unresolved endpoint = %+v", got)
	}
}

func TestGroupByEndpoint_EmptyInputsAreEmptyNotNil(t *testing.T) {
	if got := GroupByEndpoint(nil, nil, nil); got == nil || len(got) != 0 {
		t.Fatalf("no agents and no findings = %v, want an empty non-nil slice", got)
	}
}
