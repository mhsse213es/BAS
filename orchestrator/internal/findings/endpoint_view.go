package findings

import "sort"

// Endpoint-wise remediation view (Phase 1). Built only from open findings and the
// agent table. Status labels follow the Phase 1 rule: Open when open findings have
// no remediation request, Phase 2 when a request exists (its execution is tracked
// later, never invented here), and No remediation required when none are open.
const (
	StatusOpen         = "Open"
	StatusPhase2       = "Phase 2"
	StatusNoneRequired = "No remediation required"
)

// EndpointAgent is one row of the agent table: an endpoint and its hostname.
type EndpointAgent struct {
	AgentID  string
	Hostname string
}

// EndpointFinding is one open finding with the endpoint it was raised on.
type EndpointFinding struct {
	ID            string   `json:"id"`
	AgentID       string   `json:"agentId"`
	TechniqueID   string   `json:"techniqueId"`
	TechniqueName string   `json:"techniqueName"`
	Tactic        string   `json:"tactic"`
	Severity      string   `json:"severity"`
	ExposureState string   `json:"exposureState"`
	ControlClass  string   `json:"controlClass"`
	// Mitigations are the ATT&CK mitigations for the technique: the recommended
	// remediation for this finding. Filled by the API layer from the ATT&CK data.
	Mitigations []string `json:"mitigations"`
}

// EndpointRemediation is one endpoint's remediation state.
type EndpointRemediation struct {
	AgentID        string            `json:"agentId"`
	Hostname       string            `json:"hostname"`
	Status         string            `json:"status"`
	OpenFindings   int               `json:"openFindings"`
	Severity       map[string]int    `json:"severity"`
	TechniqueCount int               `json:"techniqueCount"`
	Findings       []EndpointFinding `json:"findings"`
}

// GroupByEndpoint groups open findings by endpoint. Every agent in agents appears,
// including endpoints with no open findings. A finding whose agent is missing from
// agents still appears, with an empty hostname, so it is never dropped. requested
// holds the agent IDs that already have a remediation request.
func GroupByEndpoint(agents []EndpointAgent, findings []EndpointFinding, requested map[string]bool) []EndpointRemediation {
	byID := map[string]*EndpointRemediation{}
	techs := map[string]map[string]bool{}
	order := []string{}
	ensure := func(agentID, hostname string) *EndpointRemediation {
		e := byID[agentID]
		if e == nil {
			e = &EndpointRemediation{AgentID: agentID, Hostname: hostname, Severity: map[string]int{}, Findings: []EndpointFinding{}}
			byID[agentID] = e
			techs[agentID] = map[string]bool{}
			order = append(order, agentID)
		}
		if e.Hostname == "" {
			e.Hostname = hostname
		}
		return e
	}
	for _, a := range agents {
		ensure(a.AgentID, a.Hostname)
	}
	for _, f := range findings {
		e := ensure(f.AgentID, "")
		e.Findings = append(e.Findings, f)
		e.OpenFindings++
		if key := severityKey(f.Severity); key != "" {
			e.Severity[key]++
		}
		techs[f.AgentID][f.TechniqueID] = true
	}

	out := make([]EndpointRemediation, 0, len(order))
	for _, id := range order {
		e := byID[id]
		e.TechniqueCount = len(techs[id])
		sort.SliceStable(e.Findings, func(i, j int) bool {
			if ri, rj := sevRank(e.Findings[i].Severity), sevRank(e.Findings[j].Severity); ri != rj {
				return ri > rj
			}
			return e.Findings[i].TechniqueID < e.Findings[j].TechniqueID
		})
		switch {
		case e.OpenFindings == 0:
			e.Status = StatusNoneRequired
		case requested[id]:
			e.Status = StatusPhase2
		default:
			e.Status = StatusOpen
		}
		out = append(out, *e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OpenFindings != out[j].OpenFindings {
			return out[i].OpenFindings > out[j].OpenFindings
		}
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out
}

// severityKey maps a finding severity to the lowercase breakdown key. Anything
// outside the four levels is counted in OpenFindings but not in the breakdown.
func severityKey(s string) string {
	switch s {
	case "Critical":
		return "critical"
	case "High":
		return "high"
	case "Medium":
		return "medium"
	case "Low":
		return "low"
	}
	return ""
}
