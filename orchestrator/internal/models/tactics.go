package models

// Tactic is a MITRE ATT&CK Enterprise tactic — the "why" of a technique.
type Tactic struct {
	ID       string `json:"id"`       // canonical shortname, e.g. "credential-access"
	Name     string `json:"name"`     // display name, e.g. "Credential Access"
	AttackID string `json:"attackId"` // ATT&CK tactic ID, e.g. "TA0006"
	Order    int    `json:"order"`    // kill-chain ordering, 1..14
}

// EnterpriseTactics is the canonical, ordered list of the 14 MITRE ATT&CK
// Enterprise tactics. It is the single source of truth for tactic names used to
// seed the knowledge-graph `tactics` table and to label reports. The shortnames
// match the values produced by LookupTactic / stored in techniques.tactic.
var EnterpriseTactics = []Tactic{
	{ID: "reconnaissance", Name: "Reconnaissance", AttackID: "TA0043", Order: 1},
	{ID: "resource-development", Name: "Resource Development", AttackID: "TA0042", Order: 2},
	{ID: "initial-access", Name: "Initial Access", AttackID: "TA0001", Order: 3},
	{ID: "execution", Name: "Execution", AttackID: "TA0002", Order: 4},
	{ID: "persistence", Name: "Persistence", AttackID: "TA0003", Order: 5},
	{ID: "privilege-escalation", Name: "Privilege Escalation", AttackID: "TA0004", Order: 6},
	{ID: "defense-evasion", Name: "Defense Evasion", AttackID: "TA0005", Order: 7},
	{ID: "credential-access", Name: "Credential Access", AttackID: "TA0006", Order: 8},
	{ID: "discovery", Name: "Discovery", AttackID: "TA0007", Order: 9},
	{ID: "lateral-movement", Name: "Lateral Movement", AttackID: "TA0008", Order: 10},
	{ID: "collection", Name: "Collection", AttackID: "TA0009", Order: 11},
	{ID: "command-and-control", Name: "Command and Control", AttackID: "TA0011", Order: 12},
	{ID: "exfiltration", Name: "Exfiltration", AttackID: "TA0010", Order: 13},
	{ID: "impact", Name: "Impact", AttackID: "TA0040", Order: 14},
}

// tacticNameByID is a fast shortname → display-name lookup built from
// EnterpriseTactics.
var tacticNameByID = func() map[string]string {
	m := make(map[string]string, len(EnterpriseTactics))
	for _, t := range EnterpriseTactics {
		m[t.ID] = t.Name
	}
	return m
}()

// TacticName returns the human-readable display name for a tactic shortname,
// or the shortname itself when unknown.
func TacticName(id string) string {
	if n, ok := tacticNameByID[id]; ok {
		return n
	}
	return id
}
