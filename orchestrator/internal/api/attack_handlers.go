package api

import (
	"net/http"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/go-chi/chi/v5"
)

// enterpriseTactics is the canonical ATT&CK Enterprise kill-chain ordering plus
// display names. Stable — the matrix columns render in this order.
var enterpriseTactics = []struct{ ID, Name string }{
	{"reconnaissance", "Reconnaissance"}, {"resource-development", "Resource Development"},
	{"initial-access", "Initial Access"}, {"execution", "Execution"},
	{"persistence", "Persistence"}, {"privilege-escalation", "Privilege Escalation"},
	{"defense-evasion", "Defense Evasion"}, {"credential-access", "Credential Access"},
	{"discovery", "Discovery"}, {"lateral-movement", "Lateral Movement"},
	{"collection", "Collection"}, {"command-and-control", "Command and Control"},
	{"exfiltration", "Exfiltration"}, {"impact", "Impact"},
}

// AttackMatrix returns the authoritative enterprise matrix: tactics (in
// kill-chain order) each with their techniques {id,name}. A technique that
// belongs to several tactics appears under each (matching ATT&CK Navigator).
// Coverage status is overlaid by the client from run data, so this structure
// stays static and cacheable. GET /api/attack/matrix
func (h *Handler) AttackMatrix(w http.ResponseWriter, r *http.Request) {
	byTactic := map[string][]map[string]string{}
	for _, t := range attackdata.All() {
		for _, tac := range t.Tactics {
			byTactic[tac] = append(byTactic[tac], map[string]string{"id": t.ID, "name": t.Name})
		}
	}
	tactics := make([]map[string]any, 0, len(enterpriseTactics))
	for _, tac := range enterpriseTactics {
		techs := byTactic[tac.ID]
		if techs == nil {
			techs = []map[string]string{}
		}
		tactics = append(tactics, map[string]any{"id": tac.ID, "name": tac.Name, "techniques": techs})
	}
	respond(w, map[string]any{"tactics": tactics})
}

// AttackTechnique returns the authoritative enrichment for one technique.
// GET /api/attack/technique/{id}
func (h *Handler) AttackTechnique(w http.ResponseWriter, r *http.Request) {
	e := attackdata.Lookup(chi.URLParam(r, "id"))
	if e == nil {
		jsonError(w, "technique not found", http.StatusNotFound)
		return
	}
	respond(w, e)
}
