package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/audspect/bas/internal/analytics"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// GET /api/ti/readiness?agentId=&runId=
// Returns per-ATT&CK-group readiness scores derived from the most recent
// (or specified) run's TechniqueMatrix. No external API required — uses the
// bundled MITRE ATT&CK STIX enrichment. Groups with <3 tested techniques
// are excluded. Results sorted worst prevention readiness first.
func (h *Handler) GetTIReadiness(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		http.Error(w, "reporting engine not available", http.StatusServiceUnavailable)
		return
	}

	runID := r.URL.Query().Get("runId")
	agentID := r.URL.Query().Get("agentId")

	var matrix []reporting.TechniqueRow

	switch {
	case runID != "":
		rep, err := h.reportingEngine.BuildFromRun(r.Context(), runID, "")
		if err != nil {
			http.Error(w, "run not found", http.StatusNotFound)
			return
		}
		matrix = rep.TechniqueMatrix
	case agentID != "":
		rep, err := h.reportingEngine.Build(r.Context(), agentID, "")
		if err != nil {
			http.Error(w, "agent not found or no runs", http.StatusNotFound)
			return
		}
		matrix = rep.TechniqueMatrix
	default:
		http.Error(w, "agentId or runId required", http.StatusBadRequest)
		return
	}

	scores := reporting.BuildReadinessScores(matrix)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scores": scores,
		"total":  len(scores),
	})
}

// ── Suggest-Pack ──────────────────────────────────────────────────────────────

type packTech struct {
	TechniqueID      string `json:"techniqueId"`
	Name             string `json:"name"`
	Tactic           string `json:"tactic"`
	KEVCount         int    `json:"kevCount,omitempty"`
	RansomwareLinked bool   `json:"ransomwareLinked,omitempty"`
}

type packMeta struct {
	Type        string
	Name        string
	Description string
	Tags        []string
	IDPrefix    string
}

var packMetas = map[string]packMeta{
	"kev": {
		Type:        "kev",
		Name:        "CISA KEV Exposure Pack",
		Description: "Validates controls against ATT&CK techniques linked to active CISA Known Exploited Vulnerabilities.",
		Tags:        []string{"kev", "cisa", "threat-informed"},
		IDPrefix:    "kev-pack",
	},
	"ransomware": {
		Type:        "ransomware",
		Name:        "Ransomware Readiness Pack",
		Description: "Validates controls against ATT&CK techniques used by known ransomware threat actors (LockBit, Cl0p, Black Basta, Conti, ALPHV, and others).",
		Tags:        []string{"ransomware", "threat-informed"},
		IDPrefix:    "ransomware-pack",
	},
	"credential-theft": {
		Type:        "credential-theft",
		Name:        "Credential Theft Pack",
		Description: "Validates controls against ATT&CK credential-access techniques — password dumping, token theft, and credential harvesting.",
		Tags:        []string{"credential-access", "threat-informed"},
		IDPrefix:    "cred-theft-pack",
	},
	"living-off-the-land": {
		Type:        "living-off-the-land",
		Name:        "Living-Off-The-Land Pack",
		Description: "Validates controls against LOLBin and signed-binary proxy execution techniques that evade signature-based defenses.",
		Tags:        []string{"lotl", "lolbin", "threat-informed"},
		IDPrefix:    "lotl-pack",
	},
	"powershell-abuse": {
		Type:        "powershell-abuse",
		Name:        "PowerShell Abuse Pack",
		Description: "Validates controls against PowerShell execution, obfuscation, and download cradle techniques.",
		Tags:        []string{"powershell", "execution", "threat-informed"},
		IDPrefix:    "ps-abuse-pack",
	},
	"lateral-movement": {
		Type:        "lateral-movement",
		Name:        "Lateral Movement Pack",
		Description: "Validates controls against ATT&CK lateral-movement techniques — pass-the-hash, remote services, and network share exploitation.",
		Tags:        []string{"lateral-movement", "threat-informed"},
		IDPrefix:    "lat-move-pack",
	},
}

// GET /api/ti/suggest-pack?type=<packType>
// Supported types: kev, ransomware, credential-theft, living-off-the-land,
// powershell-abuse, lateral-movement.
// Returns a technique list and a suggestedScenario body ready to POST to /api/scenarios.
func (h *Handler) GetSuggestPack(w http.ResponseWriter, r *http.Request) {
	packType := r.URL.Query().Get("type")
	meta, ok := packMetas[packType]
	if !ok {
		http.Error(w, "unknown pack type; supported: kev, ransomware, credential-theft, living-off-the-land, powershell-abuse, lateral-movement", http.StatusBadRequest)
		return
	}

	var techs []packTech
	var extraMeta map[string]interface{}
	var err error

	switch packType {
	case "kev":
		techs, extraMeta, err = h.kevPackTechs(r)
	case "ransomware":
		techs, err = h.ransomwarePackTechs(r)
	case "credential-theft":
		techs, err = h.tacticPackTechs(r, "credential-access")
	case "lateral-movement":
		techs, err = h.tacticPackTechs(r, "lateral-movement")
	case "living-off-the-land":
		techs, err = h.idListPackTechs(r, lotlTechIDs)
	case "powershell-abuse":
		techs, err = h.idListPackTechs(r, psAbuseTechIDs)
	}
	if err != nil {
		http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ids := make([]string, len(techs))
	for i, t := range techs {
		ids[i] = t.TechniqueID
	}

	now := time.Now().UTC()
	suggestedName := fmt.Sprintf("%s — %s", meta.Name, now.Format("2006-01-02"))
	suggestedID := fmt.Sprintf("%s-%s", meta.IDPrefix, now.Format("20060102"))

	resp := map[string]interface{}{
		"packType":       meta.Type,
		"packName":       meta.Name,
		"description":    meta.Description,
		"techniqueCount": len(techs),
		"techniques":     techs,
		"hasData":        len(techs) > 0,
		"suggestedName":  suggestedName,
		"suggestedId":    suggestedID,
		"suggestedScenario": map[string]interface{}{
			"id":            suggestedID,
			"name":          suggestedName,
			"description":   meta.Description,
			"tags":          meta.Tags,
			"artTechniques": ids,
		},
	}
	for k, v := range extraMeta {
		resp[k] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// kevPackTechs queries technique_cves+cves for ART-testable techniques with KEV CVEs.
func (h *Handler) kevPackTechs(r *http.Request) ([]packTech, map[string]interface{}, error) {
	rows, err := h.db.Query(r.Context(), `
		SELECT t.technique_id, t.name, t.tactic,
		       COUNT(*) AS kev_count,
		       bool_or(c.known_ransomware) AS ransomware_linked
		FROM technique_cves tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		JOIN techniques t ON t.technique_id = tc.technique_id
		WHERE EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = t.technique_id)
		GROUP BY t.technique_id, t.name, t.tactic
		ORDER BY kev_count DESC, ransomware_linked DESC, t.technique_id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var techs []packTech
	totalCVEs, ransomwareCount := 0, 0
	for rows.Next() {
		var t packTech
		var kevCount int
		var ransomware bool
		if err := rows.Scan(&t.TechniqueID, &t.Name, &t.Tactic, &kevCount, &ransomware); err != nil {
			continue
		}
		t.KEVCount = kevCount
		t.RansomwareLinked = ransomware
		totalCVEs += kevCount
		if ransomware {
			ransomwareCount++
		}
		techs = append(techs, t)
	}
	extra := map[string]interface{}{
		"totalKevCves":    totalCVEs,
		"ransomwareCount": ransomwareCount,
	}
	return techs, extra, rows.Err()
}

// ransomwarePackTechs returns ART-testable techniques used by ransomware ATT&CK groups.
func (h *Handler) ransomwarePackTechs(r *http.Request) ([]packTech, error) {
	idx := attackdata.GroupTechniqueIndex()
	ransomwareKeywords := []string{
		"lockbit", "clop", "cl0p", "black basta", "conti", "wizard spider",
		"revil", "gold southfield", "alphv", "blackcat", "scattered spider",
		"darkside", "carbon spider", "hive", "royal", "akira", "vice society",
		"play ransomware", "fin11", "ta505", "lazarus",
	}
	seen := map[string]bool{}
	var ids []string
	for groupName, techIDs := range idx {
		lower := strings.ToLower(groupName)
		matched := false
		for _, kw := range ransomwareKeywords {
			if strings.Contains(lower, kw) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, tid := range techIDs {
			if !seen[tid] {
				seen[tid] = true
				ids = append(ids, tid)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return h.techsFromIDs(r, ids)
}

// tacticPackTechs returns ART-testable techniques matching a specific ATT&CK tactic.
func (h *Handler) tacticPackTechs(r *http.Request, tactic string) ([]packTech, error) {
	rows, err := h.db.Query(r.Context(), `
		SELECT t.technique_id, t.name, t.tactic
		FROM techniques t
		WHERE t.tactic = $1
		  AND EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = t.technique_id)
		ORDER BY t.technique_id`, tactic)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var techs []packTech
	for rows.Next() {
		var t packTech
		if err := rows.Scan(&t.TechniqueID, &t.Name, &t.Tactic); err != nil {
			continue
		}
		techs = append(techs, t)
	}
	return techs, rows.Err()
}

// idListPackTechs returns ART-testable techniques from a hardcoded ID list.
func (h *Handler) idListPackTechs(r *http.Request, techIDs []string) ([]packTech, error) {
	return h.techsFromIDs(r, techIDs)
}

// techsFromIDs fetches technique metadata from the DB for a slice of technique IDs,
// filtered to those that have ART atomic tests available.
func (h *Handler) techsFromIDs(r *http.Request, ids []string) ([]packTech, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := h.db.Query(r.Context(), `
		SELECT t.technique_id, t.name, t.tactic
		FROM techniques t
		WHERE t.technique_id = ANY($1)
		  AND EXISTS (SELECT 1 FROM art_atomic_tests a WHERE a.technique_id = t.technique_id)
		ORDER BY t.tactic, t.technique_id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var techs []packTech
	for rows.Next() {
		var t packTech
		if err := rows.Scan(&t.TechniqueID, &t.Name, &t.Tactic); err != nil {
			continue
		}
		techs = append(techs, t)
	}
	return techs, rows.Err()
}

// lotlTechIDs is the curated LOLBin / Signed-Binary-Proxy Execution technique list.
var lotlTechIDs = []string{
	"T1218", "T1218.001", "T1218.002", "T1218.003", "T1218.004", "T1218.005",
	"T1218.007", "T1218.008", "T1218.009", "T1218.010", "T1218.011", "T1218.013",
	"T1059.001", "T1059.003", "T1059.005",
	"T1547.001", "T1053.005", "T1202", "T1127", "T1127.001",
	"T1036.003", "T1220", "T1197",
}

// psAbuseTechIDs is the curated PowerShell abuse technique list.
var psAbuseTechIDs = []string{
	"T1059.001", "T1059.003", "T1059.005", "T1059.006",
	"T1547.001", "T1218.011", "T1218.010",
	"T1562.001", "T1562.004",
	"T1055.001", "T1055.002",
	"T1543.003", "T1546.003",
	"T1027.010",
}

// ── Priority API ─────────────────────────────────────────────────────────────

// GET /api/ti/priority?agentId=&runId=
// Returns KEV+EPSS+threat-actor composite priority scores for the run's
// tested techniques. Sorted highest priority first.
func (h *Handler) GetTIPriority(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		http.Error(w, "reporting engine not available", http.StatusServiceUnavailable)
		return
	}

	runID := r.URL.Query().Get("runId")
	agentID := r.URL.Query().Get("agentId")

	var rep *reporting.FullReport
	var err error

	switch {
	case runID != "":
		rep, err = h.reportingEngine.BuildFromRun(r.Context(), runID, "")
	case agentID != "":
		rep, err = h.reportingEngine.Build(r.Context(), agentID, "")
	default:
		http.Error(w, "agentId or runId required", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	scores := rep.PriorityScores
	if scores == nil {
		scores = []reporting.TechniquePriority{}
	}

	critical, high, medium, low := 0, 0, 0, 0
	for _, s := range scores {
		switch s.PriorityTier {
		case "Critical":
			critical++
		case "High":
			high++
		case "Medium":
			medium++
		default:
			low++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scores": scores,
		"total":  len(scores),
		"tiers": map[string]interface{}{
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
		},
	})
}

// ── Readiness History ─────────────────────────────────────────────────────────

// historyEntry is one row from threat_readiness_history.
type historyEntry struct {
	RunID      string  `json:"runId"`
	ActorName  string  `json:"actorName"`
	Prevention float64 `json:"prevention"`
	Detection  float64 `json:"detection"`
	Tested     int     `json:"tested"`
	Total      int     `json:"total"`
	Confidence string  `json:"confidence"`
	RecordedAt string  `json:"recordedAt"`
}

// actorTrend aggregates the measurement series for one threat actor and
// computes the net change from the oldest to most recent entry.
type actorTrend struct {
	ActorName       string         `json:"actorName"`
	Latest          float64        `json:"latestPrevention"`
	LatestDetection float64        `json:"latestDetection"`
	Delta           float64        `json:"preventionDelta"` // latest - oldest
	DetectionDelta  float64        `json:"detectionDelta"`
	Direction       string         `json:"direction"` // "up"/"down"/"stable"
	DataPoints      int            `json:"dataPoints"`
	History         []historyEntry `json:"history"`
}

// GET /api/ti/readiness/history?agentId=&actor=&limit=
// Returns per-actor readiness history and trend summary for an agent.
// actor= filters to a single group; omit for all groups.
// limit= caps rows per actor (default 10, max 100).
func (h *Handler) GetTIReadinessHistory(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		http.Error(w, "agentId required", http.StatusBadRequest)
		return
	}
	actor := r.URL.Query().Get("actor")
	limit := 10
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if n, err := strconv.Atoi(ls); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	var query string
	var args []interface{}
	if actor != "" {
		query = `
			SELECT run_id, actor_name, prevention, detection, tested, total, confidence, recorded_at
			FROM threat_readiness_history
			WHERE agent_id = $1 AND actor_name = $2
			ORDER BY recorded_at DESC
			LIMIT $3`
		args = []interface{}{agentID, actor, limit}
	} else {
		query = `
			SELECT run_id, actor_name, prevention, detection, tested, total, confidence, recorded_at
			FROM (
				SELECT *, ROW_NUMBER() OVER (PARTITION BY actor_name ORDER BY recorded_at DESC) AS rn
				FROM threat_readiness_history
				WHERE agent_id = $1
			) sub
			WHERE rn <= $2
			ORDER BY actor_name, recorded_at DESC`
		args = []interface{}{agentID, limit}
	}
	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	actorMap := map[string]*actorTrend{}
	actorOrder := []string{}
	for rows.Next() {
		var e historyEntry
		var ts time.Time
		if err := rows.Scan(&e.RunID, &e.ActorName, &e.Prevention, &e.Detection,
			&e.Tested, &e.Total, &e.Confidence, &ts); err != nil {
			continue
		}
		e.RecordedAt = ts.UTC().Format(time.RFC3339)
		at, ok := actorMap[e.ActorName]
		if !ok {
			at = &actorTrend{ActorName: e.ActorName}
			actorMap[e.ActorName] = at
			actorOrder = append(actorOrder, e.ActorName)
		}
		at.History = append(at.History, e)
		at.DataPoints++
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	trends := make([]actorTrend, 0, len(actorOrder))
	for _, name := range actorOrder {
		at := actorMap[name]
		if len(at.History) == 0 {
			continue
		}
		// History is DESC (newest first).
		at.Latest = at.History[0].Prevention
		at.LatestDetection = at.History[0].Detection
		if len(at.History) > 1 {
			oldest := at.History[len(at.History)-1]
			at.Delta = math.Round((at.Latest-oldest.Prevention)*10) / 10
			at.DetectionDelta = math.Round((at.LatestDetection-oldest.Detection)*10) / 10
		}
		switch {
		case at.Delta > 1:
			at.Direction = "up"
		case at.Delta < -1:
			at.Direction = "down"
		default:
			at.Direction = "stable"
		}
		trends = append(trends, *at)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agentId": agentID,
		"trends":  trends,
		"total":   len(trends),
	})
}

// GET /api/analytics/threat-intel-summary — fleet-wide threat-intel posture:
// top prioritized actors plus CISA KEV exposure. Viewer+.
func (h *Handler) GetThreatIntelSummary(w http.ResponseWriter, r *http.Request) {
	result, err := analytics.ThreatIntelSummary(r.Context(), h.db, h.threatPriorityEngine)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
