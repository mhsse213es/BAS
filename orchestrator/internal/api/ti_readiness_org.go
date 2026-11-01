package api

import (
	"math"
	"net/http"
	"sort"
	"time"
)

// Organisation-level threat-actor readiness (Phase 2).
//
// The per-agent readiness history records, for each (run, actor), a prevention
// percentage and the number of tested techniques behind it. The organisation
// figure is NOT an average of agent percentages: it pools technique counts.
//
//	prevented(row) = round(prevention% × tested / 100)
//	org latest(actor) = Σ prevented over each agent's LATEST assessment of the actor
//	                    ÷ Σ tested over the same rows  × 100
//
// Each agent contributes its most recent assessment only, so a fleet is not
// weighted by how often a machine happened to be tested. The daily trend pools
// every assessment recorded that day in the same way. An actor with no tested
// techniques anywhere is omitted rather than shown as 0%.
//
// Rows are pooled as technique results, so an agent that tested 40 techniques
// counts 40 times and one that tested 4 counts 4 times. That is the intended
// weighting: it reflects how much evidence each row carries.

// readinessRow is one threat_readiness_history row, reduced to what pooling needs.
type readinessRow struct {
	AgentID    string
	Actor      string
	Prevention float64
	Tested     int
	RecordedAt time.Time
}

// orgReadinessPoint is one day's pooled prevention for an actor.
type orgReadinessPoint struct {
	Date       string  `json:"date"`
	Prevention float64 `json:"prevention"`
	Tested     int     `json:"tested"`
}

// orgActorReadiness is the organisation-level readiness for one actor.
type orgActorReadiness struct {
	ActorName        string              `json:"actorName"`
	AgentCount       int                 `json:"agentCount"`
	PreventedTechs   int                 `json:"preventedTechniques"`
	TestedTechs      int                 `json:"testedTechniques"`
	LatestPrevention float64             `json:"latestPrevention"`
	PreventionDelta  float64             `json:"preventionDelta"`
	Direction        string              `json:"direction"`
	History          []orgReadinessPoint `json:"history"`
}

func preventedOf(r readinessRow) int {
	return int(math.Round(r.Prevention * float64(r.Tested) / 100))
}

// readinessPct returns prevented/tested as a percentage rounded to one decimal place.
func readinessPct(prevented, tested int) float64 {
	return math.Round(float64(prevented)/float64(tested)*1000) / 10
}

// buildOrgReadiness pools readiness rows into organisation-level figures. Pure: no I/O.
func buildOrgReadiness(rows []readinessRow) []orgActorReadiness {
	type agentKey struct{ agent, actor string }
	latest := map[agentKey]readinessRow{}
	days := map[string]map[string]*orgReadinessPoint{} // actor -> date -> pooled point (prevented kept separately)
	dayPrevented := map[string]map[string]int{}

	for _, r := range rows {
		if r.Tested <= 0 {
			continue
		}
		k := agentKey{r.AgentID, r.Actor}
		if cur, ok := latest[k]; !ok || r.RecordedAt.After(cur.RecordedAt) {
			latest[k] = r
		}
		date := r.RecordedAt.UTC().Format("2006-01-02")
		if days[r.Actor] == nil {
			days[r.Actor] = map[string]*orgReadinessPoint{}
			dayPrevented[r.Actor] = map[string]int{}
		}
		p := days[r.Actor][date]
		if p == nil {
			p = &orgReadinessPoint{Date: date}
			days[r.Actor][date] = p
		}
		p.Tested += r.Tested
		dayPrevented[r.Actor][date] += preventedOf(r)
	}

	type agg struct {
		agents, prevented, tested int
	}
	byActor := map[string]*agg{}
	for k, r := range latest {
		a := byActor[k.actor]
		if a == nil {
			a = &agg{}
			byActor[k.actor] = a
		}
		a.agents++
		a.tested += r.Tested
		a.prevented += preventedOf(r)
	}

	out := make([]orgActorReadiness, 0, len(byActor))
	for actor, a := range byActor {
		if a.tested == 0 {
			continue
		}
		o := orgActorReadiness{ActorName: actor, AgentCount: a.agents, PreventedTechs: a.prevented,
			TestedTechs: a.tested, LatestPrevention: readinessPct(a.prevented, a.tested)}

		dates := make([]string, 0, len(days[actor]))
		for d := range days[actor] {
			dates = append(dates, d)
		}
		sort.Strings(dates)
		for _, d := range dates {
			p := days[actor][d]
			p.Prevention = readinessPct(dayPrevented[actor][d], p.Tested)
			o.History = append(o.History, *p)
		}
		if len(o.History) > 0 {
			o.PreventionDelta = math.Round((o.LatestPrevention-o.History[0].Prevention)*10) / 10
		}
		switch {
		case o.PreventionDelta > 1:
			o.Direction = "up"
		case o.PreventionDelta < -1:
			o.Direction = "down"
		default:
			o.Direction = "stable"
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LatestPrevention != out[j].LatestPrevention {
			return out[i].LatestPrevention < out[j].LatestPrevention
		}
		return out[i].ActorName < out[j].ActorName
	})
	return out
}

// GetTIReadinessOrg returns organisation-level readiness for every threat actor,
// pooled across agents as described above. Read-only (Viewer+).
// GET /api/ti/readiness/org?days=90
func (h *Handler) GetTIReadinessOrg(w http.ResponseWriter, r *http.Request) {
	days := 90
	rows, err := h.db.Query(r.Context(), `
		SELECT agent_id, actor_name, prevention, tested, recorded_at
		FROM threat_readiness_history
		WHERE recorded_at > NOW() - make_interval(days => $1)
		  AND tested > 0`, days)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var in []readinessRow
	for rows.Next() {
		var rr readinessRow
		var prev float32
		if rows.Scan(&rr.AgentID, &rr.Actor, &prev, &rr.Tested, &rr.RecordedAt) != nil {
			continue
		}
		rr.Prevention = float64(prev)
		in = append(in, rr)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	actors := buildOrgReadiness(in)
	agents := map[string]bool{}
	for _, rr := range in {
		agents[rr.AgentID] = true
	}
	respond(w, map[string]interface{}{
		"scope":      "organisation",
		"definition": "Prevented ÷ tested techniques, pooled across each agent's latest assessment of the actor. Not an average of agent percentages.",
		"windowDays": days,
		"agentCount": len(agents),
		"actorCount": len(actors),
		"actors":     actors,
	})
}
