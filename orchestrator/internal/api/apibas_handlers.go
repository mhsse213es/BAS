package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
)

// Read-only results API for stored API BAS runs. Every route is behind auth.CanViewAPIBASRuns. Installations
// are isolated by database, so the permission is the authorization boundary; no tenant column is needed.
//
// The detail view returns evidence references, not response bodies. Each exchange is listed by run tag and
// index, with its step, method, path, status and redacted-leak count. Bodies are not exposed here.

type apibasRunSummary struct {
	ID             string    `json:"id"`
	RunTag         string    `json:"run_tag"`
	ScenarioID     string    `json:"scenario_id"`
	Build          string    `json:"build"`
	Protocol       string    `json:"protocol"`
	Result         string    `json:"result"`
	Exploitability string    `json:"exploitability"`
	Control        string    `json:"control"`
	Detection      string    `json:"detection"`
	Reason         string    `json:"reason"`
	StartedAt      time.Time `json:"started_at"`
	CreatedAt      time.Time `json:"created_at"`
}

type apibasEvidenceRef struct {
	Ref          string `json:"ref"`
	StepID       string `json:"step_id"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Status       int    `json:"status"`
	LeakedValues int    `json:"leaked_values"`
}

type apibasRunDetail struct {
	apibasRunSummary
	Detail           string              `json:"detail,omitempty"`
	DetectionReason  string              `json:"detection_reason,omitempty"`
	DetectionResults map[string]string   `json:"detection_results,omitempty"`
	TimingVerdict    string              `json:"timing_verdict,omitempty"`
	Evidence         []apibasEvidenceRef `json:"evidence"`
}

// storedReport is the subset of the stored report the API reads. Response bodies are not decoded, so they
// cannot reach the response.
type storedReport struct {
	Detail           string            `json:"Detail"`
	DetectionReason  string            `json:"DetectionReason"`
	DetectionResults map[string]string `json:"DetectionResults"`
	TimingVerdict    string            `json:"TimingVerdict"`
	Exchanges        []struct {
		StepID string `json:"StepID"`
		Method string `json:"Method"`
		Path   string `json:"Path"`
		Status int    `json:"Status"`
		Leaked int    `json:"Leaked"`
	} `json:"Exchanges"`
}

func summaryOf(r db.APIBASRun) apibasRunSummary {
	return apibasRunSummary{
		ID: r.ID, RunTag: r.RunTag, ScenarioID: r.ScenarioID, Build: r.Build, Protocol: r.Protocol,
		Result: r.Result, Exploitability: r.Exploitability, Control: r.Control, Detection: r.Detection,
		Reason: r.Reason, StartedAt: r.StartedAt, CreatedAt: r.CreatedAt,
	}
}

// ListAPIBASRuns returns stored runs, newest first. Optional scenario filter and limit (1 to 500).
func (h *Handler) ListAPIBASRuns(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			jsonError(w, "limit must be between 1 and 500", http.StatusBadRequest)
			return
		}
		limit = n
	}
	runs, err := db.ListAPIBASRuns(r.Context(), h.db, r.URL.Query().Get("scenario"), limit)
	if err != nil {
		jsonError(w, "could not list apibas runs", http.StatusInternalServerError)
		return
	}
	out := make([]apibasRunSummary, 0, len(runs))
	for _, run := range runs {
		out = append(out, summaryOf(run))
	}
	respond(w, map[string]any{"runs": out})
}

// GetAPIBASRun returns one stored run with its verdicts, detection outcome, errors and evidence references.
func (h *Handler) GetAPIBASRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetAPIBASRun(r.Context(), h.db, id)
	if errors.Is(err, db.ErrAPIBASRunNotFound) {
		jsonError(w, "apibas run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load apibas run", http.StatusInternalServerError)
		return
	}
	var rep storedReport
	if err := json.Unmarshal([]byte(run.Report), &rep); err != nil {
		jsonError(w, "stored report is unreadable", http.StatusInternalServerError)
		return
	}
	detail := apibasRunDetail{
		apibasRunSummary: summaryOf(run),
		Detail:           rep.Detail,
		DetectionReason:  rep.DetectionReason,
		DetectionResults: rep.DetectionResults,
		TimingVerdict:    rep.TimingVerdict,
		Evidence:         []apibasEvidenceRef{},
	}
	for i, ex := range rep.Exchanges {
		detail.Evidence = append(detail.Evidence, apibasEvidenceRef{
			Ref:          fmt.Sprintf("%s#%d", run.RunTag, i),
			StepID:       ex.StepID,
			Method:       ex.Method,
			Path:         ex.Path,
			Status:       ex.Status,
			LeakedValues: ex.Leaked,
		})
	}
	respond(w, detail)
}
