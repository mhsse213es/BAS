package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/riskinputs"
	"github.com/audspect/bas/internal/riskquant"
	"github.com/go-chi/chi/v5"
)

// riskRange is the wire form of a low / likely / high estimate.
type riskRange struct {
	Low    float64 `json:"low"`
	Likely float64 `json:"likely"`
	High   float64 `json:"high"`
}

func (r riskRange) toQuant() *riskquant.Range {
	return &riskquant.Range{Low: r.Low, Likely: r.Likely, High: r.High}
}

// riskInputBody is the body of PUT /api/risk/inputs/{technique}. A missing range is an error, not zero.
type riskInputBody struct {
	Label     string     `json:"label"`
	Frequency *riskRange `json:"frequency"`
	Magnitude *riskRange `json:"magnitude"`
}

type riskInputView struct {
	TechniqueID string    `json:"techniqueId"`
	Label       string    `json:"label"`
	Frequency   riskRange `json:"frequency"`
	Magnitude   riskRange `json:"magnitude"`
	UpdatedBy   string    `json:"updatedBy"`
	UpdatedAt   string    `json:"updatedAt"`
	Version     int64     `json:"version"`
}

type riskHistoryView struct {
	TechniqueID string               `json:"techniqueId"`
	Action      string               `json:"action"`
	Previous    *riskinputs.Snapshot `json:"previous"`
	Current     *riskinputs.Snapshot `json:"current"`
	Actor       string               `json:"actor"`
	ChangedAt   string               `json:"changedAt"`
}

// GetRiskInputs returns the deployment currency and the stored inputs. Any signed-in user, like the
// board report that already shows the figure.
// GET /api/risk/inputs
func (h *Handler) GetRiskInputs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cur, err := riskinputs.Currency(ctx, h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list, err := riskinputs.List(ctx, h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]riskInputView, 0, len(list))
	for _, in := range list {
		out = append(out, riskInputView{
			TechniqueID: in.TechniqueID, Label: in.Label,
			Frequency: riskRange{in.Frequency.Low, in.Frequency.Likely, in.Frequency.High},
			Magnitude: riskRange{in.Magnitude.Low, in.Magnitude.Likely, in.Magnitude.High},
			UpdatedBy: in.UpdatedBy, UpdatedAt: in.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"), Version: in.Version,
		})
	}
	respond(w, map[string]any{"currency": cur, "inputs": out})
}

// GetRiskInputHistory returns every recorded change for one technique, oldest first.
// GET /api/risk/inputs/{technique}/history
func (h *Handler) GetRiskInputHistory(w http.ResponseWriter, r *http.Request) {
	tech := chi.URLParam(r, "technique")
	hist, err := riskinputs.History(r.Context(), h.db, tech)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]riskHistoryView, 0, len(hist))
	for _, e := range hist {
		out = append(out, riskHistoryView{
			TechniqueID: e.TechniqueID, Action: e.Action,
			Previous: e.Previous, Current: e.Current,
			Actor: e.Actor, ChangedAt: e.ChangedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	respond(w, out)
}

// SetRiskCurrency sets the deployment currency. Admin only. PUT /api/risk/currency
func (h *Handler) SetRiskCurrency(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Currency string `json:"currency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	actor := riskActor(r)
	prev, err := riskinputs.SetCurrency(r.Context(), h.db, strings.TrimSpace(body.Currency), actor)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.auditLog(r, "risk.currency.set", "risk_settings", map[string]any{"previous": prev, "current": body.Currency}, "ok")
	respond(w, map[string]any{"currency": body.Currency})
}

// PutRiskInput sets the input for one technique. Admin only. PUT /api/risk/inputs/{technique}
func (h *Handler) PutRiskInput(w http.ResponseWriter, r *http.Request) {
	tech := chi.URLParam(r, "technique")
	var body riskInputBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.Frequency == nil || body.Magnitude == nil {
		jsonError(w, "frequency and magnitude are both required; a missing value is not treated as zero", http.StatusBadRequest)
		return
	}
	actor := riskActor(r)
	in := riskinputs.Input{
		TechniqueID: tech, Label: body.Label,
		Frequency: *body.Frequency.toQuant(), Magnitude: *body.Magnitude.toQuant(),
	}
	saved, err := riskinputs.Put(r.Context(), h.db, in, actor)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.auditLog(r, "risk.input.set", tech, map[string]any{"version": saved.Version}, "ok")
	respond(w, map[string]any{"techniqueId": tech, "version": saved.Version})
}

// DeleteRiskInput clears one technique's input, so it is unquantified again. Admin only.
// DELETE /api/risk/inputs/{technique}
func (h *Handler) DeleteRiskInput(w http.ResponseWriter, r *http.Request) {
	tech := chi.URLParam(r, "technique")
	err := riskinputs.Clear(r.Context(), h.db, tech, riskActor(r))
	if errors.Is(err, riskinputs.ErrNotFound) {
		jsonError(w, "no input stored for this technique", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.auditLog(r, "risk.input.clear", tech, nil, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// riskActor is the authenticated user's ID. Empty means no authenticated claims, which the store refuses.
func riskActor(r *http.Request) string {
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		return claims.UserID
	}
	return ""
}

// riskQuantification builds the loss estimate for one report. It returns nil, with no error, when no
// currency is set, or when no open finding in the report has stored inputs. A report without inputs
// therefore keeps hiding the card.
func (h *Handler) riskQuantification(ctx context.Context, rep *reporting.FullReport) (*riskquant.Summary, error) {
	cur, err := riskinputs.Currency(ctx, h.db)
	if err != nil || cur == "" {
		return nil, err
	}
	inputs, err := riskinputs.List(ctx, h.db)
	if err != nil {
		return nil, err
	}
	open := make([]riskinputs.OpenFinding, 0, len(rep.TopFindings))
	for _, f := range rep.TopFindings {
		open = append(open, riskinputs.OpenFinding{TechniqueID: f.TechniqueID, Label: f.TechniqueName})
	}
	exposures := riskinputs.ExposuresForReport(open, inputs)
	if !riskinputs.AnyInput(exposures) {
		return nil, nil
	}
	s, err := riskquant.Compute(cur, exposures)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
