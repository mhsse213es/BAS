package tracker

import (
	"encoding/json"
	"net/http"
	"time"
)

// Both handlers below read r.RemoteAddr directly -- already trust-aware by
// this point, see handler.go's HandleWebhook for the full rationale.

func (t *Tracker) handleCredSubmit(w http.ResponseWriter, r *http.Request, tok *TrackToken) {
	payload := map[string]any{
		"target_id": tok.TargetID,
		"ip":        r.RemoteAddr,
		"ua":        r.UserAgent(),
		"ts":        time.Now().UTC(),
		// We record the fact of submission, never the credential values.
		"submitted": true,
	}
	_ = t.recorder.Record(r.Context(), tok.ExecutionID, tok.StepExecID,
		"credentials_submitted", tok.TargetID, r.RemoteAddr, payload)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (t *Tracker) handleReport(w http.ResponseWriter, r *http.Request, tok *TrackToken) {
	payload := map[string]any{
		"target_id": tok.TargetID,
		"ip":        r.RemoteAddr,
		"ts":        time.Now().UTC(),
	}
	_ = t.recorder.Record(r.Context(), tok.ExecutionID, tok.StepExecID,
		"phishing_reported", tok.TargetID, r.RemoteAddr, payload)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "Thank you for reporting this email.",
	})
}
