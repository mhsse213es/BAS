package tracker

import (
	"net/http"
	"time"
)

func (t *Tracker) handleClick(w http.ResponseWriter, r *http.Request, tok *TrackToken) {
	payload := map[string]any{
		"target_id": tok.TargetID,
		"ip":        realIP(r),
		"ua":        r.UserAgent(),
		"ts":        time.Now().UTC(),
		"count":     tok.UsedCount + 1,
	}
	_ = t.recorder.Record(r.Context(), tok.ExecutionID, tok.StepExecID,
		"link_clicked", tok.TargetID, realIP(r), payload)

	landing := ""
	if tok.Payload != nil {
		landing, _ = tok.Payload["landing"].(string)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch landing {
	case "cred":
		_, _ = w.Write([]byte(t.credLandingHTML))
	default:
		_, _ = w.Write([]byte(t.safeLandingHTML))
	}
}
