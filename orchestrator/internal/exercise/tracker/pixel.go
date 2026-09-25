package tracker

import (
	"net/http"
	"time"
)

// gif1x1 is a 1×1 transparent GIF.
var gif1x1 = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

func (t *Tracker) handleOpen(w http.ResponseWriter, r *http.Request, tok *TrackToken) {
	if tok.UsedCount == 0 {
		// r.RemoteAddr is already trust-aware here -- see handler.go's
		// HandleWebhook for the full rationale (same shared router, same
		// trustedRealIP middleware upstream).
		payload := map[string]any{
			"target_id": tok.TargetID,
			"ip":        r.RemoteAddr,
			"ua":        r.UserAgent(),
			"ts":        time.Now().UTC(),
		}
		_ = t.recorder.Record(r.Context(), tok.ExecutionID, tok.StepExecID,
			"email_opened", tok.TargetID, r.RemoteAddr, payload)
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	_, _ = w.Write(gif1x1)
}
