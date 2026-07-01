package tracker

import (
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Tracker is the HTTP service for exercise tracking events.
// It mounts at /x/* on the public (unauthenticated) section of the router.
type Tracker struct {
	tokens          TokenStore
	recorder        Recorder
	safeLandingHTML string
	credLandingHTML string
}

// New creates a Tracker with default landing pages.
func New(tokens TokenStore, recorder Recorder) *Tracker {
	return &Tracker{
		tokens:          tokens,
		recorder:        recorder,
		safeLandingHTML: defaultSafeLandingHTML,
		credLandingHTML: defaultCredLandingHTML,
	}
}

// WithSafeLanding overrides the default safe-landing HTML.
func (t *Tracker) WithSafeLanding(html string) *Tracker { t.safeLandingHTML = html; return t }

// WithCredLanding overrides the default credential-harvest HTML.
func (t *Tracker) WithCredLanding(html string) *Tracker { t.credLandingHTML = html; return t }

// HandleOpen serves the 1×1 open-tracking pixel.
// GET /x/open/{token}
func (t *Tracker) HandleOpen(w http.ResponseWriter, r *http.Request) {
	t.withToken(w, r, chi.URLParam(r, "token"), func(tok *TrackToken) {
		_ = t.tokens.RecordTokenUse(r.Context(), tok.Token)
		t.handleOpen(w, r, tok)
	})
}

// HandleClick records a link click and serves the landing page.
// GET /x/click/{token}
func (t *Tracker) HandleClick(w http.ResponseWriter, r *http.Request) {
	t.withToken(w, r, chi.URLParam(r, "token"), func(tok *TrackToken) {
		_ = t.tokens.RecordTokenUse(r.Context(), tok.Token)
		t.handleClick(w, r, tok)
	})
}

// HandleCredSubmit records a credential-harvest submission.
// POST /x/cred/{token}
func (t *Tracker) HandleCredSubmit(w http.ResponseWriter, r *http.Request) {
	t.withToken(w, r, chi.URLParam(r, "token"), func(tok *TrackToken) {
		_ = t.tokens.RecordTokenUse(r.Context(), tok.Token)
		t.handleCredSubmit(w, r, tok)
	})
}

// HandleReport records a phishing-report action.
// POST /x/report/{token}
func (t *Tracker) HandleReport(w http.ResponseWriter, r *http.Request) {
	t.withToken(w, r, chi.URLParam(r, "token"), func(tok *TrackToken) {
		_ = t.tokens.RecordTokenUse(r.Context(), tok.Token)
		t.handleReport(w, r, tok)
	})
}

// HandleWebhook records an inbound webhook call from an external system.
// POST /x/hook/{token}
// The response is always 200 OK so the external caller knows the POST succeeded.
// The trigger registry will fire the waiting step on the next executor tick.
func (t *Tracker) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	t.withToken(w, r, token, func(tok *TrackToken) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024)) // 64 KiB limit
		if wh, ok := t.tokens.(WebhookStore); ok {
			_ = wh.InsertWebhookCall(r.Context(), tok.Token, tok.ExecutionID, tok.StepExecID, body)
		}
		_ = t.recorder.Record(r.Context(), tok.ExecutionID, tok.StepExecID,
			"webhook_received", realIP(r), "inbound_webhook",
			map[string]any{"token": tok.Token, "content_type": r.Header.Get("Content-Type")})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}

// withToken resolves the token from the DB and calls fn. Returns 404 on miss.
func (t *Tracker) withToken(w http.ResponseWriter, r *http.Request, token string, fn func(*TrackToken)) {
	if token == "" {
		http.NotFound(w, r)
		return
	}
	tok, err := t.tokens.GetTrackToken(r.Context(), token)
	if err != nil {
		log.Printf("[tracker] token %q not found: %v", token, err)
		http.NotFound(w, r)
		return
	}
	fn(tok)
}

func realIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.SplitN(v, ",", 2)[0]
	}
	return r.RemoteAddr
}
