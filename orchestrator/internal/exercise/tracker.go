package exercise

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Tracker handles inbound tracking requests (open pixels, click redirects,
// phishing-report submissions, credential harvest submissions).
// Routes are mounted at /x/* on the public (unauthenticated) section of the router.
type Tracker struct {
	store *Store
	chain *EvidenceChain
	// SafeLandingHTML is served when a tracked link is clicked and LandingPage="safe".
	SafeLandingHTML string
	// CredLandingHTML is the credential harvest page (served for LandingPage="cred").
	CredLandingHTML string
}

func NewTracker(store *Store, chain *EvidenceChain) *Tracker {
	return &Tracker{
		store:           store,
		chain:           chain,
		SafeLandingHTML: defaultSafeLandingHTML,
		CredLandingHTML: defaultCredLandingHTML,
	}
}

// HandleOpen serves the 1×1 tracking pixel and records an email_opened event.
// GET /x/open/{token}
func (t *Tracker) HandleOpen(w http.ResponseWriter, r *http.Request) {
	token := chi_param(r, "token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	tok, err := t.store.GetTrackToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = t.store.RecordTokenUse(r.Context(), token)
	if tok.UsedCount == 0 {
		payload := map[string]interface{}{
			"token":     token,
			"target_id": tok.TargetID,
			"ip":        realIP(r),
			"ua":        r.UserAgent(),
			"ts":        time.Now().UTC(),
		}
		_, _ = t.chain.Append(r.Context(), tok.ExecutionID, tok.StepExecID,
			"email_opened", tok.TargetID, realIP(r), payload)
	}
	// 1×1 transparent GIF
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write([]byte("\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"))
}

// HandleClick records a link_clicked event and redirects to the landing page.
// GET /x/click/{token}
func (t *Tracker) HandleClick(w http.ResponseWriter, r *http.Request) {
	token := chi_param(r, "token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	tok, err := t.store.GetTrackToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = t.store.RecordTokenUse(r.Context(), token)
	payload := map[string]interface{}{
		"token":     token,
		"target_id": tok.TargetID,
		"ip":        realIP(r),
		"ua":        r.UserAgent(),
		"ts":        time.Now().UTC(),
		"count":     tok.UsedCount + 1,
	}
	_, _ = t.chain.Append(r.Context(), tok.ExecutionID, tok.StepExecID,
		"link_clicked", tok.TargetID, realIP(r), payload)

	// Choose landing page.
	landing := ""
	if tok.Payload != nil {
		landing, _ = tok.Payload["landing"].(string)
	}
	switch landing {
	case "cred":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(t.CredLandingHTML))
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(t.SafeLandingHTML))
	}
}

// HandleCredSubmit records credential submission evidence.
// POST /x/cred/{token}
func (t *Tracker) HandleCredSubmit(w http.ResponseWriter, r *http.Request) {
	token := chi_param(r, "token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	tok, err := t.store.GetTrackToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = t.store.RecordTokenUse(r.Context(), token)
	payload := map[string]interface{}{
		"token":     token,
		"target_id": tok.TargetID,
		"ip":        realIP(r),
		"ua":        r.UserAgent(),
		"ts":        time.Now().UTC(),
		// We intentionally do NOT store the submitted credential values —
		// only the fact that a submission occurred.
		"submitted": true,
	}
	_, _ = t.chain.Append(r.Context(), tok.ExecutionID, tok.StepExecID,
		"credentials_submitted", tok.TargetID, realIP(r), payload)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleReport records a phishing-reported event (when a user clicks "Report").
// POST /x/report/{token}
func (t *Tracker) HandleReport(w http.ResponseWriter, r *http.Request) {
	token := chi_param(r, "token")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	tok, err := t.store.GetTrackToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = t.store.RecordTokenUse(r.Context(), token)
	payload := map[string]interface{}{
		"token":     token,
		"target_id": tok.TargetID,
		"ip":        realIP(r),
		"ts":        time.Now().UTC(),
	}
	_, _ = t.chain.Append(r.Context(), tok.ExecutionID, tok.StepExecID,
		"phishing_reported", tok.TargetID, realIP(r), payload)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Thank you for reporting this email."})
}

func chi_param(r *http.Request, key string) string {
	return chi.URLParam(r, key)
}

func realIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.SplitN(v, ",", 2)[0]
	}
	return r.RemoteAddr
}

// ── Default landing page HTML ─────────────────────────────────────────────────

const defaultSafeLandingHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Awareness</title>
<style>body{font-family:sans-serif;max-width:600px;margin:80px auto;padding:20px;text-align:center}
.warn{background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:24px;margin:24px 0}
h2{color:#856404}</style></head>
<body>
<div class="warn">
  <h2>⚠ This was a security awareness test</h2>
  <p>You clicked a simulated phishing link as part of an authorised cyber exercise.</p>
  <p>No data was captured. If you receive a similar email in real life, please report it immediately.</p>
</div>
</body></html>`

const defaultCredLandingHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:20px}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:10px;background:#0b5394;color:#fff;border:0;border-radius:4px;cursor:pointer}</style></head>
<body>
<h2>Sign in</h2>
<form id="f">
  <input type="text" name="username" placeholder="Username" autocomplete="username">
  <input type="password" name="password" placeholder="Password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
<script>
document.getElementById('f').addEventListener('submit',function(e){
  e.preventDefault();
  fetch(location.href,{method:'POST',body:new FormData(this)})
    .then(()=>{document.body.innerHTML='<div style="margin:80px auto;max-width:400px;padding:20px;text-align:center"><h2 style="color:#856404">⚠ Security Awareness Test</h2><p>You entered credentials into a simulated phishing page. No passwords were stored. Please report suspicious emails immediately.</p></div>'});
});
</script>
</body></html>`
