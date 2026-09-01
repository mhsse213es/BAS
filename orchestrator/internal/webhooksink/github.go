package webhooksink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGitHubGist mimics GitHub's POST /gists request: a "files" map
// keyed by filename, whose sole key carries the token. The Authorization
// header's value is never validated -- presence fidelity only, matching
// every other channel's deliberate "no real signing/auth" bar. A request
// with no auth header at all is still accepted: this channel tests
// whether DLP inspected the traffic, not whether the caller authenticated.
func handleGitHubGist(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var payload struct {
			Files map[string]struct {
				Content string `json:"content"`
			} `json:"files"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			for filename := range payload.Files {
				token = strings.TrimSuffix(filename, ".dat")
				break
			}
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "coderepo-github", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"bas-sim-gist-id","html_url":"https://gist.github.com/bas-sim"}`))
	}
}
