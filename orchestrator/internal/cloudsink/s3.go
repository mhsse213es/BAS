package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// handleS3Put mimics AWS S3's path-style PUT-object request: the object key
// (the last path segment) carries the token as its filename, stripped of
// the .dat extension every scenario step uses. No real SigV4 signature is
// checked -- see the design spec's fidelity-bar decision.
func handleS3Put(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(chi.URLParam(r, "key"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-s3", body)
		}
		w.Header().Set("ETag", `"bas-sim-etag"`)
		w.WriteHeader(http.StatusOK)
	}
}
