package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// handleOneDrivePut mimics Microsoft Graph's upload-by-path request shape
// (PUT .../root:/{path}:/content). The filename carries the token.
func handleOneDrivePut(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(chi.URLParam(r, "filename"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-onedrive", body)
		}
		w.WriteHeader(http.StatusOK)
	}
}
