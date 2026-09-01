package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// handleAzureBlobPut mimics Azure Blob Storage's PUT Blob request: the
// blob name (the last path segment) carries the token. Real Azure Blob PUT
// Blob returns 201 Created on success, unlike S3's 200 OK -- matched here
// so a DLP/CASB product's status-code expectations aren't a tell that this
// is a simulation.
func handleAzureBlobPut(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(chi.URLParam(r, "blob"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-azureblob", body)
		}
		w.WriteHeader(http.StatusCreated)
	}
}
