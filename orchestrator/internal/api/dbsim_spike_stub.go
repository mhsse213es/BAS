//go:build !dbsim_spike

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// TEMPORARY (dbsim run-experience Task 1 spike). Untagged no-op stubs so the
// call sites in routes.go and SubmitScenarioResult compile without the spike.
// Removed together with dbsim_spike.go and the two call lines at Task 1 Step 4.

func registerDBSimSpikeRoutes(_ chi.Router, _ *Handler) {}

func dbsimSpikeHook(_ *Handler, _ http.ResponseWriter, _ []byte) bool { return false }
