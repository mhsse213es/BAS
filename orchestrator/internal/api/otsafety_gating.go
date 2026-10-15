package api

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networktopology"
	"github.com/audspect/bas/internal/otsafety"
)

// resolveOTSafetyGatingContext resolves the topology and ot-safety
// import context an active-probe handler needs to run
// otsafety.CheckActiveTestAuthorization. Each id is resolved
// independently: an explicit, caller-supplied id is loaded directly
// (404 if it does not exist); an omitted id falls back to the most
// recently created import of that type, so a request that never
// mentions either field still gets gated against whatever the
// operator has declared, instead of silently skipping the check.
//
// When no import of a given type has EVER been created, that half of
// the returned context is nil -- callers must treat this as fail-open
// (nothing was ever declared, so there is nothing to check). A
// genuine lookup failure -- anything other than "never created" --
// writes an error response and returns ok=false: the caller MUST fail
// closed and must not proceed as if nothing had been imported.
func (h *Handler) resolveOTSafetyGatingContext(w http.ResponseWriter, r *http.Request, topologyImportID, otSafetyImportID string) (topo *networktopology.TopologyImport, safety *otsafety.OTSafetyImport, ok bool) {
	if topologyImportID != "" {
		t, err := db.GetNetworkTopologyImport(r.Context(), h.db, topologyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "network topology import not found", http.StatusNotFound)
				return nil, nil, false
			}
			jsonError(w, "failed to load the declared network topology import: "+err.Error(), http.StatusInternalServerError)
			return nil, nil, false
		}
		topo = t
	} else {
		latest, err := db.ListNetworkTopologyImports(r.Context(), h.db, 1)
		if err != nil {
			jsonError(w, "failed to resolve the current network topology import for OT/ICS safety gating: "+err.Error(), http.StatusInternalServerError)
			return nil, nil, false
		}
		if len(latest) > 0 {
			topo = latest[0]
		}
	}

	if otSafetyImportID != "" {
		s, err := db.GetOTSafetyImport(r.Context(), h.db, otSafetyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "ot safety import not found", http.StatusNotFound)
				return nil, nil, false
			}
			jsonError(w, "failed to load the declared ot safety import: "+err.Error(), http.StatusInternalServerError)
			return nil, nil, false
		}
		safety = s
	} else {
		latest, err := db.ListOTSafetyImports(r.Context(), h.db, 1)
		if err != nil {
			jsonError(w, "failed to resolve the current ot safety import for OT/ICS safety gating: "+err.Error(), http.StatusInternalServerError)
			return nil, nil, false
		}
		if len(latest) > 0 {
			safety = latest[0]
		}
	}

	return topo, safety, true
}
