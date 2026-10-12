package api

import (
	"net/http"

	"github.com/audspect/bas/internal/admatrix"
)

// GetADCoverage returns Audspect's Active Directory attack-capability coverage
// report: per-capability validation level, coverage status, prerequisites,
// execution method, evidence and telemetry requirements, cleanup and honest
// limitations, plus measurable summary counts traceable to each entry.
//
// It is read-only and sourced entirely from internal/admatrix (the single
// coverage catalog); it executes nothing and keeps model-simulated capabilities
// strictly distinct from executed or telemetry-observed ones.
func (h *Handler) GetADCoverage(w http.ResponseWriter, r *http.Request) {
	respond(w, admatrix.Report())
}
