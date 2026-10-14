package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkefficacy"
)

// maxNetworkControlExpectationImportRequestBytes mirrors every prior
// phase's import cap -- a real expectation document can be as large as
// a real policy or topology document.
const maxNetworkControlExpectationImportRequestBytes = 5 << 20

// CreateNetworkControlExpectationImport -- POST /api/network-control-expectations.
func (h *Handler) CreateNetworkControlExpectationImport(w http.ResponseWriter, r *http.Request) {
	var req networkefficacy.ControlExpectationImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkControlExpectationImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateControlExpectationImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertNetworkControlExpectationImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "networkcontrolexpectation.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkcontrolexpectation.import", req.ID, map[string]any{"expectationCount": len(req.Expectations)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateControlExpectationImport(imp *networkefficacy.ControlExpectationImport) error {
	if len(imp.Expectations) == 0 {
		return fmt.Errorf("at least one expectation is required")
	}
	if len(imp.Expectations) > networkefficacy.MaxExpectationsPerImport {
		return fmt.Errorf("too many expectations — got %d, max %d", len(imp.Expectations), networkefficacy.MaxExpectationsPerImport)
	}
	for i, exp := range imp.Expectations {
		if _, _, err := net.ParseCIDR(exp.FlowSourceCIDR); err != nil {
			return fmt.Errorf("expectations[%d]: invalid flowSourceCidr %q", i, exp.FlowSourceCIDR)
		}
		if _, _, err := net.ParseCIDR(exp.FlowDestCIDR); err != nil {
			return fmt.Errorf("expectations[%d]: invalid flowDestCidr %q", i, exp.FlowDestCIDR)
		}
		if exp.FlowPort < 1 || exp.FlowPort > 65535 {
			return fmt.Errorf("expectations[%d]: flowPort must be between 1 and 65535", i)
		}
		if exp.ExpectedAction != networkefficacy.ExpectedBlock && exp.ExpectedAction != networkefficacy.ExpectedAlert {
			return fmt.Errorf("expectations[%d]: expectedAction must be %q or %q", i, networkefficacy.ExpectedBlock, networkefficacy.ExpectedAlert)
		}
	}
	return nil
}

// ListNetworkControlExpectationImports -- GET /api/network-control-expectations.
func (h *Handler) ListNetworkControlExpectationImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListNetworkControlExpectationImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*networkefficacy.ControlExpectationImport{}
	}
	respond(w, imports)
}

// GetNetworkControlExpectationImport -- GET /api/network-control-expectations/{id}.
func (h *Handler) GetNetworkControlExpectationImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetNetworkControlExpectationImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network control expectation import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
