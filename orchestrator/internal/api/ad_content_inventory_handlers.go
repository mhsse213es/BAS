package api

import (
	"net/http"

	"github.com/audspect/bas/internal/adlibinv"
	"github.com/audspect/bas/internal/adprimitive"
)

// contentInventoryResponse wraps the raw adlibinv.Report with the store-attachment
// state, so an empty inventory is never mistaken for a verified absence of
// content when a store simply is not loaded.
type contentInventoryResponse struct {
	ARTStoreLoaded     bool            `json:"artStoreLoaded"`
	CalderaStoreLoaded bool            `json:"calderaStoreLoaded"`
	ARTTechniques      int             `json:"artTechniques"`
	Report             adlibinv.Report `json:"report"`
	Note               string          `json:"note,omitempty"`
}

// GetADContentInventory runs the ART/Caldera library inventory for the full AD
// primitive set against the LIVE content stores and reports, per ATT&CK
// technique, whether reusable executable content actually exists.
//
// It is read-only: it queries the attached stores (GetSteps/GetAbilities) and
// executes nothing, mutates neither the stores, dispatch, nor the content-state
// classification. "missing" here means "not found in the attached store(s)",
// which is a verified absence only when both stores are loaded -- the response
// carries the store-attachment state and a note so that distinction is explicit.
func (h *Handler) GetADContentInventory(w http.ResponseWriter, r *http.Request) {
	// Guard against passing a typed-nil *ARTStore/*CalderaStore as a non-nil
	// interface (which adlibinv.Inventory would then call and panic on).
	var art adlibinv.ARTSource
	if h.artStore != nil {
		art = h.artStore
	}
	var caldera adlibinv.CalderaSource
	if h.calderaStore != nil {
		caldera = h.calderaStore
	}

	resp := contentInventoryResponse{
		ARTStoreLoaded:     h.artStore != nil,
		CalderaStoreLoaded: h.calderaStore != nil,
		Report:             adlibinv.Inventory(adprimitive.All(), art, caldera),
	}
	if h.artStore != nil {
		resp.ARTTechniques = h.artStore.Count()
	}
	switch {
	case art == nil && caldera == nil:
		resp.Note = "no content stores attached; the inventory reflects an empty library, not a verified absence of reusable content"
	case art == nil || caldera == nil:
		resp.Note = "only one content store is attached; 'missing' means not found in the attached store, not a verified absence across both libraries"
	}
	respond(w, resp)
}
