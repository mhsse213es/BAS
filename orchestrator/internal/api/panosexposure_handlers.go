package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/panosexposure"
)

// maxPANOSAssets bounds one assessment request, so a single call cannot
// allocate an unbounded result set.
const maxPANOSAssets = 500

// panosAssessRequest is one advisory and the PAN-OS assets to assess against it.
// The advisory is supplied by the caller. Nothing about the vendor's affected
// versions is embedded in the server.
type panosAssessRequest struct {
	Advisory panosexposure.Advisory `json:"advisory"`
	Assets   []panosexposure.Asset  `json:"assets"`
}

// AssessPANOSExposure returns an exposure verdict per asset for one advisory.
// Stateless: it reads nothing from the database and writes nothing. Auth is
// required (tierAny), and the body is capped at 1 MiB.
// POST /api/panos-exposure/assess
func (h *Handler) AssessPANOSExposure(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req panosAssessRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonError(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		jsonError(w, "invalid JSON body: unexpected data after the object", http.StatusBadRequest)
		return
	}
	if len(req.Assets) == 0 {
		jsonError(w, "assets must not be empty", http.StatusBadRequest)
		return
	}
	if len(req.Assets) > maxPANOSAssets {
		jsonError(w, "too many assets in one request (max 500)", http.StatusBadRequest)
		return
	}

	results := make([]panosexposure.Result, 0, len(req.Assets))
	counts := map[panosexposure.Verdict]int{}
	for _, a := range req.Assets {
		res := panosexposure.Assess(a, req.Advisory)
		results = append(results, res)
		counts[res.Verdict]++
	}
	jsonOK(w, map[string]any{
		"cve":     req.Advisory.CVE,
		"source":  req.Advisory.Source,
		"results": results,
		"counts":  counts,
	})
}
