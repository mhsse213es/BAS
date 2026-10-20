package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/panosexposure"
)

// maxPANOSAssets bounds one assessment request, so a single call cannot
// allocate an unbounded result set.
const maxPANOSAssets = 500

// panosAssessRequest names the advisory to assess against in one of two ways:
//   - "advisory": a caller-supplied advisory (kept for compatibility), or
//   - "advisoryCve" (optionally "advisoryRevision"): a revision from the
//     built-in registry. Without a revision, the latest verified one is used.
//
// Exactly one of the two forms must be given.
type panosAssessRequest struct {
	Advisory         *panosexposure.Advisory `json:"advisory,omitempty"`
	AdvisoryCVE      string                  `json:"advisoryCve,omitempty"`
	AdvisoryRevision int                     `json:"advisoryRevision,omitempty"`
	Assets           []panosexposure.Asset   `json:"assets"`
}

// resolveAdvisory returns the advisory the request names and whether it came
// from the registry. A registry miss is an error, never a fallback to guessing.
func resolveAdvisory(req panosAssessRequest) (panosexposure.Advisory, string, error) {
	switch {
	case req.Advisory != nil && req.AdvisoryCVE != "":
		return panosexposure.Advisory{}, "", fmt.Errorf("give either advisory or advisoryCve, not both")
	case req.Advisory != nil:
		return *req.Advisory, "caller-supplied", nil
	case req.AdvisoryCVE == "":
		return panosexposure.Advisory{}, "", fmt.Errorf("an advisory is required: advisory or advisoryCve")
	}
	reg, err := panosexposure.BuiltinRegistry()
	if err != nil {
		return panosexposure.Advisory{}, "", fmt.Errorf("built-in advisory registry is unavailable: %w", err)
	}
	var rec panosexposure.AdvisoryRecord
	if req.AdvisoryRevision > 0 {
		rec, err = reg.Get(req.AdvisoryCVE, req.AdvisoryRevision)
	} else {
		rec, err = reg.Latest(req.AdvisoryCVE)
	}
	if err != nil {
		return panosexposure.Advisory{}, "", err
	}
	return rec.Advisory, rec.VerificationStatus, nil
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
	if _, err := dec.Token(); err != io.EOF {
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

	adv, status, err := resolveAdvisory(req)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	at := time.Now().UTC()
	results := make([]panosexposure.Result, 0, len(req.Assets))
	counts := map[panosexposure.Verdict]int{}
	for _, a := range req.Assets {
		res := panosexposure.AssessAt(a, adv, at)
		res.AdvisoryStatus = status
		switch status {
		case panosexposure.StatusVerified:
		case "caller-supplied":
			res.Limitations = append(res.Limitations, "advisory supplied by the caller; Audspect has not verified it")
		default:
			res.Limitations = append(res.Limitations, "advisory revision is "+status+"; its data is not verified")
		}
		results = append(results, res)
		counts[res.Verdict]++
	}
	jsonOK(w, map[string]any{
		"cve":             adv.CVE,
		"advisoryVersion": adv.Version,
		"advisoryStatus":  status,
		"source":          adv.Source,
		"results":         results,
		"counts":          counts,
	})
}
