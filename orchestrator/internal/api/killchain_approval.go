package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/killchain"
)

// advanceApproval is the operator's approval of a campaign's live stages. It is sent
// with the advance request. An empty body is no approval, which is fine for a
// posture-only campaign.
type advanceApproval struct {
	ConfirmLive bool   `json:"confirmLive"`
	ConfirmLab  bool   `json:"confirmLab"`
	Reason      string `json:"reason"`
}

// readAdvanceApproval reads the optional approval body. Unknown field names are refused,
// so a misspelt confirmation cannot be dropped silently. encoding/json matches names
// regardless of case, so a case-only difference is the same field, not an unknown one.
func readAdvanceApproval(r *http.Request) (advanceApproval, error) {
	var a advanceApproval
	const limit = 16 << 10
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return a, errors.New("approval body is unreadable")
	}
	if len(raw) > limit {
		return a, errors.New("approval body is too large")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return a, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, fmt.Errorf("invalid approval body: %w", err)
	}
	return a, nil
}

// checkCampaignApproval refuses an advance that would run live stages without approval.
// It only inspects the signed definition, so approval covers exactly the stages the
// definition declares.
func checkCampaignApproval(def killchain.CampaignDef, a advanceApproval, approver string) error {
	live, lab := def.LiveAndLabStages()
	if len(live) == 0 {
		return nil
	}
	if !a.ConfirmLive {
		return fmt.Errorf("campaign has live stages %v: confirmLive=true is required", live)
	}
	if strings.TrimSpace(a.Reason) == "" {
		return errors.New("a reason is required to approve live stages")
	}
	if len(lab) > 0 && !a.ConfirmLab {
		return fmt.Errorf("campaign has lab stages %v: confirmLab=true is required", lab)
	}
	// Lab stages need an identified approver. The creator may approve their own lab
	// stages: a single-person lab team is allowed. The audit records creator and approver.
	if len(lab) > 0 && approver == "" {
		return errors.New("cannot identify the approver for lab stages")
	}
	return nil
}
