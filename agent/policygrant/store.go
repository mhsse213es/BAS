package policygrant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// Store is every grant this agent currently holds. The grant store itself
// (not any audit log) is the authoritative security state: CheckGrant alone
// decides ALLOW/VETO.
type Store struct {
	Grants []Grant `json:"grants"`
}

// MarshalSigned serializes s and returns it alongside an HMAC-SHA256 over the
// exact serialized bytes, keyed by key. key's own protection (DPAPI on
// Windows, root-owned-file+local-secret on Linux) lives outside this
// package, in the OS-specific layer that calls it.
func MarshalSigned(s Store, key []byte) (data, mac []byte, err error) {
	data, err = json.Marshal(s)
	if err != nil {
		return nil, nil, err
	}
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return data, h.Sum(nil), nil
}

// UnmarshalSigned verifies mac over data before decoding, so a hand-edited
// file that merely keeps the right JSON shape still fails validation. Empty
// data/mac (no grant file has ever been written) decodes to an empty Store,
// not an error -- every agent's first grant creates the store from nothing.
func UnmarshalSigned(data, mac, key []byte) (Store, error) {
	if len(data) == 0 && len(mac) == 0 {
		return Store{}, nil
	}
	h := hmac.New(sha256.New, key)
	h.Write(data)
	if !hmac.Equal(h.Sum(nil), mac) {
		return Store{}, fmt.Errorf("grant store integrity check failed -- file may have been tampered with or the wrong key was used")
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return Store{}, err
	}
	return s, nil
}

// CheckGrant is the B5 gate's one call into this package: does any grant in
// s currently authorize action for agentID (optionally scoped to
// scenarioID), at now? status mirrors the spec's grant_status vocabulary
// ("absent" / "expired" / "scope_mismatch") for VETOED's reporting fields --
// "invalid" (a tampered/corrupt store) is the caller's to report, since that
// failure happens before a Store even exists to call CheckGrant on.
//
// Distinguishing "absent" from "expired" from "scope_mismatch" (rather than
// collapsing all three to a bare false) is deliberate: an operator who
// issued a grant and still got vetoed needs to know WHY, not just that they
// did.
func (s Store) CheckGrant(agentID, action, scenarioID string, now time.Time) (ok bool, status string) {
	bestStatus := "absent"
	for _, g := range s.Grants {
		if g.AgentID != agentID || g.Action != action {
			continue
		}
		// A matching agent+action pair exists -- refine the status beyond
		// the default "absent" even if this particular grant doesn't end
		// up authorizing.
		if bestStatus == "absent" {
			bestStatus = "scope_mismatch"
		}
		if !now.Before(g.ExpiresAt) {
			bestStatus = "expired"
			continue
		}
		if g.ScenarioID != "" && g.ScenarioID != scenarioID {
			continue
		}
		return true, "ok"
	}
	return false, bestStatus
}
