// Package threatidentity owns canonical actor identity and Threats for the
// Threat Content Factory (spec 2026-10-06-tcf-phase2-canonical-threat-design.md
// §3-§4): the deterministic resolver, the threat-derived content id, and the
// Postgres store that persists both.
package threatidentity

import (
	"crypto/sha256"
	"encoding/hex"
)

// ContentIDScheme versions the intel content-id derivation (spec §4.2).
// Never change the bytes of an existing scheme; add a new one.
const ContentIDScheme = "audspect/tcf/intel-content-id/v1"

// ContentID derives an intel content id from an immutable threat id. It
// never sees a name, alias, source or ATT&CK group, so renames and
// canonicalization cannot fork content identity (spec §4.1).
func ContentID(threatID string) string {
	h := sha256.Sum256([]byte(ContentIDScheme + "\x00" + threatID))
	return "intel-" + hex.EncodeToString(h[:])[:16]
}
