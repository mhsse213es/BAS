// Package networksecurity holds the shared result vocabulary for Network
// BAS Phase 5's transport-security checks (cleartext-protocol detection
// and TLS certificate validation, both in internal/networktransport).
// It has no logic of its own. See
// docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md.
package networksecurity

import (
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

// SecurityState is the shared rule for every check in this phase: Secure
// means the tested requirement was positively demonstrated; Insecure
// means a specific weakness was positively demonstrated; Unknown means
// the evidence cannot support either conclusion. No check ever promotes
// an absence of bad evidence into Secure.
type SecurityState string

const (
	Secure   SecurityState = "secure"
	Insecure SecurityState = "insecure"
	Unknown  SecurityState = "unknown"
)

type SecurityCheckResult struct {
	Target     networkgraph.Target   `json:"target"`
	State      SecurityState         `json:"state"`
	Reason     string                `json:"reason,omitempty"`
	Provenance cloudgraph.Provenance `json:"provenance"`
}
