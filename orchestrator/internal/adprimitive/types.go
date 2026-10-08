// Package adprimitive is the AD attack-primitive schema (AD-M04): a typed
// description of an individual AD attack technique's prerequisites and
// postconditions, per AD.txt lines 343-396.
//
// A Primitive is deliberately NOT the same concept as a MITRE ATT&CK
// technique ID. AD.txt (lines 129-178) is explicit that one technique can
// cover many primitives -- ADCS/T1649 alone decomposes into CA discovery,
// template discovery, enrollment-permission analysis, EKU analysis, and
// more, each with its own prerequisites and postconditions. TechniqueID
// is therefore optional: many primitives have no single MITRE ID to
// point to.
//
// This package holds pure data types only -- no chain-planning logic
// (AD-M05 will consume Capability equality between one primitive's
// Postconditions and another's Prerequisites.Capabilities to decide what
// can follow what) and no scenario backfill (a separate future AD-M04
// sub-phase maps these onto the existing scenarios/*.yaml step format).
package adprimitive

// CapabilityKind is one of the attacker capability states AD.txt's own
// worked example names (lines 379-395).
type CapabilityKind string

const (
	CapDomainUser               CapabilityKind = "DOMAIN_USER"
	CapServiceAccountCredential CapabilityKind = "SERVICE_ACCOUNT_CREDENTIAL"
	CapLocalAdmin               CapabilityKind = "LOCAL_ADMIN"
	CapNTLMHash                 CapabilityKind = "NTLM_HASH"
	CapTicket                   CapabilityKind = "TICKET"
	CapDomainCredentialMaterial CapabilityKind = "DOMAIN_CREDENTIAL_MATERIAL"
)

// Capability is an attacker capability state, optionally scoped to a
// target (e.g. LOCAL_ADMIN@SERVER01 is Capability{Kind: CapLocalAdmin,
// Target: "SERVER01"}; DOMAIN_USER is host-agnostic, Target stays "").
// Binding a real host into Target when planning an actual chain is
// AD-M05's job, not this schema's.
type Capability struct {
	Kind   CapabilityKind `json:"kind"`
	Target string         `json:"target,omitempty"`
}

// Prerequisites is what must already be true for a Primitive to be
// applicable, per AD.txt's worked example (lines 349-354).
type Prerequisites struct {
	DomainJoined bool     `json:"domainJoined"`
	Privileges   []string `json:"privileges,omitempty"` // e.g. "domain_user" -- AD.txt gives no closed set

	// Capabilities are attacker capability states that must already be
	// held -- the chain-reasoning half (AD.txt lines 362-369: "requires:
	// - credential_material_obtained"). Matched against another
	// Primitive's Postconditions by equality.
	Capabilities []Capability `json:"capabilities,omitempty"`

	// Conditions are open-ended environment-state checks specific to
	// this primitive (AD.txt's own example key is "spn_account_exists"),
	// never drawn from a fixed enum.
	Conditions map[string]bool `json:"conditions,omitempty"`
}

// Primitive is one AD attack primitive: an action with a name, an
// optional MITRE cross-reference, what it requires, and what capability
// it grants once it succeeds.
type Primitive struct {
	ID          string `json:"id"` // e.g. "kerberoast", "adcs-template-discovery"
	Name        string `json:"name"`
	TechniqueID string `json:"techniqueId,omitempty"` // MITRE ATT&CK sub-technique, when one exists

	Prerequisites  Prerequisites `json:"prerequisites"`
	Postconditions []Capability  `json:"postconditions,omitempty"` // capabilities GAINED once this primitive succeeds
}
