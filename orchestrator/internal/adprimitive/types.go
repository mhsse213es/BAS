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

	// The 2 below are DISCOVERY-type capabilities (knowledge of a target,
	// not possession of a credential), added for the Kerberoasting/AS-REP
	// catalog backfill -- CapabilityKind was always an open string type,
	// so this extends it rather than redesigning it.
	CapKerberoastableTargetKnown CapabilityKind = "KERBEROASTABLE_TARGET_KNOWN"
	CapASREPRoastableTargetKnown CapabilityKind = "ASREP_ROASTABLE_TARGET_KNOWN"

	// The 2 below are the outcomes of ACL-rights abuse (added for the
	// ACLAbuseCatalog): CapControlledAccount is "the attacker now has
	// usable credentials for, or full control of, a specific account"
	// (ForceChangePassword/GenericAll); CapGroupMember is "the attacker
	// is now a member of a specific group" (AddMember/AddSelf).
	CapControlledAccount CapabilityKind = "CONTROLLED_ACCOUNT"
	CapGroupMember       CapabilityKind = "GROUP_MEMBER"

	// CapRBCDConfigured is the intermediate state between configuring
	// Resource-Based Constrained Delegation on a target and actually
	// impersonating a user through it (added for RBCDCatalog).
	CapRBCDConfigured CapabilityKind = "RBCD_CONFIGURED"

	// CapTemplateControlled is ESC4's outcome -- the holder can
	// reconfigure a certificate template's own properties, but has not
	// yet exploited it for account takeover the way ESC1/ESC2/ESC3 do.
	// Connecting this to ESC1-style exploitation as a 2-step chain is
	// left to AD-M05.
	CapTemplateControlled CapabilityKind = "TEMPLATE_CONTROLLED"

	// CapDCSyncRightHolderKnown is another DISCOVERY-type capability (same
	// family as CapKerberoastableTargetKnown/CapASREPRoastableTargetKnown
	// above): the current principal's possession of a DCSync-enabling
	// extended right (DS-Replication-Get-Changes[-All]) is now KNOWN, not
	// exercised. Deliberately distinct from CapDomainCredentialMaterial --
	// learning the right is held is not the same as having replicated
	// anything with it (added for DCSyncCatalog's exposure-check primitive).
	CapDCSyncRightHolderKnown CapabilityKind = "DCSYNC_RIGHT_HOLDER_KNOWN"

	// CapACLPrivilegeExposureKnown is another DISCOVERY-type capability (same
	// family as CapDCSyncRightHolderKnown above): the presence of a
	// dangerous inbound ACL grant (GenericAll/GenericWrite/WriteDacl/
	// WriteOwner/ForceChangePassword/AddMember/AddSelf/AllExtendedRights)
	// held by a non-tier-0 principal over a privileged object is now KNOWN,
	// not exercised. Deliberately distinct from CapControlledAccount and
	// CapGroupMember -- auditing that a takeover-enabling right is exposed
	// is not the same as having used it to take over an account or join a
	// group (added for ACLAbuseCatalog's read-only exposure-check primitive).
	CapACLPrivilegeExposureKnown CapabilityKind = "ACL_PRIVILEGE_EXPOSURE_KNOWN"

	// CapADCSTemplateExposureKnown is another DISCOVERY-type capability (same
	// family as CapACLPrivilegeExposureKnown above): the presence of an
	// ESC1-4-class certificate-template misconfiguration (enrollee-supplied
	// subject + authentication EKU + low-privileged enroll, Any-Purpose/no
	// EKU, enrollment-agent EKU, or a template DACL writable by a non-tier-0
	// principal) readable from the AD Configuration partition is now KNOWN,
	// not exercised. Deliberately distinct from CapControlledAccount and
	// CapTemplateControlled -- auditing that a template is misconfigured is
	// not the same as having requested a certificate or taken over a
	// template. Scoped to the LDAP-readable template surface (ESC1-4); the
	// CA-host-level flags (ESC6) and web-enrollment reach (ESC8) are out of
	// a Configuration-partition read's scope (added for ADCSCatalog's
	// read-only exposure-check primitive).
	CapADCSTemplateExposureKnown CapabilityKind = "ADCS_TEMPLATE_EXPOSURE_KNOWN"

	// CapDelegationExposureKnown is a DISCOVERY-type capability: the presence
	// of a Kerberos delegation misconfiguration (an account trusted for
	// unconstrained delegation that is not a Domain Controller, or a
	// constrained-delegation / resource-based-constrained-delegation
	// configuration) readable from the directory is now KNOWN, not exercised.
	// Deliberately distinct from CapTicket -- auditing that a delegation
	// primitive is exposed is not the same as having coerced an
	// authentication or forged a ticket through it (added for
	// DelegationCatalog's read-only exposure-check primitive).
	CapDelegationExposureKnown CapabilityKind = "DELEGATION_EXPOSURE_KNOWN"

	// CapTrustExposureKnown is a DISCOVERY-type capability: the presence of a
	// trust/SID-history abuse condition (a cross-forest trust with SID
	// filtering disabled, or accounts carrying a populated sIDHistory)
	// readable from the directory is now KNOWN, not exercised. Deliberately
	// distinct from CapTicket -- auditing that the condition is exposed is
	// not the same as having forged an inter-realm ticket through it (added
	// for TrustAbuseCatalog's read-only exposure-check primitive).
	CapTrustExposureKnown CapabilityKind = "TRUST_EXPOSURE_KNOWN"

	// CapGPOExposureKnown is a DISCOVERY-type capability: the presence of a
	// Group Policy object that is writable by a non-tier-0 principal AND
	// linked to a populated scope, readable from the directory, is now
	// KNOWN, not exercised. Deliberately distinct from CapLocalAdmin --
	// auditing that a writable linked GPO is exposed is not the same as
	// having pushed policy through it to gain code execution (added for
	// GPOAbuseCatalog's read-only exposure-check primitive).
	CapGPOExposureKnown CapabilityKind = "GPO_EXPOSURE_KNOWN"

	// CapRBCDExposureKnown is a DISCOVERY-type capability: the presence of
	// the RBCD-configure precondition -- a non-tier-0 principal holding
	// write access (GenericAll/GenericWrite/WriteProperty/WriteDacl/
	// WriteOwner) over a computer object, together with a non-zero
	// ms-DS-MachineAccountQuota that lets any domain user create the
	// machine account used as the impersonation principal -- readable from
	// the directory, is now KNOWN, not exercised. Deliberately distinct
	// from CapRBCDConfigured and CapLocalAdmin -- auditing that the
	// configure precondition is exposed is not the same as having written
	// the delegation attribute or impersonated anyone through it (added for
	// RBCDCatalog's read-only exposure-check primitive). It is also narrower
	// than CapDelegationExposureKnown, which reports delegation attributes
	// ALREADY set; this reports the write-ability to set them.
	CapRBCDExposureKnown CapabilityKind = "RBCD_EXPOSURE_KNOWN"
)

// RiskClass is structural metadata only: a 3-value tier matching
// scenario.ExecutionClass's exact string values, assigned per primitive
// by postcondition shape (discovery-type postcondition ->
// RiskNonDestructive; credential/account/group/delegation postcondition
// -> RiskPotentiallyDestructive). adprimitive has no dependency on
// scenario -- this is a documented value-correspondence, not a typed
// reference.
type RiskClass string

const (
	RiskNonDestructive         RiskClass = "non_destructive"
	RiskPotentiallyDestructive RiskClass = "potentially_destructive"
	RiskDestructive            RiskClass = "destructive"
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
	RiskClass      RiskClass     `json:"riskClass"`
}
