package adprimitive

// KerberoastingCatalog backfills AD-M04's schema onto the real,
// already-shipped scenarios/kerberoasting-ad-drill.yaml -- one Primitive
// per scenario stage that actually produces or requires attacker
// capability (stages 4-8 of that scenario are general AD reconnaissance
// -- trust/GPO/privileged-group/LAPS enumeration -- not part of the
// Kerberoasting/AS-REP chain this backfill targets).
var KerberoastingCatalog = []Primitive{
	{
		// Backfills Stage 1 ("AD Stage 1 -- Service Principal Name (SPN)
		// Enumeration (T1558.003)").
		ID: "spn-enumerate", Name: "SPN Enumeration", TechniqueID: "T1558.003",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Privileges:   []string{"domain_user"},
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapKerberoastableTargetKnown}},
		RiskClass:      RiskNonDestructive,
	},
	{
		// Backfills Stage 2 ("AD Stage 2 -- Kerberoasting TGS-REP Request
		// (no crack) (T1558.003)"). Shares Stage 1's TechniqueID -- ATT&CK
		// does not distinguish "found a target" from "requested its
		// ticket" the way these two primitives do.
		ID: "kerberoast-tgs-request", Name: "Kerberoasting TGS-REP Request", TechniqueID: "T1558.003",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapKerberoastableTargetKnown}},
		},
		Postconditions: []Capability{{Kind: CapServiceAccountCredential}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		// Backfills Stage 3 ("AD Stage 3 -- AS-REP Roastable Account
		// Discovery (T1558.004)"). The real scenario step is discovery
		// ONLY -- its own blast_radius text is explicit that it never
		// requests or cracks an AS-REP -- so this primitive's
		// postcondition is a discovery capability, never a credential
		// one.
		ID: "asrep-roast-discover", Name: "AS-REP Roastable Account Discovery", TechniqueID: "T1558.004",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Privileges:   []string{"domain_user"},
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapASREPRoastableTargetKnown}},
		RiskClass:      RiskNonDestructive,
	},
}

// ACLAbuseCatalog defines 4 ACL-abuse primitives from established AD
// attack technique knowledge. UNLIKE KerberoastingCatalog above, these
// have NO corresponding scenario YAML yet (scenarios/*.yaml has zero ACL-
// abuse coverage as of this writing) -- this is primitive-schema
// knowledge, not scenario coverage, and must not be read as "ACL-abuse
// scenarios exist." WriteOwner, WriteDacl, Owns, AllExtendedRights,
// AddKeyCredentialLink, and ReadLAPSPassword are deliberately deferred to
// a later pass.
//
// Each primitive's Prerequisites.Conditions uses the convention
// "acl_right_held:<RightName>", where <RightName> is the exact string
// value of the matching adenv.ACLRight constant (e.g. "ForceChangePassword"
// for adenv.ACLForceChangePassword). This means "the attacker holds this
// ACL right over SOME target" -- resolving which target satisfies that,
// for a specific environment, is graph traversal over attackpath's
// matching EdgeKind, which is AD-M05's job (the future chain planner),
// not this schema's. adprimitive deliberately has no dependency on adenv
// or attackpath; this is a documented STRING convention, not a typed
// cross-package reference.
var ACLAbuseCatalog = []Primitive{
	{
		ID: "acl-forcechangepassword-abuse", Name: "ForceChangePassword ACL Abuse",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:ForceChangePassword": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "acl-genericall-takeover", Name: "GenericAll ACL Takeover",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:GenericAll": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "acl-addmember-privileged-group", Name: "AddMember Privileged Group Join",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:AddMember": true},
		},
		Postconditions: []Capability{{Kind: CapGroupMember}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "acl-addself-privileged-group", Name: "AddSelf Privileged Group Join",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:AddSelf": true},
		},
		Postconditions: []Capability{{Kind: CapGroupMember}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	// acl-privilege-exposure-check is the read-only DISCOVERY counterpart to
	// the four ABUSE primitives above (same family role as DCSyncCatalog's
	// dcsync-replication-right-exposure-check): it reads privileged objects'
	// DACLs to learn whether a dangerous takeover-enabling right
	// (GenericAll/GenericWrite/WriteDacl/WriteOwner/ForceChangePassword/
	// AddMember/AddSelf/AllExtendedRights) is granted to a non-tier-0
	// principal. It has NO acl_right_held precondition -- it discovers which
	// rights exist rather than requiring one be held -- and is non-destructive
	// (it resets no password, takes over no object, adds no member). Unlike
	// its abuse siblings it carries a TechniqueID, because permission-grant
	// discovery IS a clean ATT&CK technique (T1069, Permission Groups
	// Discovery), whereas the abuse-via-inherited-rights primitives have no
	// crisp 1:1 sub-technique.
	{
		ID: "acl-privilege-exposure-check", Name: "ACL Privilege Exposure Audit", TechniqueID: "T1069",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapACLPrivilegeExposureKnown}},
		RiskClass:      RiskNonDestructive,
	},
}

// RBCDCatalog defines 2 chained primitives for Resource-Based Constrained
// Delegation abuse, following the same "no scenario YAML yet, primitive
// knowledge only" status as ACLAbuseCatalog (confirmed by grep across
// scenarios/*.yaml).
//
// rbcd-configure requires BOTH a write-capable ACL right over the target
// (the same "acl_right_held:<RightName>" convention ACLAbuseCatalog
// established) AND an already-controlled principal to name in the
// target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute -- commonly
// a computer account the attacker created via MachineAccountQuota (which
// lets any domain user create new computer accounts by default). Once
// configured, rbcd-impersonate requests a service ticket via
// S4U2Self+S4U2Proxy impersonating ANY user (including a Domain Admin) to
// the target -- exactly AD.txt's own worked LOCAL_ADMIN@SERVER01 example
// (lines 385-386), reusing the pre-existing CapLocalAdmin constant rather
// than inventing a new one.
var RBCDCatalog = []Primitive{
	{
		ID: "rbcd-configure", Name: "Configure Resource-Based Constrained Delegation",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapControlledAccount}},
			Conditions:   map[string]bool{"acl_right_held:GenericWrite": true},
		},
		Postconditions: []Capability{{Kind: CapRBCDConfigured}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "rbcd-impersonate", Name: "RBCD S4U2Proxy Impersonation",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapRBCDConfigured}},
		},
		Postconditions: []Capability{{Kind: CapLocalAdmin}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	// rbcd-configure-exposure-check is the read-only DISCOVERY counterpart to
	// the two RBCD ABUSE primitives above (same family role as the other
	// exposure-checks): it reads computer objects' DACLs for non-tier-0 write
	// access (the rbcd-configure precondition) and reads the domain's
	// ms-DS-MachineAccountQuota (the foothold that lets any domain user create
	// the impersonation principal). It has NO acl_right_held precondition --
	// it discovers the write surface rather than requiring the right be held
	// -- and is non-destructive (writes no delegation attribute, impersonates
	// no one). It is narrower than kerberos-delegation-exposure-check, which
	// reports delegation attributes ALREADY set; this reports the write-
	// ability to set them. Carries a TechniqueID (T1069, Permission Groups
	// Discovery) because permission-grant discovery IS a clean ATT&CK
	// technique, unlike the abuse-via-write primitives.
	{
		ID: "rbcd-configure-exposure-check", Name: "RBCD Configure-Surface Exposure Audit", TechniqueID: "T1069",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapRBCDExposureKnown}},
		RiskClass:      RiskNonDestructive,
	},
}

// DelegationCatalog covers the two Kerberos delegation abuses that are NOT
// resource-based (RBCD lives in RBCDCatalog above): unconstrained delegation
// (TGT capture) and constrained delegation (S4U2Proxy). All share T1558.
var DelegationCatalog = []Primitive{
	{
		// Control of a principal trusted for unconstrained delegation lets the
		// attacker coerce a privileged account to authenticate to it and keep
		// that account's forwarded TGT.
		ID: "kerberos-unconstrained-delegation", Name: "Unconstrained Delegation TGT Capture", TechniqueID: "T1558",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapControlledAccount}},
			Conditions:   map[string]bool{"controls_unconstrained_delegation_principal": true},
		},
		Postconditions: []Capability{{Kind: CapTicket}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		// Control of a principal configured for constrained delegation lets the
		// attacker use S4U2Proxy (with S4U2Self when protocol transition is set)
		// to obtain a service ticket to a configured target as an arbitrary user.
		ID: "kerberos-constrained-delegation", Name: "Constrained Delegation S4U2Proxy Abuse", TechniqueID: "T1558",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapControlledAccount}},
			Conditions:   map[string]bool{"controls_constrained_delegation_principal": true},
		},
		Postconditions: []Capability{{Kind: CapTicket}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	// kerberos-delegation-exposure-check is the read-only DISCOVERY
	// counterpart to the two delegation ABUSE primitives above (same family
	// role as the DCSync/ACL/ADCS exposure-checks): it reads the directory
	// for delegation misconfigurations -- a non-DC account trusted for
	// unconstrained delegation (userAccountControl TRUSTED_FOR_DELEGATION),
	// a constrained-delegation account (msDS-AllowedToDelegateTo), or a
	// resource-based delegation target (msDS-AllowedToActOnBehalfOf...). It
	// has NO controls_*_delegation_principal precondition -- it discovers
	// the misconfiguration rather than requiring control of the principal --
	// and is non-destructive (coerces no authentication, forges no ticket).
	{
		ID: "kerberos-delegation-exposure-check", Name: "Kerberos Delegation Exposure Audit", TechniqueID: "T1558",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapDelegationExposureKnown}},
		RiskClass:      RiskNonDestructive,
	},
}

// TrustAbuseCatalog covers SID-history injection across AD trusts (T1134.005):
// intra-forest parent-child trusts (no SID filtering) and cross-forest trusts
// whose SID filtering has been disabled. Both model an attacker who already owns
// one domain's credential material forging an inter-realm TGT into the other.
var TrustAbuseCatalog = []Primitive{
	{
		ID: "trust-intra-forest-sid-history", Name: "Intra-Forest Trust Abuse (SID History to Forest Root)", TechniqueID: "T1134.005",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainCredentialMaterial}},
			Conditions:   map[string]bool{"intra_forest_trust_abusable": true},
		},
		Postconditions: []Capability{{Kind: CapTicket}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "trust-cross-forest-sid-history", Name: "Cross-Forest Trust Abuse (SID Filtering Disabled)", TechniqueID: "T1134.005",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainCredentialMaterial}},
			Conditions:   map[string]bool{"cross_forest_trust_sid_filter_disabled": true},
		},
		Postconditions: []Capability{{Kind: CapTicket}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	// trust-sid-history-exposure-check is the read-only DISCOVERY counterpart
	// to the two trust ABUSE primitives above (same family role as the other
	// exposure-checks): it reads trustedDomain objects for a cross-forest
	// trust whose SID filtering/quarantine is disabled, and reads accounts
	// for a populated sIDHistory attribute. It has NO *_trust_* precondition
	// and requires no CapDomainCredentialMaterial -- it discovers the
	// condition rather than requiring domain credential material to abuse it
	// -- and is non-destructive (forges no inter-realm ticket).
	{
		ID: "trust-sid-history-exposure-check", Name: "Trust / SID-History Exposure Audit", TechniqueID: "T1134.005",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapTrustExposureKnown}},
		RiskClass:      RiskNonDestructive,
	},
}

// GPOAbuseCatalog covers Group Policy abuse (T1484.001): edit rights on a GPO
// that is linked to a populated scope let an attacker push policy (an immediate
// scheduled task, local-admin membership) that executes as SYSTEM on every
// object under the link -- modeled by the permission (writable) and affected
// scope (linked) together, with a privilege path to local admin.
var GPOAbuseCatalog = []Primitive{
	{
		ID: "gpo-abuse-linked-scope", Name: "GPO Abuse: Policy Push to Linked Scope", TechniqueID: "T1484.001",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapControlledAccount}},
			Conditions:   map[string]bool{"controls_writable_linked_gpo": true},
		},
		Postconditions: []Capability{{Kind: CapLocalAdmin}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	// gpo-abuse-exposure-check is the read-only DISCOVERY counterpart to the
	// GPO ABUSE primitive above (same family role as the other
	// exposure-checks): it reads groupPolicyContainer objects for a DACL
	// writable by a non-tier-0 principal AND a gPLink to a populated scope
	// (domain/OU/site). It has NO controls_writable_linked_gpo precondition
	// -- it discovers the exposed GPO rather than requiring control of it --
	// and is non-destructive (pushes no policy, creates no scheduled task).
	{
		ID: "gpo-abuse-exposure-check", Name: "GPO Writable-Linked Exposure Audit", TechniqueID: "T1484.001",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapGPOExposureKnown}},
		RiskClass:      RiskNonDestructive,
	},
}

// DCSyncCatalog defines the single DCSync primitive. DS-Replication-Get-
// Changes and DS-Replication-Get-Changes-All (the 2 extended rights
// DCSync requires) collapse into attackpath's single AllExtendedRights
// ACE right -- the same "acl_right_held:<RightName>" convention
// ACLAbuseCatalog/RBCDCatalog already use. Unlike those two, DCSync has
// a clean 1:1 MITRE mapping (T1003.006) and NO scenario YAML exists for
// it yet (confirmed by grep; the only scenarios/*.yaml matches for
// "replicat" are an unrelated coincidental use of the word in
// ransomware-encryption prose) -- primitive knowledge, not a backfill,
// same status as every other catalog in this file.
//
// This Conditions-based convention cannot structurally express that the
// right must be held specifically on the DOMAIN object, not just any
// object -- resolving that specificity against a real environment's
// graph is AD-M05's job, the same deferral already established for every
// ACL-shaped primitive here.
var DCSyncCatalog = []Primitive{
	{
		ID: "dcsync", Name: "DCSync Directory Replication", TechniqueID: "T1003.006",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:all-extended-rights": true},
		},
		Postconditions: []Capability{{Kind: CapDomainCredentialMaterial}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	// dcsync-replication-right-exposure-check is a SEPARATE, narrower
	// primitive from dcsync above -- it reads the domain object's own
	// access-control list to learn whether the current principal already
	// holds DS-Replication-Get-Changes[-All] (the 2 extended rights DCSync
	// requires), exactly the same discovery-vs-exploitation split the
	// Kerberoasting/AS-REP backfill already established (spn-enumerate vs
	// kerberoast-tgs-request). It does NOT request directory replication
	// data and produces no credential material -- its postcondition is the
	// discovery capability CapDCSyncRightHolderKnown, never
	// CapDomainCredentialMaterial. Has its own scenario (unlike dcsync
	// itself, which remains reusable-unmapped -- see admatrix's content
	// state for both): checking who already holds this right is read-only
	// and requires none of the privilege dcsync's own real exploitation does.
	{
		ID: "dcsync-replication-right-exposure-check", Name: "DCSync Replication-Right Exposure Check", TechniqueID: "T1003.006",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapDCSyncRightHolderKnown}},
		RiskClass:      RiskNonDestructive,
	},
}

// ADCSCatalog connects adenv's ESC1-4 configuration predicates
// (IsESC1Vulnerable, IsESC2Vulnerable, IsESC3Vulnerable,
// HasTemplateWriteAccess) to AD-M04's prerequisite/postcondition model.
// Each Conditions key names the predicate it corresponds to -- a
// documented naming correspondence, not a typed dependency, preserving
// adprimitive's independence from adenv. All 4 share TechniqueID T1649
// (Steal or Forge Authentication Certificates), the same pattern
// KerberoastingCatalog established for T1558.003. No scenario YAML
// exists for any ESC variant yet; primitive knowledge only, same status
// as every other catalog in this file.
var ADCSCatalog = []Primitive{
	{
		ID: "adcs-esc1", Name: "ADCS ESC1: Enrollee-Supplied Subject", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc1_vulnerable_template": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "adcs-esc2", Name: "ADCS ESC2: Any-Purpose EKU", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc2_vulnerable_template": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "adcs-esc3", Name: "ADCS ESC3: Enrollment Agent Template", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc3_vulnerable_template": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		ID: "adcs-esc4", Name: "ADCS ESC4: Template ACL Abuse", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc4_template_write_access": true},
		},
		Postconditions: []Capability{{Kind: CapTemplateControlled}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		// ESC6: the CA's EDITF_ATTRIBUTESUBJECTALTNAME2 flag lets a requester
		// put an arbitrary SAN on a cert from ANY enrollable auth template --
		// like ESC1 but a CA-wide misconfiguration, independent of the
		// template's own EnrolleeSuppliesSubject.
		ID: "adcs-esc6", Name: "ADCS ESC6: CA SAN Policy Flag (EDITF_ATTRIBUTESUBJECTALTNAME2)", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc6_vulnerable_ca": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	{
		// ESC8: NTLM relay to the CA's HTTP web-enrollment endpoint. Needs no
		// attacker enrollment right -- a coerced principal's authentication is
		// relayed to obtain a cert as that principal. Modeled from a domain
		// foothold for chain purposes.
		ID: "adcs-esc8", Name: "ADCS ESC8: NTLM Relay to Web Enrollment", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"esc8_relayable_ca": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
		RiskClass:      RiskPotentiallyDestructive,
	},
	// adcs-esc-exposure-check is the read-only DISCOVERY counterpart to the
	// six ESC ABUSE primitives above (same family role as the DCSync and ACL
	// exposure-checks): it reads the AD Configuration partition's certificate
	// templates to learn whether an ESC1-4-class misconfiguration exists
	// (enrollee-supplied subject + authentication EKU + low-privileged
	// enroll, Any-Purpose/no EKU, enrollment-agent EKU, or a template DACL
	// writable by a non-tier-0 principal). It has NO esc*_vulnerable
	// precondition -- it discovers which templates are misconfigured rather
	// than requiring one be -- and is non-destructive (it requests no
	// certificate, takes over no template). Scoped to the LDAP-readable
	// template surface (ESC1-4); the CA-host flags (ESC6) and web-enrollment
	// reach (ESC8) need reach a Configuration-partition read does not give.
	{
		ID: "adcs-esc-exposure-check", Name: "ADCS ESC Template Exposure Audit", TechniqueID: "T1649",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
		},
		Postconditions: []Capability{{Kind: CapADCSTemplateExposureKnown}},
		RiskClass:      RiskNonDestructive,
	},
}
