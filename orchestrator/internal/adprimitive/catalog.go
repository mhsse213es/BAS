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
			Conditions:   map[string]bool{"acl_right_held:AllExtendedRights": true},
		},
		Postconditions: []Capability{{Kind: CapDomainCredentialMaterial}},
		RiskClass:      RiskPotentiallyDestructive,
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
}
