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
	},
	{
		ID: "acl-genericall-takeover", Name: "GenericAll ACL Takeover",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:GenericAll": true},
		},
		Postconditions: []Capability{{Kind: CapControlledAccount}},
	},
	{
		ID: "acl-addmember-privileged-group", Name: "AddMember Privileged Group Join",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:AddMember": true},
		},
		Postconditions: []Capability{{Kind: CapGroupMember}},
	},
	{
		ID: "acl-addself-privileged-group", Name: "AddSelf Privileged Group Join",
		Prerequisites: Prerequisites{
			DomainJoined: true,
			Capabilities: []Capability{{Kind: CapDomainUser}},
			Conditions:   map[string]bool{"acl_right_held:AddSelf": true},
		},
		Postconditions: []Capability{{Kind: CapGroupMember}},
	},
}
