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
