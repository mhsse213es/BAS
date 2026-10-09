package adprimitive

import "testing"

func findPrimitive(id string) (Primitive, bool) {
	for _, p := range KerberoastingCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestAllCatalogs_EveryPrimitiveHasAValidRiskClass(t *testing.T) {
	valid := map[RiskClass]bool{
		RiskNonDestructive:         true,
		RiskPotentiallyDestructive: true,
		RiskDestructive:            true,
	}
	all := append(append(append(append(append(append(append([]Primitive{}, KerberoastingCatalog...), ACLAbuseCatalog...), RBCDCatalog...), DCSyncCatalog...), ADCSCatalog...), DelegationCatalog...), TrustAbuseCatalog...)
	if len(all) != 20 {
		t.Fatalf("expected 20 total primitives across all catalogs, got %d", len(all))
	}
	for _, p := range all {
		if !valid[p.RiskClass] {
			t.Errorf("%s: RiskClass %q is not one of the 3 defined values", p.ID, p.RiskClass)
		}
	}
}

func TestKerberoastingCatalog_OnlyDiscoveryPrimitivesAreNonDestructive(t *testing.T) {
	nonDestructiveIDs := map[string]bool{"spn-enumerate": true, "asrep-roast-discover": true}
	for _, p := range KerberoastingCatalog {
		want := RiskPotentiallyDestructive
		if nonDestructiveIDs[p.ID] {
			want = RiskNonDestructive
		}
		if p.RiskClass != want {
			t.Errorf("%s: expected RiskClass %q, got %q", p.ID, want, p.RiskClass)
		}
	}
}

func TestKerberoastingCatalog_Stage1And2ShareTechniqueIDButAreDistinctPrimitives(t *testing.T) {
	enum, ok := findPrimitive("spn-enumerate")
	if !ok || enum.TechniqueID != "T1558.003" {
		t.Fatalf("expected spn-enumerate with TechniqueID T1558.003, got %+v (ok=%v)", enum, ok)
	}
	kerb, ok := findPrimitive("kerberoast-tgs-request")
	if !ok || kerb.TechniqueID != "T1558.003" {
		t.Fatalf("expected kerberoast-tgs-request with TechniqueID T1558.003, got %+v (ok=%v)", kerb, ok)
	}
	if enum.ID == kerb.ID {
		t.Fatal("spn-enumerate and kerberoast-tgs-request must be distinct catalog entries despite sharing a TechniqueID")
	}
}

func TestKerberoastingCatalog_EnumeratePostconditionSatisfiesKerberoastPrerequisite(t *testing.T) {
	enum, _ := findPrimitive("spn-enumerate")
	kerb, _ := findPrimitive("kerberoast-tgs-request")

	satisfied := false
	for _, have := range enum.Postconditions {
		for _, need := range kerb.Prerequisites.Capabilities {
			if have == need {
				satisfied = true
			}
		}
	}
	if !satisfied {
		t.Fatalf("expected spn-enumerate's postcondition %+v to satisfy kerberoast-tgs-request's prerequisite %+v", enum.Postconditions, kerb.Prerequisites.Capabilities)
	}
}

func findInACLAbuseCatalog(id string) (Primitive, bool) {
	for _, p := range ACLAbuseCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestACLAbuseCatalog_ForceChangePasswordAndGenericAllConvergeOnSameCapability(t *testing.T) {
	fcp, ok := findInACLAbuseCatalog("acl-forcechangepassword-abuse")
	if !ok {
		t.Fatal("expected acl-forcechangepassword-abuse in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLForceChangePassword's value
	// ("ForceChangePassword") -- see this plan's Review Focus.
	if !fcp.Prerequisites.Conditions["acl_right_held:ForceChangePassword"] {
		t.Fatalf("expected acl-forcechangepassword-abuse to require acl_right_held:ForceChangePassword, got %+v", fcp.Prerequisites.Conditions)
	}
	if len(fcp.Postconditions) != 1 || fcp.Postconditions[0].Kind != CapControlledAccount {
		t.Fatalf("expected acl-forcechangepassword-abuse postcondition CapControlledAccount, got %+v", fcp.Postconditions)
	}

	gca, ok := findInACLAbuseCatalog("acl-genericall-takeover")
	if !ok {
		t.Fatal("expected acl-genericall-takeover in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLGenericAll's value ("GenericAll").
	if !gca.Prerequisites.Conditions["acl_right_held:GenericAll"] {
		t.Fatalf("expected acl-genericall-takeover to require acl_right_held:GenericAll, got %+v", gca.Prerequisites.Conditions)
	}
	if len(gca.Postconditions) != 1 || gca.Postconditions[0].Kind != CapControlledAccount {
		t.Fatalf("expected acl-genericall-takeover postcondition CapControlledAccount, got %+v", gca.Postconditions)
	}

	// Different prerequisite rights, same outcome kind -- multiple paths
	// to the same capability, not a 1:1 technique-to-capability mapping.
	if fcp.ID == gca.ID {
		t.Fatal("acl-forcechangepassword-abuse and acl-genericall-takeover must be distinct primitives")
	}
}

func TestACLAbuseCatalog_AddMemberAndAddSelfAreDistinctPrimitives(t *testing.T) {
	am, ok := findInACLAbuseCatalog("acl-addmember-privileged-group")
	if !ok {
		t.Fatal("expected acl-addmember-privileged-group in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLAddMember's value ("AddMember").
	if !am.Prerequisites.Conditions["acl_right_held:AddMember"] {
		t.Fatalf("expected acl-addmember-privileged-group to require acl_right_held:AddMember, got %+v", am.Prerequisites.Conditions)
	}

	as, ok := findInACLAbuseCatalog("acl-addself-privileged-group")
	if !ok {
		t.Fatal("expected acl-addself-privileged-group in ACLAbuseCatalog")
	}
	// Copied literally from adenv.ACLAddSelf's value ("AddSelf").
	if !as.Prerequisites.Conditions["acl_right_held:AddSelf"] {
		t.Fatalf("expected acl-addself-privileged-group to require acl_right_held:AddSelf, got %+v", as.Prerequisites.Conditions)
	}

	if am.ID == as.ID {
		t.Fatal("acl-addmember-privileged-group and acl-addself-privileged-group must be distinct primitives")
	}
	for _, p := range []Primitive{am, as} {
		if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapGroupMember {
			t.Fatalf("expected %s postcondition CapGroupMember, got %+v", p.ID, p.Postconditions)
		}
	}
}

func TestACLAbuseCatalog_NoneHaveATechniqueID(t *testing.T) {
	// ACL-rights abuse via inherited permissions has no clean 1:1 ATT&CK
	// sub-technique -- leaving TechniqueID empty is more honest than an
	// imprecise tag (see this plan's Global Constraints).
	for _, p := range ACLAbuseCatalog {
		if p.TechniqueID != "" {
			t.Errorf("expected %s to have no TechniqueID, got %q", p.ID, p.TechniqueID)
		}
	}
}

func findInRBCDCatalog(id string) (Primitive, bool) {
	for _, p := range RBCDCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestRBCDCatalog_ConfigureRequiresBothACLRightAndControlledPrincipal(t *testing.T) {
	cfg, ok := findInRBCDCatalog("rbcd-configure")
	if !ok {
		t.Fatal("expected rbcd-configure in RBCDCatalog")
	}
	if !cfg.Prerequisites.Conditions["acl_right_held:GenericWrite"] {
		t.Fatalf("expected rbcd-configure to require acl_right_held:GenericWrite, got %+v", cfg.Prerequisites.Conditions)
	}
	hasControlledAccount := false
	for _, c := range cfg.Prerequisites.Capabilities {
		if c.Kind == CapControlledAccount {
			hasControlledAccount = true
		}
	}
	if !hasControlledAccount {
		t.Fatalf("expected rbcd-configure to require CapControlledAccount (a principal to name in the attribute), got %+v", cfg.Prerequisites.Capabilities)
	}
}

func TestRBCDCatalog_ConfigurePostconditionSatisfiesImpersonatePrerequisite(t *testing.T) {
	cfg, _ := findInRBCDCatalog("rbcd-configure")
	imp, ok := findInRBCDCatalog("rbcd-impersonate")
	if !ok {
		t.Fatal("expected rbcd-impersonate in RBCDCatalog")
	}

	satisfied := false
	for _, have := range cfg.Postconditions {
		for _, need := range imp.Prerequisites.Capabilities {
			if have == need {
				satisfied = true
			}
		}
	}
	if !satisfied {
		t.Fatalf("expected rbcd-configure's postcondition %+v to satisfy rbcd-impersonate's prerequisite %+v", cfg.Postconditions, imp.Prerequisites.Capabilities)
	}

	// The outcome is exactly AD.txt's own worked LOCAL_ADMIN@SERVER01
	// example (lines 385-386) -- reusing the pre-existing CapLocalAdmin
	// constant, not inventing a new one.
	if len(imp.Postconditions) != 1 || imp.Postconditions[0].Kind != CapLocalAdmin {
		t.Fatalf("expected rbcd-impersonate postcondition CapLocalAdmin, got %+v", imp.Postconditions)
	}
}

func TestRBCDCatalog_NoneHaveATechniqueID(t *testing.T) {
	for _, p := range RBCDCatalog {
		if p.TechniqueID != "" {
			t.Errorf("expected %s to have no TechniqueID, got %q", p.ID, p.TechniqueID)
		}
	}
}

func TestDCSyncCatalog_RequiresAllExtendedRightsAndHasTechniqueID(t *testing.T) {
	if len(DCSyncCatalog) != 1 {
		t.Fatalf("expected exactly 1 primitive in DCSyncCatalog, got %d", len(DCSyncCatalog))
	}
	p := DCSyncCatalog[0]
	if p.ID != "dcsync" {
		t.Fatalf("expected ID dcsync, got %q", p.ID)
	}
	if p.TechniqueID != "T1003.006" {
		t.Fatalf("expected TechniqueID T1003.006, got %q", p.TechniqueID)
	}
	// Canonical kebab-case value, matching adenv.ACLAllExtendedRights /
	// attackpath.EdgeAllExtendedRights / the sharphound mapping -- so DCSync
	// resolves against an env derived from real BloodHound data.
	if !p.Prerequisites.Conditions["acl_right_held:all-extended-rights"] {
		t.Fatalf("expected dcsync to require acl_right_held:all-extended-rights, got %+v", p.Prerequisites.Conditions)
	}
	// Reuses the pre-existing constant from AD-M04's original schema
	// (AD.txt's own "After DCSync: DOMAIN_CREDENTIAL_MATERIAL" example),
	// not a newly-invented one.
	if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapDomainCredentialMaterial {
		t.Fatalf("expected postcondition CapDomainCredentialMaterial, got %+v", p.Postconditions)
	}
}

func findInADCSCatalog(id string) (Primitive, bool) {
	for _, p := range ADCSCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestTrustAbuseCatalog_IntraAndCrossForest(t *testing.T) {
	if len(TrustAbuseCatalog) != 2 {
		t.Fatalf("expected exactly 2 trust-abuse primitives, got %d", len(TrustAbuseCatalog))
	}
	seenCond := map[string]bool{}
	for _, p := range TrustAbuseCatalog {
		if p.TechniqueID != "T1134.005" {
			t.Errorf("%s: expected TechniqueID T1134.005, got %q", p.ID, p.TechniqueID)
		}
		if len(p.Prerequisites.Conditions) != 1 {
			t.Fatalf("%s: expected exactly 1 condition, got %+v", p.ID, p.Prerequisites.Conditions)
		}
		for k := range p.Prerequisites.Conditions {
			if seenCond[k] {
				t.Fatalf("condition key %q reused across trust-abuse primitives", k)
			}
			seenCond[k] = true
		}
		if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapTicket {
			t.Fatalf("%s: expected postcondition CapTicket, got %+v", p.ID, p.Postconditions)
		}
	}
	if !seenCond["intra_forest_trust_abusable"] || !seenCond["cross_forest_trust_sid_filter_disabled"] {
		t.Fatalf("expected both trust condition keys, got %+v", seenCond)
	}
}

func TestDelegationCatalog_UnconstrainedAndConstrained(t *testing.T) {
	if len(DelegationCatalog) != 2 {
		t.Fatalf("expected exactly 2 delegation primitives (unconstrained, constrained), got %d", len(DelegationCatalog))
	}
	seenCond := map[string]bool{}
	for _, p := range DelegationCatalog {
		if p.TechniqueID != "T1558" {
			t.Errorf("%s: expected TechniqueID T1558, got %q", p.ID, p.TechniqueID)
		}
		if len(p.Prerequisites.Conditions) != 1 {
			t.Fatalf("%s: expected exactly 1 condition, got %+v", p.ID, p.Prerequisites.Conditions)
		}
		for k := range p.Prerequisites.Conditions {
			if seenCond[k] {
				t.Fatalf("condition key %q reused across delegation primitives", k)
			}
			seenCond[k] = true
		}
		if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapTicket {
			t.Fatalf("%s: expected postcondition CapTicket, got %+v", p.ID, p.Postconditions)
		}
	}
	if !seenCond["controls_unconstrained_delegation_principal"] || !seenCond["controls_constrained_delegation_principal"] {
		t.Fatalf("expected both delegation condition keys, got %+v", seenCond)
	}
}

func TestADCSCatalog_FourDistinctPrimitivesShareTechniqueID(t *testing.T) {
	if len(ADCSCatalog) != 6 {
		t.Fatalf("expected exactly 6 primitives in ADCSCatalog (ESC1-4, ESC6, ESC8), got %d", len(ADCSCatalog))
	}
	seenConditionKeys := map[string]bool{}
	for _, p := range ADCSCatalog {
		if p.TechniqueID != "T1649" {
			t.Errorf("%s: expected TechniqueID T1649, got %q", p.ID, p.TechniqueID)
		}
		if len(p.Prerequisites.Conditions) != 1 {
			t.Fatalf("%s: expected exactly 1 Conditions entry, got %+v", p.ID, p.Prerequisites.Conditions)
		}
		for key := range p.Prerequisites.Conditions {
			if seenConditionKeys[key] {
				t.Fatalf("condition key %q reused across more than one primitive", key)
			}
			seenConditionKeys[key] = true
		}
	}

	esc4, ok := findInADCSCatalog("adcs-esc4")
	if !ok {
		t.Fatal("expected adcs-esc4 in ADCSCatalog")
	}
	if len(esc4.Postconditions) != 1 || esc4.Postconditions[0].Kind != CapTemplateControlled {
		t.Fatalf("expected adcs-esc4 postcondition CapTemplateControlled, got %+v", esc4.Postconditions)
	}

	for _, id := range []string{"adcs-esc1", "adcs-esc2", "adcs-esc3"} {
		p, ok := findInADCSCatalog(id)
		if !ok {
			t.Fatalf("expected %s in ADCSCatalog", id)
		}
		if len(p.Postconditions) != 1 || p.Postconditions[0].Kind != CapControlledAccount {
			t.Fatalf("expected %s postcondition CapControlledAccount, got %+v", id, p.Postconditions)
		}
	}
}

func TestKerberoastingCatalog_ASREPDiscoverDoesNotClaimCredentialCapability(t *testing.T) {
	asrep, ok := findPrimitive("asrep-roast-discover")
	if !ok || asrep.TechniqueID != "T1558.004" {
		t.Fatalf("expected asrep-roast-discover with TechniqueID T1558.004, got %+v (ok=%v)", asrep, ok)
	}
	for _, cap := range asrep.Postconditions {
		if cap.Kind == CapServiceAccountCredential || cap.Kind == CapNTLMHash || cap.Kind == CapDomainCredentialMaterial || cap.Kind == CapTicket {
			t.Fatalf("asrep-roast-discover must not claim a credential-bearing postcondition (the real scenario step only discovers roastable accounts, never requests or cracks a ticket), got %+v", cap)
		}
	}
}
