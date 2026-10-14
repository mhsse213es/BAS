package admatrix

import (
	"github.com/audspect/bas/internal/adcompose"
	"github.com/audspect/bas/internal/adcoverage"
	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adlab"
	"github.com/audspect/bas/internal/adprimitive"
)

// Composition is a canonical, named AD attack path: an ordered primitive chain
// reachable from Start in an enabling synthetic lab. It is metadata only --
// Compose reuses adcompose to link the chain to any mapped scenario content and
// to surface composition problems; adgate remains the sole execution-decision
// point. A Composition is model-simulated: it never implies the path has run.
type Composition struct {
	Name  string
	Chain []adprimitive.Primitive
	Start []adprimitive.Capability
	Lab   adlab.Lab
}

// Compose links this composition's chain to scenario content via adcompose. The
// gap primitives have no scenario YAML yet, so they compose cleanly at the
// capability level while honestly reporting ProblemUnmapped (an empty coverage
// report expresses "no scenario covers these").
func (c Composition) Compose() adcompose.ComposedChain {
	return adcompose.Compose(c.Chain, c.Start, adcoverage.Report{}, c.Lab)
}

func findPrimitive(catalog []adprimitive.Primitive, id string) adprimitive.Primitive {
	for _, p := range catalog {
		if p.ID == id {
			return p
		}
	}
	panic("admatrix: no primitive " + id + " in catalog") // grounding guarantee, covered by tests
}

func syntheticLab(name, desc, attacker string, env adenv.Environment) adlab.Lab {
	return adlab.Lab{Name: name, Description: desc, Env: env, Attacker: attacker, Attestation: adgate.SyntheticProvenance()}
}

// Compositions returns the canonical gap attack-path compositions, grounded in
// the real catalogs, each in a synthetic lab that enables it.
func Compositions() []Composition {
	const attacker = "attacker"
	domainUser := []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}

	// ADCS ESC1: a domain user enrolls in a vulnerable, enrollee-supplied-subject
	// template and takes over an account.
	esc1Env := adenv.Environment{PKI: adenv.PKI{Templates: []adenv.CertTemplate{{
		Name:                    "UserAuth",
		PublishedToCA:           true,
		EnrolleeSuppliesSubject: true,
		ManagerApprovalRequired: false,
		EKUs:                    []string{"Client Authentication"},
		EnrollmentRights:        []string{attacker},
	}}}}

	// RBCD takeover: GenericAll over a victim yields a controlled account, which
	// (with GenericWrite over a target computer) configures RBCD and impersonates
	// a privileged user for local admin on that target.
	rbcdEnv := adenv.Environment{Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
		{Principal: attacker, Target: "victim", Right: adenv.ACLGenericAll},
		{Principal: attacker, Target: "server01", Right: adenv.ACLGenericWrite},
	}}}

	// DCSync: a domain user holding the replication extended right dumps domain
	// credential material.
	dcsyncEnv := adenv.Environment{Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
		{Principal: attacker, Target: "corp.example.com", Right: adenv.ACLAllExtendedRights},
	}}}

	return []Composition{
		{
			Name:  "adcs-esc1-enrollment-escalation",
			Chain: []adprimitive.Primitive{findPrimitive(adprimitive.ADCSCatalog, "adcs-esc1")},
			Start: domainUser,
			Lab:   syntheticLab("adcs-esc1", "ADCS ESC1 enrollee-supplied-subject escalation", attacker, esc1Env),
		},
		{
			Name: "rbcd-computer-takeover",
			Chain: []adprimitive.Primitive{
				findPrimitive(adprimitive.ACLAbuseCatalog, "acl-genericall-takeover"),
				findPrimitive(adprimitive.RBCDCatalog, "rbcd-configure"),
				findPrimitive(adprimitive.RBCDCatalog, "rbcd-impersonate"),
			},
			Start: domainUser,
			Lab:   syntheticLab("rbcd-takeover", "GenericAll -> RBCD configure -> impersonate", attacker, rbcdEnv),
		},
		{
			Name:  "dcsync-domain-dominance",
			Chain: []adprimitive.Primitive{findPrimitive(adprimitive.DCSyncCatalog, "dcsync")},
			Start: domainUser,
			Lab:   syntheticLab("dcsync", "DCSync directory replication", attacker, dcsyncEnv),
		},
	}
}
