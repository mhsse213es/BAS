package adlab

import (
	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adgate"
)

// SyntheticProvider returns the deterministic built-in labs. It never errors.
type SyntheticProvider struct{}

func (SyntheticProvider) Labs() ([]Lab, error) {
	return []Lab{
		aclGenericAllTakeoverLab(),
		adcsESC1EnrollableLab(),
		adcsESC1NotEnrollableLab(),
		noFootholdSafeLab(),
	}, nil
}

// aclGenericAllTakeoverLab: the attacker's group holds GenericAll over a
// target account, so acl-genericall-takeover yields CapControlledAccount.
func aclGenericAllTakeoverLab() Lab {
	return Lab{
		Name:        "acl-genericall-takeover",
		Description: "Attacker's group holds GenericAll over a service account.",
		Attacker:    "attacker",
		Attestation: adgate.SyntheticProvenance(),
		Env: adenv.Environment{
			Identity: adenv.Identity{Groups: []adenv.Group{
				{Name: "Helpdesk", Members: []string{"attacker"}},
			}},
			Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
				{Principal: "Helpdesk", Target: "svc-admin", Right: adenv.ACLGenericAll},
			}},
		},
	}
}

// adcsESC1EnrollableLab: a published ESC1-vulnerable template the attacker's
// group can enroll in.
func adcsESC1EnrollableLab() Lab {
	return Lab{
		Name:        "adcs-esc1-enrollable",
		Description: "ESC1-vulnerable template; attacker's group has enrollment rights.",
		Attacker:    "attacker",
		Attestation: adgate.SyntheticProvenance(),
		Env: adenv.Environment{
			Identity: adenv.Identity{Groups: []adenv.Group{
				{Name: "Domain Users", Members: []string{"attacker"}},
			}},
			PKI: adenv.PKI{Templates: []adenv.CertTemplate{{
				Name:                    "VulnWebAuth",
				EKUs:                    []string{"Client Authentication"},
				EnrolleeSuppliesSubject: true,
				ManagerApprovalRequired: false,
				PublishedToCA:           true,
				EnrollmentRights:        []string{"Domain Users"},
			}}},
		},
	}
}

// adcsESC1NotEnrollableLab: the SAME vulnerable template, but the attacker
// belongs to no group with enrollment rights -> ESC1 gated off.
func adcsESC1NotEnrollableLab() Lab {
	return Lab{
		Name:        "adcs-esc1-not-enrollable",
		Description: "ESC1-vulnerable template, but attacker cannot enroll in it.",
		Attacker:    "attacker",
		Attestation: adgate.SyntheticProvenance(),
		Env: adenv.Environment{
			PKI: adenv.PKI{Templates: []adenv.CertTemplate{{
				Name:                    "VulnWebAuth",
				EKUs:                    []string{"Client Authentication"},
				EnrolleeSuppliesSubject: true,
				ManagerApprovalRequired: false,
				PublishedToCA:           true,
				EnrollmentRights:        []string{"PKI Admins"}, // attacker not a member
			}}},
		},
	}
}

// noFootholdSafeLab: attacker holds no abusable ACL right and there is no
// vulnerable template -> nothing reachable.
func noFootholdSafeLab() Lab {
	return Lab{
		Name:        "no-foothold-safe",
		Description: "Attacker has a domain-user foothold but no abusable rights.",
		Attacker:    "attacker",
		Attestation: adgate.SyntheticProvenance(),
		Env: adenv.Environment{
			Identity: adenv.Identity{Users: []adenv.User{{Name: "attacker", Enabled: true}}},
		},
	}
}
