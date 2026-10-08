package adlab

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adenv"
)

// compile-time assertion that EnvResolver satisfies the interface.
var _ adchain.ConditionResolver = (*EnvResolver)(nil)

func timeAfter() <-chan time.Time { return time.After(2 * time.Second) }

func TestResolve_ACLRightHeldDirectly(t *testing.T) {
	env := adenv.Environment{
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "attacker", Target: "victim", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "attacker")
	if !r.Resolve("acl_right_held:GenericAll") {
		t.Error("expected true: attacker directly holds GenericAll")
	}
	if r.Resolve("acl_right_held:WriteDACL") {
		t.Error("expected false: attacker holds no WriteDACL")
	}
}

func TestResolve_ACLRightHeldViaNestedGroups(t *testing.T) {
	// attacker -> G1 -> G2, and the ACL grants G2.
	env := adenv.Environment{
		Identity: adenv.Identity{Groups: []adenv.Group{
			{Name: "G1", Members: []string{"attacker"}},
			{Name: "G2", Members: []string{"G1"}},
		}},
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "G2", Target: "victim", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "attacker")
	if !r.Resolve("acl_right_held:GenericAll") {
		t.Error("expected true: attacker reaches G2 transitively, G2 holds GenericAll")
	}
}

func TestResolve_GroupCycleTerminates(t *testing.T) {
	// A membership cycle must not loop forever.
	env := adenv.Environment{
		Identity: adenv.Identity{Groups: []adenv.Group{
			{Name: "A", Members: []string{"attacker", "B"}},
			{Name: "B", Members: []string{"A"}},
		}},
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "A", Target: "victim", Right: adenv.ACLAddMember},
		}},
	}
	done := make(chan bool, 1)
	go func() {
		r := NewEnvResolver(env, "attacker")
		done <- r.Resolve("acl_right_held:AddMember")
	}()
	select {
	case got := <-done:
		if !got {
			t.Error("expected true: attacker is in A (which holds AddMember) despite the A<->B cycle")
		}
	case <-timeAfter():
		t.Fatal("NewEnvResolver/Resolve did not terminate on a membership cycle")
	}
}

func TestResolve_AttackerAbsentResolvesFalse(t *testing.T) {
	env := adenv.Environment{
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "someone-else", Target: "victim", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "ghost")
	if r.Resolve("acl_right_held:GenericAll") {
		t.Error("expected false: the ghost attacker holds nothing")
	}
}

func TestResolve_ESC1EnrollmentGated(t *testing.T) {
	vulnerable := adenv.CertTemplate{
		Name:                    "VulnWebAuth",
		EKUs:                    []string{"Client Authentication"},
		EnrolleeSuppliesSubject: true,
		ManagerApprovalRequired: false,
		PublishedToCA:           true,
		EnrollmentRights:        []string{"Domain Users"},
	}
	env := adenv.Environment{
		Identity: adenv.Identity{Groups: []adenv.Group{
			{Name: "Domain Users", Members: []string{"attacker"}},
		}},
		PKI: adenv.PKI{Templates: []adenv.CertTemplate{vulnerable}},
	}
	if !NewEnvResolver(env, "attacker").Resolve("esc1_vulnerable_template") {
		t.Error("expected true: template is ESC1-vulnerable and attacker's group can enroll")
	}

	// Same template, attacker NOT in EnrollmentRights -> gated false.
	envNoEnroll := env
	envNoEnroll.Identity = adenv.Identity{} // attacker belongs to no group
	if NewEnvResolver(envNoEnroll, "attacker").Resolve("esc1_vulnerable_template") {
		t.Error("expected false: template is vulnerable but attacker cannot enroll")
	}
}

func TestResolve_ESC4TemplateWriteAccess(t *testing.T) {
	env := adenv.Environment{
		PKI: adenv.PKI{Templates: []adenv.CertTemplate{
			{Name: "T", WriteRights: []string{"attacker"}},
		}},
	}
	if !NewEnvResolver(env, "attacker").Resolve("esc4_template_write_access") {
		t.Error("expected true: attacker holds write access on a template")
	}
}

func TestResolve_EmptyPKIAllESCFalse(t *testing.T) {
	r := NewEnvResolver(adenv.Environment{}, "attacker")
	for _, key := range []string{"esc1_vulnerable_template", "esc2_vulnerable_template", "esc3_vulnerable_template", "esc4_template_write_access"} {
		if r.Resolve(key) {
			t.Errorf("expected false for %s with empty PKI", key)
		}
	}
}

func TestResolve_MalformedAndUnknownKeysFalse(t *testing.T) {
	env := adenv.Environment{
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
			{Principal: "attacker", Target: "v", Right: adenv.ACLGenericAll},
		}},
	}
	r := NewEnvResolver(env, "attacker")
	for _, key := range []string{"acl_right_held:", "acl_right_held", "totally_unknown_key", ""} {
		if r.Resolve(key) {
			t.Errorf("expected false for malformed/unknown key %q", key)
		}
	}
}
