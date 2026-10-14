package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
)

func TestResolve_IntraForestTrustAbusable(t *testing.T) {
	env := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeParentChild}}}}
	if !NewEnvResolver(env, "attacker").Resolve("intra_forest_trust_abusable") {
		t.Fatal("a parent-child trust must make intra_forest_trust_abusable resolve")
	}
	noTrust := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeExternal}}}}
	if NewEnvResolver(noTrust, "attacker").Resolve("intra_forest_trust_abusable") {
		t.Fatal("an external-only trust must NOT make intra_forest_trust_abusable resolve")
	}
}

func TestResolve_CrossForestTrustSIDFilterDisabled(t *testing.T) {
	disabled := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeExternal, SIDFilteringDisabled: true}}}}
	if !NewEnvResolver(disabled, "attacker").Resolve("cross_forest_trust_sid_filter_disabled") {
		t.Fatal("external trust with SID filtering disabled must resolve")
	}
	enabled := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeExternal}}}}
	if NewEnvResolver(enabled, "attacker").Resolve("cross_forest_trust_sid_filter_disabled") {
		t.Fatal("external trust with SID filtering enabled (default) must NOT resolve")
	}
}
