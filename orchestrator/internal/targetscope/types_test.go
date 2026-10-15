package targetscope

import "testing"

func TestIsAuthorized_CIDREntry_LiteralIPContained(t *testing.T) {
	scope := &TargetScopeImport{AuthorizedTargets: []AuthorizedTarget{{CIDR: "10.0.1.0/24"}}}
	if !IsAuthorized("10.0.1.5", scope) {
		t.Error("expected 10.0.1.5 to be authorized by the 10.0.1.0/24 entry")
	}
	if IsAuthorized("10.0.2.5", scope) {
		t.Error("expected 10.0.2.5 to NOT be authorized -- outside the declared CIDR")
	}
}

func TestIsAuthorized_HostEntry_CaseInsensitiveExactMatch(t *testing.T) {
	scope := &TargetScopeImport{AuthorizedTargets: []AuthorizedTarget{{Host: "payment-gateway.internal"}}}
	if !IsAuthorized("Payment-Gateway.Internal", scope) {
		t.Error("expected a case-insensitive exact host match to be authorized")
	}
	if IsAuthorized("other-host.internal", scope) {
		t.Error("expected an unrelated hostname to NOT be authorized")
	}
}

func TestIsAuthorized_HostnameNeverMatchesCIDREntry(t *testing.T) {
	scope := &TargetScopeImport{AuthorizedTargets: []AuthorizedTarget{{CIDR: "10.0.1.0/24"}}}
	if IsAuthorized("payment-gateway.internal", scope) {
		t.Error("expected a hostname to never match a CIDR entry -- no implicit DNS resolution")
	}
}

func TestUnauthorizedTargets_NilScope_FailsOpen(t *testing.T) {
	got := UnauthorizedTargets([]string{"10.0.1.5", "anything.example"}, nil)
	if got != nil {
		t.Errorf("got %v, want nil -- no scope has ever been declared, so nothing is reported unauthorized", got)
	}
}

func TestUnauthorizedTargets_ScopeExists_ReportsEveryUncoveredHostOnce(t *testing.T) {
	scope := &TargetScopeImport{AuthorizedTargets: []AuthorizedTarget{{CIDR: "10.0.1.0/24"}, {Host: "approved.example"}}}
	got := UnauthorizedTargets([]string{"10.0.1.5", "10.0.2.5", "approved.example", "not-approved.example", "10.0.2.5"}, scope)
	want := []string{"10.0.2.5", "not-approved.example"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
			break
		}
	}
}
