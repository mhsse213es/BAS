package connector

import (
	"testing"

	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

// TestNewProductionScheduler_WiresEvidenceAndIdentity guards the exact
// wiring gap that shipped in cmd/server/main.go: the running server built
// the scheduler with bare NewScheduler + WithIdentityStore but WITHOUT
// WithEvidenceStore. With s.evidence nil, recordSourceSync returns before
// it records a single source instance, trust version, observation, or
// threat clock -- so threat_observed, the threat/intelligence clocks, and
// every velocity measurement silently never record, even though content
// generation (which carries its own evidence store) keeps working. The
// server must build the scheduler through NewProductionScheduler so the
// evidence layer can never be left unwired again.
func TestNewProductionScheduler_WiresEvidenceAndIdentity(t *testing.T) {
	es := evidence.NewStore(nil)
	is := threatidentity.NewStore(nil)

	s := NewProductionScheduler(nil, nil, nil, 24, nil, nil, es, is)

	if s.evidence == nil {
		t.Fatal("NewProductionScheduler must wire the evidence store; a nil evidence store silently disables all clock/observation/threat_observed recording")
	}
	if s.identity == nil {
		t.Fatal("NewProductionScheduler must wire the identity store")
	}
}
