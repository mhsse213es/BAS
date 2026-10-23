package exec

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/safety"
)

// testGuard returns a Guard for a lab engagement that allows only the given
// server origin, with limits generous enough not to interfere.
func testGuard(t *testing.T, serverURL string, m model.Model) *safety.Guard {
	t.Helper()
	now := time.Now()
	e := safety.Engagement{
		ID: "test", Customer: "toy", Environment: "lab", Hosts: []string{serverURL}, Approver: "test",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		MaxRequests: 1 << 20, MaxConcurrent: 64, RPS: 1e6,
	}
	g, err := safety.NewGuard(e, nil, m, safety.GuardOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
