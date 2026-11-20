package main

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

// privilegedFixtureFake adds the optional privileged-session capability to the
// fixture fake and records it in the same call log.
type privilegedFixtureFake struct {
	*fixtureFakeAdapter
	privUser string
}

func (p *privilegedFixtureFake) ConnectPrivileged(_ context.Context, cfg dbprobe.ConnectionConfig) error {
	p.calls = append(p.calls, "ConnectPrivileged")
	p.privUser = cfg.User
	return nil
}

// A fixture run with a seed credential opens the privileged session after the
// identity gate and before Seed, and seeds with that account, not the probe's.
func TestDBProbeOpensPrivilegedSessionBeforeSeed(t *testing.T) {
	ff := setupFixtureFake(t)
	provisionDBCred(t, "lab-pg-admin", "admin_user", testCredPassword)
	p := &privilegedFixtureFake{fixtureFakeAdapter: ff}
	orig := dbprobeNewAdapter
	dbprobeNewAdapter = func(string) (dbprobe.Adapter, bool) { return p, true }
	t.Cleanup(func() { dbprobeNewAdapter = orig })

	executeDBProbe(context.Background(), testDBProbeStep(func(s *protocol.DBProbeSpec) {
		s.FixtureID = "accounts"
		s.SeedCredentialRef = "dbcred:lab-pg-admin"
	}))
	calls := strings.Join(ff.calls, ",")
	iPriv, iSeed, iIdent := strings.Index(calls, "ConnectPrivileged"), strings.Index(calls, "Seed"), strings.Index(calls, "Identity")
	if iPriv < 0 || iPriv < iIdent || iPriv > iSeed {
		t.Fatalf("privileged session not between identity and seed: %s", calls)
	}
	if p.privUser != "admin_user" {
		t.Fatalf("privileged session used account %q, want admin_user", p.privUser)
	}
}
