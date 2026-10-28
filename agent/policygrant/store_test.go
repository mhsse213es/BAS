package policygrant

import (
	"bytes"
	"testing"
	"time"
)

func TestMarshalUnmarshalSigned_RoundTrips(t *testing.T) {
	key := []byte("a fake 32-byte test HMAC key!!!")
	s := Store{Grants: []Grant{{
		AgentID: "agent-1", Action: "T1003.006:default", Reason: "lab test",
		IssuedAt: fixedNow, ExpiresAt: fixedNow.Add(time.Hour),
	}}}

	data, mac, err := MarshalSigned(s, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalSigned(data, mac, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Grants) != 1 || got.Grants[0].AgentID != "agent-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestUnmarshalSigned_RejectsTamperedContent(t *testing.T) {
	key := []byte("a fake 32-byte test HMAC key!!!")
	s := Store{Grants: []Grant{{AgentID: "agent-1", Action: "T1003.006:default", Reason: "x", IssuedAt: fixedNow, ExpiresAt: fixedNow.Add(time.Hour)}}}
	data, mac, err := MarshalSigned(s, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("hand-edited content fails even though it still has the right shape", func(t *testing.T) {
		tampered := bytes.Replace(data, []byte("agent-1"), []byte("agent-9"), 1)
		if _, err := UnmarshalSigned(tampered, mac, key); err == nil {
			t.Fatal("expected a tampered file to be rejected")
		}
	})

	t.Run("wrong key fails", func(t *testing.T) {
		if _, err := UnmarshalSigned(data, mac, []byte("a different fake 32-byte key!!!")); err == nil {
			t.Fatal("expected the wrong key to be rejected")
		}
	})
}

func TestUnmarshalSigned_EmptyInputIsEmptyStore(t *testing.T) {
	// A missing/never-created grant file must mean "no grants", not an error --
	// every agent's first policy grant creates the store from nothing.
	got, err := UnmarshalSigned(nil, nil, []byte("any key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Grants) != 0 {
		t.Fatalf("got %+v, want empty", got)
	}
}

func TestStore_CheckGrant(t *testing.T) {
	valid := Grant{AgentID: "agent-1", Action: "T1003.006:default", IssuedAt: fixedNow, ExpiresAt: fixedNow.Add(time.Hour)}
	expired := Grant{AgentID: "agent-1", Action: "T1490:vss_delete", IssuedAt: fixedNow.Add(-2 * time.Hour), ExpiresAt: fixedNow.Add(-time.Hour)}
	scoped := Grant{AgentID: "agent-1", Action: "T1003.006:scoped", ScenarioID: "dcsync-live", IssuedAt: fixedNow, ExpiresAt: fixedNow.Add(time.Hour)}
	s := Store{Grants: []Grant{valid, expired, scoped}}

	t.Run("an unexpired matching grant authorizes", func(t *testing.T) {
		ok, status := s.CheckGrant("agent-1", "T1003.006:default", "", fixedNow)
		if !ok || status != "ok" {
			t.Fatalf("ok=%v status=%q", ok, status)
		}
	})

	t.Run("no matching grant at all reports absent", func(t *testing.T) {
		ok, status := s.CheckGrant("agent-1", "T1558.003:kerberoast", "", fixedNow)
		if ok || status != "absent" {
			t.Fatalf("ok=%v status=%q", ok, status)
		}
	})

	t.Run("a matching but expired grant reports expired, not absent", func(t *testing.T) {
		ok, status := s.CheckGrant("agent-1", "T1490:vss_delete", "", fixedNow)
		if ok || status != "expired" {
			t.Fatalf("ok=%v status=%q", ok, status)
		}
	})

	t.Run("a matching scoped grant against the wrong scenario reports scope_mismatch", func(t *testing.T) {
		ok, status := s.CheckGrant("agent-1", "T1003.006:scoped", "other-scenario", fixedNow)
		if ok || status != "scope_mismatch" {
			t.Fatalf("ok=%v status=%q", ok, status)
		}
	})

	t.Run("a different agent is always absent, even for an action/scenario that exists for someone else", func(t *testing.T) {
		ok, status := s.CheckGrant("agent-999", "T1003.006:default", "", fixedNow)
		if ok || status != "absent" {
			t.Fatalf("ok=%v status=%q", ok, status)
		}
	})
}
