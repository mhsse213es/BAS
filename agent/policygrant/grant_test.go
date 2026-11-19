package policygrant

import (
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func TestRequest_Validate(t *testing.T) {
	valid := Request{Action: "T1003.006:default", Reason: "lab DCSync verification", TTL: time.Hour}

	t.Run("a complete request is valid", func(t *testing.T) {
		if err := valid.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("action is required", func(t *testing.T) {
		r := valid
		r.Action = ""
		if err := r.Validate(); err == nil {
			t.Fatal("expected an error for empty action")
		}
	})

	t.Run("action must be technique:action_key shaped -- a bare execution_class is never a valid scope", func(t *testing.T) {
		for _, bad := range []string{"destructive", "T1003.006", "T1003.006:", ":default"} {
			r := valid
			r.Action = bad
			if err := r.Validate(); err == nil {
				t.Fatalf("%q: expected an error", bad)
			}
		}
	})

	t.Run("reason is required", func(t *testing.T) {
		r := valid
		r.Reason = ""
		if err := r.Validate(); err == nil {
			t.Fatal("expected an error for empty reason")
		}
	})

	t.Run("TTL must be positive -- no permanent grants, ever", func(t *testing.T) {
		for _, ttl := range []time.Duration{0, -time.Hour} {
			r := valid
			r.TTL = ttl
			if err := r.Validate(); err == nil {
				t.Fatalf("ttl=%v: expected an error", ttl)
			}
		}
	})
}

func TestNewGrant(t *testing.T) {
	t.Run("binds the agent, sets issued/expiry from now+TTL", func(t *testing.T) {
		g, err := NewGrant("agent-123", Request{Action: "T1003.006:default", ScenarioID: "dcsync-live", Reason: "lab test", TTL: 30 * time.Minute}, fixedNow)
		if err != nil {
			t.Fatal(err)
		}
		if g.AgentID != "agent-123" {
			t.Fatalf("AgentID = %q", g.AgentID)
		}
		if !g.IssuedAt.Equal(fixedNow) {
			t.Fatalf("IssuedAt = %v, want %v", g.IssuedAt, fixedNow)
		}
		want := fixedNow.Add(30 * time.Minute)
		if !g.ExpiresAt.Equal(want) {
			t.Fatalf("ExpiresAt = %v, want %v", g.ExpiresAt, want)
		}
	})

	t.Run("refuses an invalid request -- construction cannot bypass Validate", func(t *testing.T) {
		if _, err := NewGrant("agent-123", Request{Action: "", Reason: "x", TTL: time.Hour}, fixedNow); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestGrant_Authorizes(t *testing.T) {
	base := Grant{
		AgentID:   "agent-123",
		Action:    "T1003.006:default",
		Reason:    "lab test",
		IssuedAt:  fixedNow,
		ExpiresAt: fixedNow.Add(time.Hour),
	}

	t.Run("matches agent + action, unscoped scenario authorizes any scenario", func(t *testing.T) {
		if !base.Authorizes("agent-123", "T1003.006:default", "any-scenario", fixedNow) {
			t.Fatal("expected authorized")
		}
		if !base.Authorizes("agent-123", "T1003.006:default", "", fixedNow) {
			t.Fatal("expected authorized with no scenario context")
		}
	})

	t.Run("a different agent is never authorized -- a copied grant file must not validate elsewhere", func(t *testing.T) {
		if base.Authorizes("agent-999", "T1003.006:default", "", fixedNow) {
			t.Fatal("expected refused for a different agent")
		}
	})

	t.Run("a different action is never authorized", func(t *testing.T) {
		if base.Authorizes("agent-123", "T1490:vss_delete", "", fixedNow) {
			t.Fatal("expected refused for a different action")
		}
	})

	t.Run("an expired grant is never authorized", func(t *testing.T) {
		if base.Authorizes("agent-123", "T1003.006:default", "", fixedNow.Add(time.Hour+time.Second)) {
			t.Fatal("expected refused once expired")
		}
	})

	t.Run("a scenario-scoped grant refuses a different scenario", func(t *testing.T) {
		scoped := base
		scoped.ScenarioID = "dcsync-live"
		if scoped.Authorizes("agent-123", "T1003.006:default", "other-scenario", fixedNow) {
			t.Fatal("expected refused for a non-matching scenario scope")
		}
		if !scoped.Authorizes("agent-123", "T1003.006:default", "dcsync-live", fixedNow) {
			t.Fatal("expected authorized for the matching scenario scope")
		}
	})
}
