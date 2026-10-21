package main

import "testing"

// An existing admin is never changed by startup, whatever the environment says. This is what stops a
// dashboard password change from being reverted on restart.
func TestDecideAdminBootstrap_ExistingAdminIsLeftAlone(t *testing.T) {
	for _, pw := range []string{"", "a-long-enough-password"} {
		act, err := decideAdminBootstrap(true, pw)
		if err != nil || act != adminLeave {
			t.Fatalf("existing admin with password %q: action %v err %v, want leave", pw, act, err)
		}
	}
}

// With no admin, an environment password creates the first admin.
func TestDecideAdminBootstrap_FirstRunWithPasswordCreates(t *testing.T) {
	act, err := decideAdminBootstrap(false, "a-long-enough-password")
	if err != nil || act != adminCreate {
		t.Fatalf("first run with password: action %v err %v, want create", act, err)
	}
}

// With no admin and no password there is no default credential. Nothing is created, and the first-run
// setup endpoint is the way in.
func TestDecideAdminBootstrap_NoDefaultCredential(t *testing.T) {
	act, err := decideAdminBootstrap(false, "")
	if err != nil || act != adminNone {
		t.Fatalf("first run without password: action %v err %v, want none", act, err)
	}
}

// A password below the minimum is refused rather than stored.
func TestDecideAdminBootstrap_ShortPasswordRefused(t *testing.T) {
	if _, err := decideAdminBootstrap(false, "short"); err == nil {
		t.Fatal("short password accepted for first-run admin")
	}
}
