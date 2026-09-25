//go:build windows

package main

import "testing"

func TestStoreAndReadProxyCredentials_RoundTrips(t *testing.T) {
	origUser, origPassword := ReadProxyCredentials()
	t.Cleanup(func() {
		if err := StoreProxyCredentials(origUser, origPassword); err != nil {
			t.Logf("cleanup: failed to restore original proxy credentials: %v", err)
		}
	})

	if err := StoreProxyCredentials("branch-svc-account", "s3cr3t-p@ss"); err != nil {
		t.Fatalf("StoreProxyCredentials: %v", err)
	}
	user, password := ReadProxyCredentials()
	if user != "branch-svc-account" {
		t.Errorf("user = %q, want branch-svc-account", user)
	}
	if password != "s3cr3t-p@ss" {
		t.Errorf("password = %q, want s3cr3t-p@ss", password)
	}
}

func TestReadProxyCredentials_AbsentReturnsEmpty(t *testing.T) {
	origUser, origPassword := ReadProxyCredentials()
	t.Cleanup(func() {
		if err := StoreProxyCredentials(origUser, origPassword); err != nil {
			t.Logf("cleanup: failed to restore original proxy credentials: %v", err)
		}
	})

	// Overwrite with an empty password, then confirm an absent
	// BAS_PROXY_PASSWORD_ENC value (never written) reads back as "" rather
	// than erroring -- an agent with no configured proxy credentials is the
	// normal, common case.
	if err := StoreProxyCredentials("only-user-no-password", ""); err != nil {
		t.Fatalf("StoreProxyCredentials: %v", err)
	}
	user, password := ReadProxyCredentials()
	if user != "only-user-no-password" {
		t.Errorf("user = %q, want only-user-no-password", user)
	}
	if password != "" {
		t.Errorf("password = %q, want empty (never stored)", password)
	}
}
