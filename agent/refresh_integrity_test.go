//go:build windows

package main

import (
	"errors"
	"testing"
)

func TestRefreshStoredIntegrityStoresTheCurrentHash(t *testing.T) {
	var stored string
	err := refreshStoredIntegrity(func() (string, error) { return "abc123", nil }, func(h string) error { stored = h; return nil })
	if err != nil || stored != "abc123" {
		t.Fatalf("stored %q err %v", stored, err)
	}
}

func TestRefreshStoredIntegrityReportsHashAndStoreFailures(t *testing.T) {
	boom := errors.New("boom")
	if err := refreshStoredIntegrity(func() (string, error) { return "", boom }, func(string) error { t.Fatal("must not store"); return nil }); err == nil {
		t.Fatal("hash failure must be reported")
	}
	if err := refreshStoredIntegrity(func() (string, error) { return "h", nil }, func(string) error { return boom }); err == nil {
		t.Fatal("store failure must be reported")
	}
	if err := refreshStoredIntegrity(func() (string, error) { return "", nil }, func(string) error { t.Fatal("must not store empty"); return nil }); err == nil {
		t.Fatal("an empty hash must be refused")
	}
}
