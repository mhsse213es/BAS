package main

import "testing"

func TestBuildIdentity_PopulatesRequiredFields(t *testing.T) {
	id := buildIdentity()
	if id.Hostname == "" {
		t.Error("Hostname is empty")
	}
	if id.OSVersion == "" {
		t.Error("OSVersion is empty")
	}
}
