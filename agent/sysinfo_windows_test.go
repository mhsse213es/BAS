//go:build windows

package main

import "testing"

// TestGetDomainJoined_ReturnsNonNilAndDoesNotPanic proves the Win32 call
// succeeds on this real Windows build host and returns a real answer, not a
// silently-swallowed nil. Whether this specific machine is domain-joined is
// not asserted -- that depends on the host running the test -- only that the
// mechanism itself works.
func TestGetDomainJoined_ReturnsNonNilAndDoesNotPanic(t *testing.T) {
	got := getDomainJoined()
	if got == nil {
		t.Fatal("getDomainJoined() = nil, want a real answer on a live Windows host (NetGetJoinInformation should succeed here)")
	}
	t.Logf("this build host reports domain_joined=%v", *got)
}
