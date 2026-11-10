//go:build windows

package main

import (
	"errors"
	"testing"
)

// The uninstall must never report success while a service is still registered, even if it also cleaned leftover data.
func TestUninstallOutcome(t *testing.T) {
	boom := errors.New("delete service: access denied")
	cases := []struct {
		name      string
		removed   bool
		lastErr   error
		footprint int
		wantErr   bool
	}{
		{"service removed", true, nil, 0, false},
		{"service removed, one name failed", true, boom, 0, true},
		{"removal failed, data cleaned anyway", false, boom, 5, true},
		{"removal failed, no data", false, boom, 0, true},
		{"nothing registered, leftover data cleaned", false, nil, 3, false},
		{"nothing registered, nothing found", false, nil, 0, true},
	}
	for _, c := range cases {
		if err := uninstallOutcome(c.removed, c.lastErr, c.footprint); (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}
