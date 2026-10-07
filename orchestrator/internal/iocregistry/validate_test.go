package iocregistry

import "testing"

func TestIsKnownType(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"ip", true},
		{"file_hash", true},
		{"certificate", true},
		{"not_a_real_type", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsKnownType(c.in); got != c.want {
			t.Errorf("IsKnownType(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
