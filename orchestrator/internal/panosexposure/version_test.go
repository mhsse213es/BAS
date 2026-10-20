package panosexposure

import "testing"

func TestVersionOrdering(t *testing.T) {
	// Synthetic ordering fixtures.
	ordered := []string{"10.2.0", "10.2.3", "10.2.3-h1", "10.2.3-h2", "10.2.4", "10.3.0", "11.0.0"}
	for i := 0; i < len(ordered)-1; i++ {
		a, err := parseVersion(ordered[i])
		if err != nil {
			t.Fatalf("parse %s: %v", ordered[i], err)
		}
		b, err := parseVersion(ordered[i+1])
		if err != nil {
			t.Fatalf("parse %s: %v", ordered[i+1], err)
		}
		if a.compare(b) >= 0 {
			t.Fatalf("%s should sort before %s", ordered[i], ordered[i+1])
		}
		if b.compare(a) <= 0 {
			t.Fatalf("%s should sort after %s", ordered[i+1], ordered[i])
		}
	}
	same, _ := parseVersion("10.2.3-h1")
	if same.compare(same) != 0 {
		t.Fatal("a version must compare equal to itself")
	}
}
