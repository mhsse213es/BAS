package segprobe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPacks_LoadAndHavePositiveControls(t *testing.T) {
	files, err := filepath.Glob("../../../lab/segmentation/scenarios/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d packs, want 3", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s, err := LoadScenario(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var hasAllow, hasDeny bool
		for _, p := range s.Probes {
			hasAllow = hasAllow || p.Expect == ExpectAllow
			hasDeny = hasDeny || p.Expect == ExpectDeny
		}
		if !hasAllow || !hasDeny {
			t.Fatalf("%s: needs both an allow and a deny probe", f)
		}
	}
}
