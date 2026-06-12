package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsoDate(t *testing.T) {
	cases := map[string]string{
		"2017-12-14T16:46:06.044Z": "2017-12-14",
		"2025-01-15":               "2025-01-15",
		"":                         "",
		"bad":                      "",
	}
	for in, want := range cases {
		if got := isoDate(in); got != want {
			t.Errorf("isoDate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCountSigma(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Two rules tag T1548.002; one also tags T1059.001. A duplicate tag in the
	// same file must count once. A non-yaml file is ignored.
	write("a.yml", "tags:\n  - attack.t1548.002\n  - attack.t1548.002\n")
	write("b.yaml", "tags: [attack.t1548.002, attack.t1059.001]\n")
	write("c.txt", "attack.t1548.002")

	counts := countSigma(dir)
	if counts["T1548.002"] != 2 {
		t.Errorf("T1548.002 count = %d, want 2", counts["T1548.002"])
	}
	if counts["T1059.001"] != 1 {
		t.Errorf("T1059.001 count = %d, want 1", counts["T1059.001"])
	}
}

func TestLoadD3fend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "d3fend.json")
	body := `{"T1548.002":[{"id":"D3-EAL","name":"Executable Allowlisting"}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m := loadD3fend(path)
	cms := m["T1548.002"]
	if len(cms) != 1 || cms[0].ID != "D3-EAL" || cms[0].Name != "Executable Allowlisting" {
		t.Errorf("loadD3fend returned %+v", m)
	}
}
