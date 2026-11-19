package license

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The licence generator (packaging/licensing/licensegen) refuses to sign an add-on that
// is not in its own recognisedAddons list. The server grants only the add-ons in
// addonProducts. If the two lists drift apart, a licence can be issued that the server
// ignores, or the server grants one that cannot be issued. This test fails on any drift.
var recognisedAddonsRE = regexp.MustCompile(`recognisedAddons\s*=\s*map\[string\]bool\{([^}]*)\}`)
var quotedRE = regexp.MustCompile(`"([^"]+)"`)

func TestAddonAllowlistMatchesLicenceGenerator(t *testing.T) {
	src, err := os.ReadFile("../../../packaging/licensing/licensegen/main.go")
	if err != nil {
		t.Fatalf("read licensegen: %v", err)
	}
	m := recognisedAddonsRE.FindSubmatch(src)
	if m == nil {
		t.Fatal("recognisedAddons not found in licensegen; the guard cannot check the allowlist")
	}
	var generator []string
	for _, q := range quotedRE.FindAllSubmatch(m[1], -1) {
		generator = append(generator, string(q[1]))
	}
	var server []string
	for _, name := range addonProducts {
		server = append(server, name)
	}
	sort.Strings(generator)
	sort.Strings(server)
	if len(generator) == 0 {
		t.Fatal("parsed no add-ons from licensegen; the guard would pass vacuously")
	}
	if strings.Join(generator, ",") != strings.Join(server, ",") {
		t.Fatalf("add-on allowlists differ: licensegen recognises %v, server grants %v", generator, server)
	}
}
