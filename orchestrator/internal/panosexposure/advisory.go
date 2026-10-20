package panosexposure

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed advisories/*.json
var advisoryFiles embed.FS

// LoadBuiltinAdvisory returns an advisory shipped with this package, verified
// against its vendor source. It never fabricates an advisory: an unknown CVE is
// an error, not a guess.
func LoadBuiltinAdvisory(cve string) (Advisory, error) {
	data, err := advisoryFiles.ReadFile("advisories/" + cve + ".json")
	if err != nil {
		return Advisory{}, fmt.Errorf("no built-in advisory for %q", cve)
	}
	var adv Advisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return Advisory{}, fmt.Errorf("built-in advisory %q is invalid: %w", cve, err)
	}
	if adv.CVE != cve {
		return Advisory{}, fmt.Errorf("built-in advisory file %q names %q", cve, adv.CVE)
	}
	return adv, nil
}
