package ubuntumatch

import (
	"errors"
	"fmt"
	"strings"
)

// ErrIncompleteInventory is returned when the inventory output was cut off by
// the collection step's output cap. A partial list must not be treated as a
// complete inventory: packages missing from it would otherwise read as absent.
var ErrIncompleteInventory = errors.New("inventory output truncated; host inventory is incomplete")

// Recommended collection command. It emits one line per package with the
// fields needed to filter out removed packages and to keep architectures apart.
// The current scenario (scenarios/linux-installed-software.yaml) emits only
// Name|Version and does not filter by status; switching to this command needs
// a scenario edit and a re-signed .sig.
const RecommendedDpkgCommand = `dpkg-query -W -f='${Package}|${Version}|${Architecture}|${db:Status-Status}\n'`

// ParseDpkgInventory builds the installed-package map for one host from the
// output of RecommendedDpkgCommand. Only packages whose status is "installed"
// are kept. If truncated is true the inventory is rejected outright.
//
// Lines must have four fields. Malformed lines are an error, not skipped:
// silently dropping a line would hide a package from the matcher.
func ParseDpkgInventory(raw string, truncated bool) (map[string]string, error) {
	if truncated {
		return nil, ErrIncompleteInventory
	}
	pkgs := map[string]string{}
	for n, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) != 4 {
			return nil, fmt.Errorf("inventory line %d: expected 4 fields, got %d", n+1, len(f))
		}
		name, version, arch, status := strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.TrimSpace(f[2]), strings.TrimSpace(f[3])
		if name == "" || version == "" || arch == "" {
			return nil, fmt.Errorf("inventory line %d: empty name, version, or architecture", n+1)
		}
		if status != "installed" {
			continue
		}
		// Keep the architecture-independent name. If the same package is installed
		// for two architectures with different versions, the matcher cannot tell
		// which one is exposed, so mark the name ambiguous and let the matcher report UNKNOWN.
		if prev, ok := pkgs[name]; ok && prev != version {
			pkgs[name] = AmbiguousVersion
			continue
		}
		if pkgs[name] == AmbiguousVersion {
			continue
		}
		pkgs[name] = version
	}
	return pkgs, nil
}

// AmbiguousVersion marks a package name installed at two different versions on
// different architectures. ValidVersion rejects it, so the matcher returns UNKNOWN.
const AmbiguousVersion = "AMBIGUOUS"
