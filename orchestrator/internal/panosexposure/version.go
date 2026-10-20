package panosexposure

import (
	"fmt"
	"regexp"
	"strconv"
)

// version is a parsed PAN-OS release: major.minor.patch with an optional
// hotfix number (-hN). A release without a hotfix sorts before its hotfixes.
type version struct {
	major, minor, patch, hotfix int
}

var versionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?$`)

// parseVersion rejects anything it does not recognise. It never guesses, so an
// unparseable version becomes VerdictUnknown rather than a wrong verdict.
func parseVersion(s string) (version, error) {
	m := versionPattern.FindStringSubmatch(s)
	if m == nil {
		return version{}, fmt.Errorf("unrecognised PAN-OS version %q", s)
	}
	var v version
	var err error
	if v.major, err = strconv.Atoi(m[1]); err != nil {
		return version{}, err
	}
	if v.minor, err = strconv.Atoi(m[2]); err != nil {
		return version{}, err
	}
	if v.patch, err = strconv.Atoi(m[3]); err != nil {
		return version{}, err
	}
	if m[4] != "" {
		if v.hotfix, err = strconv.Atoi(m[4]); err != nil {
			return version{}, err
		}
		// -hN is a hotfix on top of the base release, so it always sorts after
		// the base. Record it as hotfix N, which is always at least 1.
		if v.hotfix < 1 {
			return version{}, fmt.Errorf("invalid hotfix in %q", s)
		}
	}
	return v, nil
}

// compare returns -1, 0 or 1 for a < b, a == b, a > b.
func (a version) compare(b version) int {
	for _, pair := range [][2]int{
		{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}, {a.hotfix, b.hotfix},
	} {
		switch {
		case pair[0] < pair[1]:
			return -1
		case pair[0] > pair[1]:
			return 1
		}
	}
	return 0
}
