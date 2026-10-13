package networkpolicy

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePortRange parses a Rule.PortRange string. "" matches any port. A
// bare number matches only that port. A "low-high" range matches any port
// in [low, high] inclusive. Any other form is rejected -- this is the one
// place that decides whether a PortRange string is well-formed; it is
// never silently treated as "any".
func ParsePortRange(s string) (matchAny bool, low, high int, err error) {
	if s == "" {
		return true, 0, 0, nil
	}
	if !strings.Contains(s, "-") {
		p, convErr := strconv.Atoi(s)
		if convErr != nil || p < 1 || p > 65535 {
			return false, 0, 0, fmt.Errorf("networkpolicy: invalid port %q", s)
		}
		return false, p, p, nil
	}
	parts := strings.SplitN(s, "-", 2)
	lo, loErr := strconv.Atoi(parts[0])
	hi, hiErr := strconv.Atoi(parts[1])
	if loErr != nil || hiErr != nil || lo < 1 || hi > 65535 || lo > hi {
		return false, 0, 0, fmt.Errorf("networkpolicy: invalid port range %q", s)
	}
	return false, lo, hi, nil
}

// MatchesPort reports whether port falls within r.PortRange.
func (r Rule) MatchesPort(port int) (bool, error) {
	matchAny, low, high, err := ParsePortRange(r.PortRange)
	if err != nil {
		return false, err
	}
	if matchAny {
		return true, nil
	}
	return port >= low && port <= high, nil
}
