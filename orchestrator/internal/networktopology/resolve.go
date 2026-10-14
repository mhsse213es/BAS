package networktopology

import (
	"fmt"
	"net"
)

// ResolveZoneCIDRs returns the CIDRs for the zone named zoneName in
// zones. Two zones sharing the same Name are genuinely ambiguous -- this
// returns an error rather than silently picking one, the same failure
// mode networkpolicy's own (unexported) zone resolution already treats
// as unresolvable.
func ResolveZoneCIDRs(zoneName string, zones []Zone) ([]string, error) {
	var found []Zone
	for _, z := range zones {
		if z.Name == zoneName {
			found = append(found, z)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("networktopology: zone %q not found", zoneName)
	}
	if len(found) > 1 {
		return nil, fmt.Errorf("networktopology: zone name %q is ambiguous -- %d zones share this name", zoneName, len(found))
	}
	return found[0].CIDRs, nil
}

// ZoneForHost returns the name of the zone whose CIDRs contain host (a
// literal IP address). If more than one zone's CIDRs contain host, that
// is ambiguous and returns an error rather than picking one arbitrarily.
func ZoneForHost(host string, zones []Zone) (string, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("networktopology: %q is not a literal IP address", host)
	}
	var matches []string
	for _, z := range zones {
		for _, c := range z.CIDRs {
			_, ipNet, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			if ipNet.Contains(ip) {
				matches = append(matches, z.Name)
				break
			}
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("networktopology: no declared zone contains host %q", host)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("networktopology: host %q matches multiple zones (%v) -- ambiguous", host, matches)
	}
	return matches[0], nil
}
