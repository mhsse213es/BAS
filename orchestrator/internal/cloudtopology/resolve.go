package cloudtopology

import (
	"fmt"
	"net"
)

// SubnetForHost returns the CanonicalID of the subnet whose CIDRBlock
// contains host (a literal IP address). More than one match is
// ambiguous and returns an error rather than picking one arbitrarily
// -- the same discipline as networktopology.ZoneForHost.
func SubnetForHost(host string, subnets []CloudSubnet) (string, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("cloudtopology: %q is not a literal IP address", host)
	}
	var matches []string
	for _, s := range subnets {
		_, ipNet, err := net.ParseCIDR(s.CIDRBlock)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			matches = append(matches, s.CanonicalID)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("cloudtopology: no declared subnet contains host %q", host)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("cloudtopology: host %q matches multiple subnets (%v) -- ambiguous", host, matches)
	}
	return matches[0], nil
}
