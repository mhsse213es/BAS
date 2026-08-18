package main

import (
	"net"
	"os"
	"os/user"
)

// Identity mirrors the fields agent/identity.go's Identity carries that
// EnrollRequest/Heartbeat actually consume -- AgentID is a stable
// hostname-derived value (Phase 1 has no persisted-ID store yet; if a
// stable-across-reinstalls ID is needed later, that's a Phase 2+ decision,
// not blocking Phase 1's enrollment proof).
type Identity struct {
	AgentID   string
	Hostname  string
	IPAddress string
	Username  string
	OSVersion string
}

func buildIdentity() Identity {
	hostname, _ := os.Hostname()
	ip := localIPAddress()
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	return Identity{
		AgentID:   hostname,
		Hostname:  hostname,
		IPAddress: ip,
		Username:  username,
		OSVersion: getOSVersion(),
	}
}

// localIPAddress mirrors agent/identity.go's approach: dial a well-known
// external address (no packet actually sent for UDP) purely to let the OS
// pick the outbound-routable local address.
func localIPAddress() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
