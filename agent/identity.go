package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
)

type Identity struct {
	AgentID   string
	Hostname  string
	IPAddress string
	OSVersion string
	Username  string
}

func collectIdentity() Identity {
	hostname, _ := os.Hostname()

	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = os.Getenv("LOGNAME")
	}
	if username == "" {
		username = "unknown"
	}

	h := sha256.Sum256([]byte(hostname))
	agentID := hex.EncodeToString(h[:])[:16]

	return Identity{
		AgentID:   agentID,
		Hostname:  hostname,
		IPAddress: getOutboundIP(),
		OSVersion: getOSVersion(),
		Username:  username,
	}
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
