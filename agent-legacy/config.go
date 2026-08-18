package main

import "os"

// Config mirrors agent/config.go's Config exactly -- same env var names, so
// the same install/deployment tooling and documentation (BAS_SERVER_URL,
// BAS_ENV_LABEL, BAS_AGENT_SECRET) works for both agents without an operator
// needing to know which one they're configuring.
type Config struct {
	ServerURL   string
	EnvLabel    string
	AgentSecret string
}

func loadConfig() Config {
	return Config{
		ServerURL:   os.Getenv("BAS_SERVER_URL"),
		EnvLabel:    os.Getenv("BAS_ENV_LABEL"),
		AgentSecret: os.Getenv("BAS_AGENT_SECRET"),
	}
}
