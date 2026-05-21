package main

import (
	"os"
	"strings"
)

type Config struct {
	ServerURL string
	EnvLabel  string
}

func loadConfig() Config {
	serverURL := os.Getenv("BAS_SERVER_URL")
	envLabel := os.Getenv("BAS_ENV_LABEL")

	if serverURL == "" || envLabel == "" {
		if u, e := readServiceParams(); u != "" || e != "" {
			if serverURL == "" {
				serverURL = u
			}
			if envLabel == "" {
				envLabel = e
			}
		}
	}
	if serverURL == "" {
		serverURL = "http://localhost:9000"
	}
	if envLabel == "" {
		envLabel = "Production"
	}
	return Config{
		ServerURL: strings.TrimRight(serverURL, "/"),
		EnvLabel:  envLabel,
	}
}
