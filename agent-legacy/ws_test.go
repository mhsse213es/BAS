package main

import "testing"

func TestBuildWSURL_ConvertsSchemeAndAddsQueryParams(t *testing.T) {
	got := buildWSURL(Config{ServerURL: "http://example.com:9000", AgentSecret: "s3cr3t"}, "agent-1")
	want := "ws://example.com:9000/ws/agent?agentId=agent-1&agentSecret=s3cr3t"
	if got != want {
		t.Errorf("buildWSURL = %q, want %q", got, want)
	}
}

func TestBuildWSURL_HTTPSBecomesWSS(t *testing.T) {
	got := buildWSURL(Config{ServerURL: "https://example.com:9443"}, "agent-1")
	want := "wss://example.com:9443/ws/agent?agentId=agent-1"
	if got != want {
		t.Errorf("buildWSURL = %q, want %q", got, want)
	}
}
