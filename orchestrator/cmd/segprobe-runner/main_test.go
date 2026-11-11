package main

import (
	"net"
	"testing"
	"time"
)

func TestProbeTCP_Connected(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if out := probeTCP(l.Addr().String(), 2*time.Second); out != "connected" {
		t.Fatalf("got %s, want connected", out)
	}
}

func TestProbeTCP_Refused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	if out := probeTCP(addr, 2*time.Second); out != "refused" {
		t.Fatalf("got %s, want refused", out)
	}
}

func TestProbeTCP_TimeoutIsNotRefused(t *testing.T) {
	// TEST-NET-1 is non-routable; the dial must not complete within the deadline.
	out := probeTCP("192.0.2.1:9", 200*time.Millisecond)
	if out != "timeout" && out != "destination_unavailable" {
		t.Fatalf("got %s, want timeout or destination_unavailable", out)
	}
}
