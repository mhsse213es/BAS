package networktransport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

func TestTCPCleartextProbe_RefusedConnection_Secure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing is listening now -- a real, fast, deterministic refusal

	p := TCPCleartextProbe{}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	if state != networksecurity.Secure {
		t.Fatalf("state = %q (reason: %s), want Secure -- nothing is listening, there is genuinely no cleartext path to downgrade to", state, reason)
	}
}

func TestTCPCleartextProbe_UnprompedHTTPBanner_Insecure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var bytesReceivedFromClient []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"))
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := conn.Read(buf) // never errors meaningfully if the client sends nothing; just records what arrived, if anything
		bytesReceivedFromClient = buf[:n]
	}()

	p := TCPCleartextProbe{}
	port := ln.Addr().(*net.TCPAddr).Port
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	<-done
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- an unprompted HTTP banner positively identifies a cleartext protocol", state, reason)
	}
	if len(bytesReceivedFromClient) != 0 {
		t.Fatalf("the probe sent %d bytes to the server -- it must only read a banner, never send anything", len(bytesReceivedFromClient))
	}
}

func TestTCPCleartextProbe_NoBannerWithinWindow_Unknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(2 * time.Second) // never writes anything within the probe's short window
	}()

	p := TCPCleartextProbe{}
	port := ln.Addr().(*net.TCPAddr).Port
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, 200*time.Millisecond)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown -- connecting with no banner at all proves nothing", state, reason)
	}
}

func TestTCPCleartextProbe_UnrecognizedBanner_Unknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("not a recognized protocol greeting"))
	}()

	p := TCPCleartextProbe{}
	port := ln.Addr().(*net.TCPAddr).Port
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown -- an unrecognized response is never positive proof of either state", state, reason)
	}
}

func TestTCPCleartextProbe_DialError_Unknown(t *testing.T) {
	p := TCPCleartextProbe{dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errSimulatedDialFailure
	}}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 80}, time.Second)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown", state, reason)
	}
}

var errSimulatedDialFailure = errors.New("simulated dial failure")
