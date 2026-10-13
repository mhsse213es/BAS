package networkgraph

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

func TestDialerProbe_SuccessfulConnectIsObserved(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)

	state, err := DialerProbe{}.Probe(context.Background(), Target{Host: "127.0.0.1", Port: addr.Port}, time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if state != cloudgraph.Observed {
		t.Fatalf("state = %q, want observed", state)
	}
}

func TestDialerProbe_ActivelyRefusedConnectionIsBlocked(t *testing.T) {
	// A port that WAS listening and is now closed reliably returns
	// "connection refused" on every platform this runs on, without ever
	// leaving loopback -- unlike dialing a port nothing ever bound to,
	// whose behavior can vary by platform/firewall.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()

	state, err := DialerProbe{}.Probe(context.Background(), Target{Host: "127.0.0.1", Port: addr.Port}, time.Second)
	if err == nil {
		t.Fatal("want a non-nil error for a refused connection")
	}
	if state != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked", state)
	}
}

func TestDialerProbe_GenericDialErrorIsUnknownNeverBlocked(t *testing.T) {
	// A real network timeout is unsafe/unreliable to force in a test
	// without risking real traffic off this host, so this injects the
	// dial seam directly -- the one case this plan tests via dependency
	// injection rather than a real socket.
	injected := context.DeadlineExceeded
	p := DialerProbe{dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, injected
	}}

	state, err := p.Probe(context.Background(), Target{Host: "10.0.0.1", Port: 443}, time.Second)
	if err != injected {
		t.Fatalf("err = %v, want the injected error unwrapped", err)
	}
	if state != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- a generic/timeout error must never be classified as blocked", state)
	}
}

func TestDialerProbe_ObservedConnectionIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			// Block reading -- if DialerProbe left its end open and wrote
			// or expected a reply, this goroutine would hang forever and
			// the test would time out, surfacing the leak.
			buf := make([]byte, 1)
			conn.Read(buf)
		}
	}()

	p := DialerProbe{}
	if _, err := p.Probe(context.Background(), Target{Host: "127.0.0.1", Port: addr.Port}, time.Second); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server side never saw the connection")
	}
	// If DialerProbe correctly closed its side immediately after connecting,
	// the accepted conn's Read above will return promptly with io.EOF rather
	// than hanging -- this test's own timeout (go test's default) is the
	// backstop if it doesn't.
}
