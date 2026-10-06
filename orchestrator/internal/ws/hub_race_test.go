package ws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/gorilla/websocket"
)

// Run with -race. Senders hammer a connection while its peer disconnects;
// before the done-channel fix, readPump's close(c.send) raced with these
// sends (37 of the 39 race reports in CI).

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func hammer(stop <-chan struct{}, wg *sync.WaitGroup, send func()) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
			send()
		}
	}
}

func TestSendToAgent_ConcurrentWithDisconnect_NoRace(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := NewHub()
		srv := httptest.NewServer(http.HandlerFunc(h.ServeAgentWS))
		url := "ws" + strings.TrimPrefix(srv.URL, "http") + "?agentId=a1"
		client, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		waitFor(t, func() bool { return h.IsAgentConnected("a1") })

		stop := make(chan struct{})
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go hammer(stop, &wg, func() { h.SendToAgent("a1", models.WSMessage{Type: "test"}) })
		}
		client.Close()
		waitFor(t, func() bool { return !h.IsAgentConnected("a1") })
		close(stop)
		wg.Wait()
		srv.Close()
	}
}

func TestBroadcastBrowsers_ConcurrentWithDisconnect_NoRace(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := NewHub()
		h.SetAllowedOrigin("https://bas.internal")
		srv := httptest.NewServer(http.HandlerFunc(h.ServeBrowserWS))
		url := "ws" + strings.TrimPrefix(srv.URL, "http")
		client, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Origin": {"https://bas.internal"}})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		browsers := func() int {
			h.mu.RLock()
			defer h.mu.RUnlock()
			return len(h.browsers)
		}
		waitFor(t, func() bool { return browsers() == 1 })

		stop := make(chan struct{})
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go hammer(stop, &wg, func() { h.BroadcastBrowsers(models.WSMessage{Type: "test"}) })
		}
		client.Close()
		waitFor(t, func() bool { return browsers() == 0 })
		close(stop)
		wg.Wait()
		srv.Close()
	}
}
