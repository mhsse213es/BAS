package bfsisim

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSimulator_DirectoryListsSyntheticIdentities(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()

	resp, err := http.Get("http://" + s.Addr() + "/api/directory/identities")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	var ids []Identity
	if err := json.NewDecoder(resp.Body).Decode(&ids); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(ids) < 5 {
		t.Fatalf("got %d identities, want at least 5", len(ids))
	}
	for _, id := range ids {
		if !strings.HasPrefix(id.SAM, "bas-sim-") {
			t.Errorf("identity %q is not clearly synthetic (want bas-sim- prefix)", id.SAM)
		}
	}
}
