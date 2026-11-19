package bfsisim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSimulator_StartServesAllFourEndpoints(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()

	base := "http://" + s.Addr()
	for _, path := range []string{
		"/api/banking/apps",
		"/api/payments/gateways",
		"/api/atm/switches",
		"/api/data/cardholder-locations",
	} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", path, resp.StatusCode)
		}
		var services []Service
		if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
			t.Fatalf("GET %s: decode: %v", path, err)
		}
		resp.Body.Close()
		if len(services) == 0 {
			t.Errorf("GET %s: empty service list", path)
		}
		for _, svc := range services {
			if svc.ID == "" {
				t.Errorf("GET %s: service with empty id", path)
			}
		}
	}
}

func TestSimulator_RegisteredServicesNonEmpty(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	ids := s.RegisteredServices()
	if len(ids) == 0 {
		t.Fatal("RegisteredServices returned no ids")
	}
}

func TestSimulator_RejectsNonGetMethod(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()

	resp, err := http.Post("http://"+s.Addr()+"/api/banking/apps", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/banking/apps: status %d, want 405", resp.StatusCode)
	}
}

func TestSimulator_LedgerCreateAndReconcile(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()
	base := "http://" + s.Addr()

	body := `{"id":"bas-sim-tx-1","amount":100.00,"account":"test-acct-1"}`
	resp, err := http.Post(base+"/api/ledger/transactions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST status %d, want 201", resp.StatusCode)
	}

	resp2, err := http.Post(base+"/api/ledger/transactions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("duplicate POST: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate POST status %d, want 409", resp2.StatusCode)
	}

	resp3, err := http.Get(base + "/api/ledger/transactions/bas-sim-tx-1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	var tx Transaction
	if err := json.NewDecoder(resp3.Body).Decode(&tx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp3.Body.Close()
	if tx.ID != "bas-sim-tx-1" || tx.Amount != 100.00 {
		t.Errorf("GET returned %+v, want id=bas-sim-tx-1 amount=100", tx)
	}

	reconcileOK := `{"expectedTotal":100.00}`
	rResp, err := http.Post(base+"/api/ledger/reconcile", "application/json", strings.NewReader(reconcileOK))
	if err != nil {
		t.Fatalf("reconcile POST: %v", err)
	}
	var reconcileResult struct {
		Balanced    bool    `json:"balanced"`
		ActualTotal float64 `json:"actualTotal"`
	}
	if err := json.NewDecoder(rResp.Body).Decode(&reconcileResult); err != nil {
		t.Fatalf("reconcile decode: %v", err)
	}
	rResp.Body.Close()
	if !reconcileResult.Balanced {
		t.Errorf("reconcile with correct expectedTotal reported balanced=false, actualTotal=%v", reconcileResult.ActualTotal)
	}

	reconcileBad := `{"expectedTotal":999.00}`
	rResp2, err := http.Post(base+"/api/ledger/reconcile", "application/json", strings.NewReader(reconcileBad))
	if err != nil {
		t.Fatalf("reconcile POST: %v", err)
	}
	var reconcileResult2 struct {
		Balanced bool `json:"balanced"`
	}
	if err := json.NewDecoder(rResp2.Body).Decode(&reconcileResult2); err != nil {
		t.Fatalf("reconcile decode: %v", err)
	}
	rResp2.Body.Close()
	if reconcileResult2.Balanced {
		t.Error("reconcile with wrong expectedTotal reported balanced=true")
	}

	req, _ := http.NewRequest(http.MethodDelete, base+"/api/ledger/transactions/bas-sim-tx-1", nil)
	resp4, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("DELETE status %d, want 200", resp4.StatusCode)
	}

	resp5, err := http.Get(base + "/api/ledger/transactions/bas-sim-tx-1")
	if err != nil {
		t.Fatalf("GET after delete: %v", err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusNotFound {
		t.Errorf("GET after delete status %d, want 404", resp5.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodDelete, base+"/api/ledger/transactions/bas-sim-tx-1", nil)
	resp6, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("DELETE already-gone: %v", err)
	}
	resp6.Body.Close()
	if resp6.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE of already-removed tx status %d, want 404 (undo scripts must tolerate this)", resp6.StatusCode)
	}
}

func TestSimulator_LedgerConcurrentWritesDoNotCorrupt(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()
	base := "http://" + s.Addr()

	const n = 20
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"id":"bas-sim-tx-%d","amount":1.0,"account":"a"}`, i)
			resp, err := http.Post(base+"/api/ledger/transactions", "application/json", strings.NewReader(body))
			if err == nil {
				resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()

	resp, err := http.Get(base + "/api/ledger/transactions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var list []Transaction
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != n {
		t.Errorf("got %d transactions after %d concurrent writes, want %d (every write must land, none lost or corrupted)", len(list), n, n)
	}
}
