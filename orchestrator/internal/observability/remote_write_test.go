package observability

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	snappy "github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/encoding/protowire"
)

// decodeWriteRequest parses a remote-write body the way a Prometheus receiver
// does: snappy block, then WriteRequest{ timeseries = 1 }.
func decodeWriteRequest(t *testing.T, body []byte) map[string]float64 {
	t.Helper()
	raw, err := snappy.Decode(nil, body)
	if err != nil {
		t.Fatalf("snappy decode: %v", err)
	}
	got := map[string]float64{}
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 || num != 1 || typ != protowire.BytesType {
			t.Fatalf("WriteRequest field %d type %d", num, typ)
		}
		raw = raw[n:]
		ts, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			t.Fatal("bad timeseries")
		}
		raw = raw[m:]
		name := ""
		var value float64
		for len(ts) > 0 {
			fnum, ftyp, fn := protowire.ConsumeTag(ts)
			ts = ts[fn:]
			switch {
			case fnum == 1 && ftyp == protowire.BytesType: // Label
				lb, ln := protowire.ConsumeBytes(ts)
				ts = ts[ln:]
				var k, v string
				for len(lb) > 0 {
					lnum, _, ln2 := protowire.ConsumeTag(lb)
					lb = lb[ln2:]
					s, sn := protowire.ConsumeBytes(lb)
					lb = lb[sn:]
					if lnum == 1 {
						k = string(s)
					} else {
						v = string(s)
					}
				}
				if k == "__name__" {
					name = v
				}
			case fnum == 2 && ftyp == protowire.BytesType: // Sample
				sb, sn := protowire.ConsumeBytes(ts)
				ts = ts[sn:]
				for len(sb) > 0 {
					snum, styp, sn2 := protowire.ConsumeTag(sb)
					sb = sb[sn2:]
					if snum == 1 && styp == protowire.Fixed64Type {
						v, vn := protowire.ConsumeFixed64(sb)
						sb = sb[vn:]
						value = math.Float64frombits(v)
					} else {
						_, vn := protowire.ConsumeVarint(sb)
						sb = sb[vn:]
					}
				}
			default:
				t.Fatalf("unexpected TimeSeries field %d", fnum)
			}
		}
		got[name] = value
	}
	return got
}

type receiver struct {
	mu      sync.Mutex
	headers http.Header
	bodies  [][]byte
	status  int
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.headers = req.Header.Clone()
	r.bodies = append(r.bodies, body)
	status := r.status
	r.mu.Unlock()
	if status == 0 {
		status = http.StatusNoContent
	}
	w.WriteHeader(status)
}

func TestRemoteWrite_PushesDecodableSeriesToReceiver(t *testing.T) {
	m := newTestMetrics(t)
	m.ActiveSteps.Set(7)
	m.ExecutionDuration.WithLabelValues("agent_task").Observe(2)
	rcv := &receiver{}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	w, err := NewRemoteWriter(srv.URL, m.Families)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Push(context.Background(), time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if rcv.headers.Get("Content-Encoding") != "snappy" || rcv.headers.Get("Content-Type") != "application/x-protobuf" {
		t.Fatalf("headers = %v", rcv.headers)
	}
	if rcv.headers.Get("X-Prometheus-Remote-Write-Version") != "0.1.0" {
		t.Fatalf("missing remote-write version header")
	}
	series := decodeWriteRequest(t, rcv.bodies[0])
	if series["exercise_active_steps"] != 7 {
		t.Fatalf("exercise_active_steps = %v, want 7 (series: %v)", series["exercise_active_steps"], series)
	}
	if series["execution_duration_seconds_count"] != 1 {
		t.Fatalf("histogram count not exported: %v", series)
	}
}

func TestRemoteWrite_ServerErrorIsReported(t *testing.T) {
	rcv := &receiver{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rcv)
	defer srv.Close()
	m := newTestMetrics(t)
	w, _ := NewRemoteWriter(srv.URL, m.Families)
	if err := w.Push(context.Background(), time.Now()); err == nil {
		t.Fatal("Push returned nil for a 500 from the receiver")
	}
}

func TestRemoteWrite_NoEndpointMeansNoWriter(t *testing.T) {
	w, err := NewRemoteWriter("", nil)
	if err != nil || w != nil {
		t.Fatalf("NewRemoteWriter(\"\") = %v, %v; want nil, nil", w, err)
	}
}

func TestRemoteWrite_RejectsNonHTTPURL(t *testing.T) {
	for _, bad := range []string{"ftp://x/api/v1/write", "remote-host:9009"} {
		if _, err := NewRemoteWriter(bad, nil); err == nil {
			t.Errorf("%q accepted, want error", bad)
		}
	}
}

func TestRemoteWrite_LeavesRegistryValuesUnchanged(t *testing.T) {
	m := newTestMetrics(t)
	m.ExecutionErrors.WithLabelValues("agent_task", "dispatch_error").Add(3)
	srv := httptest.NewServer(&receiver{})
	defer srv.Close()
	w, _ := NewRemoteWriter(srv.URL, m.Families)
	for i := 0; i < 2; i++ {
		if err := w.Push(context.Background(), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if got := familySum(m, "execution_errors_total"); got != 3 {
		t.Fatalf("counter after pushes = %v, want 3", got)
	}
}
