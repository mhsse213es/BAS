package dnssink

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"net"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func sendQuery(t *testing.T, conn net.Conn, name string) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query %q: %v", name, err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("send query %q: %v", name, err)
	}
}

func TestNewListener_BindsEphemeralPortAndReportsRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener(":0", DomainSuffix, pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		st := l.Status()
		if st.State != "running" {
			t.Errorf("State = %q, want running", st.State)
		}
		if st.Bind == "" {
			t.Error("Bind should report the actual bound address")
		}
	})
}

func TestListener_FullExchangeReassemblesAndRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener(":0", DomainSuffix, pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client, err := net.Dial("udp", l.LocalAddr().String())
		if err != nil {
			t.Fatalf("dial listener: %v", err)
		}
		defer client.Close()

		campaignID := "feedfacecafebeef"
		payload := "integration-test-payload"
		enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(payload))
		half := len(enc) / 2

		sendQuery(t, client, "000.2."+campaignID+"."+DomainSuffix)
		sendQuery(t, client, "001."+enc[:half]+"."+campaignID+"."+DomainSuffix)
		sendQuery(t, client, "002."+enc[half:]+"."+campaignID+"."+DomainSuffix)

		var (
			payloadHash string
			payloadSize int
			channel     string
		)
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := pool.QueryRow(context.Background(),
				`SELECT payload_hash, payload_size, channel FROM dlp_sink_receipts WHERE token = $1`,
				campaignID,
			).Scan(&payloadHash, &payloadSize, &channel)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no dlp_sink_receipts row for campaign %s within 5s: %v", campaignID, err)
			}
			time.Sleep(50 * time.Millisecond)
		}

		wantSum := sha256.Sum256([]byte(payload))
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash = %q, want sha256(%q)", payloadHash, payload)
		}
		if payloadSize != len(payload) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(payload))
		}
		if channel != "dns-tunnel" {
			t.Errorf("channel = %q, want dns-tunnel", channel)
		}
	})
}

func TestListener_MalformedPacketDoesNotCrashOrRespond(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener(":0", DomainSuffix, pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client, err := net.Dial("udp", l.LocalAddr().String())
		if err != nil {
			t.Fatalf("dial listener: %v", err)
		}
		defer client.Close()

		garbage := make([]byte, maxPacketBytes+10)
		if _, err := client.Write(garbage); err != nil {
			t.Fatalf("write garbage: %v", err)
		}
		sendQuery(t, client, "000.1.deadbeefcafebabe."+DomainSuffix)
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		if _, err := client.Read(buf); err != nil {
			t.Fatalf("listener did not respond to a valid query after a malformed packet: %v", err)
		}
	})
}
