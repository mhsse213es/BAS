package smtpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"net/smtp"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
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

func TestNewListener_BindsEphemeralPortAndReportsRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
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

// sendMail issues a real SMTP transaction against addr using the stdlib
// client (net/smtp is client-only, sufficient for these tests -- no
// AUTH, matching the listener's own unauthenticated posture).
func sendMail(t *testing.T, addr, subject string, body []byte) error {
	t.Helper()
	msg := []byte("From: dlptest@sink.audspect.local\r\n" +
		"To: dlptest@sink.audspect.local\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		string(body))
	return smtp.SendMail(addr, nil, "dlptest@sink.audspect.local",
		[]string{"dlptest@sink.audspect.local"}, msg)
}

func TestListener_MatchedSubjectRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
			token, "run-smtp-listener-1", "T1048.003", time.Now().Add(10*time.Minute),
		); err != nil {
			t.Fatalf("seed dlp_sink_tokens: %v", err)
		}

		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		body := []byte(token + "\r\n[BAS-SIM-DLP] listener integration test payload\r\n")
		if err := sendMail(t, l.LocalAddr().String(), token, body); err != nil {
			t.Fatalf("sendMail: %v", err)
		}

		var payloadHash string
		var payloadSize int
		var channel string
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := pool.QueryRow(context.Background(),
				`SELECT payload_hash, payload_size, channel FROM dlp_sink_receipts WHERE token = $1`,
				token,
			).Scan(&payloadHash, &payloadSize, &channel)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no dlp_sink_receipts row for token within 5s: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		wantSum := sha256.Sum256(body)
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash mismatch")
		}
		if payloadSize != len(body) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(body))
		}
		if channel != "smtp" {
			t.Errorf("channel = %q, want smtp", channel)
		}
	})
}

func TestListener_UnmatchedSubjectStillAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		// A never-issued token as the Subject -- the transaction must
		// still complete cleanly (250 OK, no SendMail error) and must
		// simply never write a receipt row.
		err = sendMail(t, l.LocalAddr().String(), "never-issued-token-value", []byte("unrelated body"))
		if err != nil {
			t.Fatalf("sendMail with an unmatched Subject should still succeed: %v", err)
		}
	})
}

func TestListener_OversizedMessageRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		tooBig := make([]byte, MaxMessageBytes+1024)
		for i := range tooBig {
			tooBig[i] = 'x'
		}
		if err := sendMail(t, l.LocalAddr().String(), "oversized-test", tooBig); err == nil {
			t.Error("a message exceeding MaxMessageBytes should be rejected by the server")
		}
	})
}

func TestListener_SecondRecipientRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		msg := []byte("From: dlptest@sink.audspect.local\r\nTo: a@b.com\r\nSubject: x\r\n\r\nbody\r\n")
		err = smtp.SendMail(l.LocalAddr().String(), nil, "dlptest@sink.audspect.local",
			[]string{"dlptest@sink.audspect.local", "second@sink.audspect.local"}, msg)
		if err == nil {
			t.Error("a message with more than one RCPT TO recipient should be rejected")
		}
	})
}
