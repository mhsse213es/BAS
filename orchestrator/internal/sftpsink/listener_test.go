package sftpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

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

// sftpClient dials l, completes the SSH handshake with NoClientAuth (no
// credential presented -- the whole point of the server's own
// NoClientAuth: true config), and returns an *sftp.Client ready to use.
func sftpClient(t *testing.T, addr string) *sftp.Client {
	t.Helper()
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "dlptest",
		Auth:            nil,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	return client
}

func TestListener_UploadRecordsReceipt(t *testing.T) {
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

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		// Genuinely 64 lowercase hex chars -- matching filenamePattern's
		// exact requirement (generateSinkToken(32)'s real output shape).
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		payload := []byte("[BAS-SIM-DLP] listener integration test payload")
		f, err := client.Create(token + ".dat")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := f.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		var payloadHash string
		var payloadSize int
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := pool.QueryRow(context.Background(),
				`SELECT payload_hash, payload_size FROM dlp_sink_receipts WHERE token = $1`,
				token,
			).Scan(&payloadHash, &payloadSize)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no dlp_sink_receipts row for token within 5s: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		wantSum := sha256.Sum256(payload)
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash mismatch")
		}
		if payloadSize != len(payload) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(payload))
		}
	})
}

func TestListener_RejectsUnexpectedFilename(t *testing.T) {
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

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		if _, err := client.Create("not-a-valid-token-name.txt"); err == nil {
			t.Error("Create with a non-<token>.dat filename should be rejected by the server")
		}
	})
}

func TestListener_ListAndReadRejected(t *testing.T) {
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

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		if _, err := client.ReadDir("/"); err == nil {
			t.Error("directory listing should be rejected -- this listener has no legitimate use for it")
		}
	})
}

func TestListener_OversizedUploadRejected(t *testing.T) {
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

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		token := "0f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a6978"
		f, err := client.Create(token + ".dat")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		defer f.Close()
		tooBig := make([]byte, MaxUploadBytes+1024)
		if _, err := f.Write(tooBig); err == nil {
			t.Error("a write exceeding MaxUploadBytes should surface an error to the SFTP client")
		}
	})
}
