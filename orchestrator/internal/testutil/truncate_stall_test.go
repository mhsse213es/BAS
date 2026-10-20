package testutil

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// stallServer accepts PostgreSQL connections, completes the startup handshake, and then
// reads and discards every later message without replying. It models a socket that stays
// open while the server never answers a query.
func stallServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var n [4]byte
				if _, err := io.ReadFull(c, n[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint32(n[:])-4)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				auth := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
				ready := []byte{'Z', 0, 0, 0, 5, 'I'}
				_, _ = c.Write(append(auth, ready...))
				_, _ = io.Copy(io.Discard, c) // never reply to any query
			}(c)
		}
	}()
	return ln.Addr().String()
}

// A TRUNCATE whose server never answers must return within the guard's bound, and the
// error must say it timed out rather than hang.
func TestTruncateGuard_StalledSocketReturnsWithinBound(t *testing.T) {
	addr := stallServer(t)
	cfg, err := pgxpool.ParseConfig("postgres://u:p@" + addr + "/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), truncateWaitLimit)
		defer cancel()
		_, err := pool.Exec(ctx, `TRUNCATE TABLE "probe" CASCADE`)
		done <- err
	}()
	select {
	case err := <-done:
		elapsed := time.Since(start)
		t.Logf("Exec returned after %s with: %v", elapsed, err)
		if err == nil {
			t.Fatal("stalled TRUNCATE reported success")
		}
		if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("error does not identify a timeout: %v", err)
		}
	case <-time.After(3 * truncateWaitLimit):
		t.Fatalf("stalled Exec did not return within %s: the context deadline did not interrupt the socket read", 3*truncateWaitLimit)
	}
}
