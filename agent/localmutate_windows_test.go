//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// TestMain overrides resolvePipeSDDL for the whole package's test run:
// activeUserToken()'s WTSQueryUserToken call requires SeTcbPrivilege,
// which only a SYSTEM process holds (per privileges.go) -- a test run as
// an elevated admin can never satisfy it. Resolving this test process's
// OWN token's SID needs no special privilege and still exercises a real
// Windows ACL (just scoped to this process's SID instead of the WTS-
// resolved interactive user's, which are the same SID when run
// interactively anyway).
func TestMain(m *testing.M) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err == nil {
		resolvePipeSDDL = func() (string, error) {
			return fmt.Sprintf("D:(A;;GA;;;%s)", tu.User.Sid.String()), nil
		}
	}
	os.Exit(m.Run())
}

// testMutatePipePath gives each test its own pipe name so one test's
// never-closed listener (startMutatePipeListener has no Close path, by
// design -- it runs for the agent's whole lifetime) can't intercept a
// later test's dial to the shared mutatePipeName.
func testMutatePipePath(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\BASAgentMutateTest-%s-%d`, t.Name(), os.Getpid())
}

func dialMutatePipe(t *testing.T, path string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		t.Fatalf("DialPipeContext: %v", err)
	}
	return conn
}

func TestStartLocalMutateAPI_RejectsWrongPID(t *testing.T) {
	path := testMutatePipePath(t)
	notThisProcess := int32(os.Getpid()) + 1
	if err := startMutatePipeListener(path, func() int32 { return notThisProcess }, func(op, host string) (string, string) {
		t.Error("handler must not be called for a rejected connection")
		return "", ""
	}); err != nil {
		t.Fatalf("startMutatePipeListener: %v", err)
	}

	conn := dialMutatePipe(t, path)
	defer conn.Close()

	_, _ = conn.Write([]byte(`{"op":"test-server","host":"https://x:1"}`))
	var resp mutateResponse
	if err := json.NewDecoder(conn).Decode(&resp); err == nil {
		t.Fatal("expected the connection to be closed with no response for a wrong-PID client")
	}
}

func TestStartLocalMutateAPI_AcceptsMatchingPID(t *testing.T) {
	path := testMutatePipePath(t)
	if err := startMutatePipeListener(path, func() int32 { return int32(os.Getpid()) }, func(op, host string) (string, string) {
		return "echo:" + op, "echo:" + host
	}); err != nil {
		t.Fatalf("startMutatePipeListener: %v", err)
	}

	conn := dialMutatePipe(t, path)
	defer conn.Close()

	if _, err := conn.Write([]byte(`{"op":"test-server","host":"https://x:1"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var resp mutateResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Outcome != "echo:test-server" || resp.Detail != "echo:https://x:1" {
		t.Fatalf("got %+v, want handler's echoed values", resp)
	}
}

func TestStartLocalMutateAPI_RejectsMatchingPIDWrongImagePath(t *testing.T) {
	origLookup := imagePathForPID
	imagePathForPID = func(pid uint32) (string, error) {
		return `C:\not\the\right\path.exe`, nil
	}
	defer func() { imagePathForPID = origLookup }()

	path := testMutatePipePath(t)
	if err := startMutatePipeListener(path, func() int32 { return int32(os.Getpid()) }, func(op, host string) (string, string) {
		t.Error("handler must not be called when the image path check fails")
		return "", ""
	}); err != nil {
		t.Fatalf("startMutatePipeListener: %v", err)
	}

	conn := dialMutatePipe(t, path)
	defer conn.Close()

	_, _ = conn.Write([]byte(`{"op":"test-server","host":"https://x:1"}`))
	var resp mutateResponse
	if err := json.NewDecoder(conn).Decode(&resp); err == nil {
		t.Fatal("expected the connection to be closed with no response for a wrong-image-path client")
	}
}
