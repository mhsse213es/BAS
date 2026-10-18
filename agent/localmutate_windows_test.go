//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// helperProcessEnv/helperPipeEnv drive the re-exec'd helper-process path
// below: the standard Go testing pattern (see os/exec's own tests) for a
// test that needs a REAL separate process, not just a closure, as one
// side of a system call -- here, a real child of the test process, since
// the mutate pipe's identity check is against the connecting process's
// PARENT (see localmutate_windows.go's serveMutateConn doc comment).
const (
	helperProcessEnv = "BAS_TEST_HELPER_DIAL_PIPE"
	helperPipeEnv    = "BAS_TEST_HELPER_PIPE_PATH"
)

// TestMain overrides resolvePipeSDDL for the whole package's test run:
// activeUserToken()'s WTSQueryUserToken call requires SeTcbPrivilege,
// which only a SYSTEM process holds (per privileges.go) -- a test run as
// an elevated admin can never satisfy it. Resolving this test process's
// OWN token's SID needs no special privilege and still exercises a real
// Windows ACL (just scoped to this process's SID instead of the WTS-
// resolved interactive user's, which are the same SID when run
// interactively anyway).
//
// It also intercepts the helper-process re-exec path before running any
// real test: when BAS_TEST_HELPER_DIAL_PIPE is set, this process IS the
// helper (spawned by dialPipeAsChild below), not the test binary proper.
func TestMain(m *testing.M) {
	if os.Getenv(helperProcessEnv) != "" {
		runHelperDialPipe()
		return
	}

	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err == nil {
		resolvePipeSDDL = func() (string, error) {
			return fmt.Sprintf("D:(A;;GA;;;%s)", tu.User.Sid.String()), nil
		}
	}
	os.Exit(m.Run())
}

// runHelperDialPipe is the re-exec'd helper's entire body: dial the pipe
// named by BAS_TEST_HELPER_PIPE_PATH, send a fixed test-server request,
// print the response (or an error marker) to stdout, and exit. The parent
// test reads this process's stdout to learn what the server actually did
// -- this process's own exit code/stdout IS the test assertion's data,
// since the parent has no other way to observe a connection it isn't
// part of.
func runHelperDialPipe() {
	path := os.Getenv(helperPipeEnv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, path)
	if err != nil {
		fmt.Println("DIAL_ERROR:", err)
		os.Exit(1)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(mutateRequest{Op: "test-server", Host: "https://x:1"}); err != nil {
		fmt.Println("WRITE_ERROR:", err)
		os.Exit(1)
	}
	var resp mutateResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		fmt.Println("READ_ERROR:", err)
		os.Exit(1)
	}
	fmt.Println("OK:", resp.Outcome, resp.Detail)
	os.Exit(0)
}

// dialPipeAsChild re-execs this test binary as the helper process above,
// so the dial happens from a REAL child of the current (test) process --
// exactly the topology serveMutateConn's parent-PID check expects (the
// tray spawning Settings/Troubleshoot as its own child processes).
// Returns the helper's stdout and its exit error (nil on exit 0) -- a
// non-nil error is not itself a test failure: a rejected connection makes
// the helper exit 1 by design, and that is the expected outcome for some
// callers (see TestStartLocalMutateAPI_RejectsMatchingPIDWrongImagePath).
func dialPipeAsChild(t *testing.T, path string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperProcessEnv+"=1", helperPipeEnv+"="+path)
	out, err := cmd.Output()
	return string(out), err
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

// TestStartLocalMutateAPI_RejectsWrongPID dials directly from the test
// process itself (not via a child) against an expected-parent value that
// cannot possibly be this test's own real parent -- proving a connection
// whose parent doesn't match is rejected, independent of the specific
// (wrong) value chosen.
func TestStartLocalMutateAPI_RejectsWrongPID(t *testing.T) {
	path := testMutatePipePath(t)
	impossibleParent := int32(1) // PID 1 is never a real parent on Windows
	if err := startMutatePipeListener(path, func() int32 { return impossibleParent }, func(op, host string) (string, string, time.Time) {
		t.Error("handler must not be called for a rejected connection")
		return "", "", time.Time{}
	}); err != nil {
		t.Fatalf("startMutatePipeListener: %v", err)
	}

	conn := dialMutatePipe(t, path)
	defer conn.Close()

	_, _ = conn.Write([]byte(`{"op":"test-server","host":"https://x:1"}`))
	var resp mutateResponse
	if err := json.NewDecoder(conn).Decode(&resp); err == nil {
		t.Fatal("expected the connection to be closed with no response for a wrong-parent client")
	}
}

func TestStartLocalMutateAPI_AcceptsMatchingPID(t *testing.T) {
	path := testMutatePipePath(t)
	if err := startMutatePipeListener(path, func() int32 { return int32(os.Getpid()) }, func(op, host string) (string, string, time.Time) {
		return "echo:" + op, "echo:" + host, time.Time{}
	}); err != nil {
		t.Fatalf("startMutatePipeListener: %v", err)
	}

	out, err := dialPipeAsChild(t, path)
	if err != nil {
		t.Fatalf("helper process failed: %v, output=%q", err, out)
	}
	want := "OK: echo:test-server echo:https://x:1\n"
	if out != want {
		t.Fatalf("helper output = %q, want %q", out, want)
	}
}

func TestStartLocalMutateAPI_RejectsMatchingPIDWrongImagePath(t *testing.T) {
	origLookup := imagePathForPID
	imagePathForPID = func(pid uint32) (string, error) {
		return `C:\not\the\right\path.exe`, nil
	}
	defer func() { imagePathForPID = origLookup }()

	path := testMutatePipePath(t)
	if err := startMutatePipeListener(path, func() int32 { return int32(os.Getpid()) }, func(op, host string) (string, string, time.Time) {
		t.Error("handler must not be called when the image path check fails")
		return "", "", time.Time{}
	}); err != nil {
		t.Fatalf("startMutatePipeListener: %v", err)
	}

	out, err := dialPipeAsChild(t, path)
	if err == nil {
		t.Fatalf("expected the helper to fail to read a response for a wrong-image-path client, got %q", out)
	}
}
