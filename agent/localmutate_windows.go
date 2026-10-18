//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// mutatePipeName is the named pipe the Settings window uses for the two
// config-mutation calls (test-server, set-server). The existing loopback
// HTTP API's static bearer token stays sufficient only for the read-only
// endpoints; this pipe is the security boundary for everything that
// mutates agent configuration -- see "Security boundary" in
// docs/superpowers/specs/2026-10-18-agent-tray-settings-troubleshoot-design.md.
const mutatePipeName = `\\.\pipe\BASAgentMutate`

// trayPID holds the PID of the most recently spawned tray process
// (set by launchTrayForActiveSession), the sole process the mutate pipe
// accepts connections from.
var trayPID atomic.Int32

// imagePathForPID resolves a process's own image path. A package-level var
// (not a plain function) so tests can override it without a real second
// process standing in for "the wrong process."
var imagePathForPID = func(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// fdHandle is satisfied by go-winio's pipe connection types: win32Pipe
// embeds *win32File, which exports Fd() uintptr, even though win32Pipe
// itself is unexported -- Go interface satisfaction only needs the
// method, never the concrete type's name.
type fdHandle interface {
	Fd() uintptr
}

// clientPIDOf resolves the PID of the process on the other end of conn.
func clientPIDOf(conn net.Conn) (uint32, error) {
	fc, ok := conn.(fdHandle)
	if !ok {
		return 0, fmt.Errorf("connection does not expose a file handle")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(fc.Fd()), &pid); err != nil {
		return 0, err
	}
	return pid, nil
}

// parentPIDOf walks a Toolhelp32 process snapshot to find pid's parent.
// There is no direct Win32 "get parent of this PID" call; enumerating the
// snapshot is the standard technique.
func parentPIDOf(pid uint32) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return 0, err
	}
	for {
		if entry.ProcessID == pid {
			return entry.ParentProcessID, nil
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			return 0, fmt.Errorf("process %d not found in snapshot", pid)
		}
	}
}

// mutateRequest/mutateResponse are the pipe's wire protocol: one JSON
// request per connection, one JSON response, then the connection closes
// (matching the Settings window's Test/Save being discrete button clicks,
// not a persistent session).
type mutateRequest struct {
	Op   string `json:"op"`
	Host string `json:"host"`
}

type mutateResponse struct {
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	// ServerTime is set only for a successful test-server call, carrying
	// the server's own clock from that call's authenticated response --
	// lets Troubleshoot's clock-skew check reuse this exact round trip
	// instead of a second, separately-authenticated request.
	ServerTime time.Time `json:"serverTime,omitempty"`
}

// startLocalMutateAPI creates the SID-scoped named pipe and serves it for
// the lifetime of the agent process. handler is called with (op, host)
// for every request from a connection that passes BOTH the PID check
// (against expectedClientPID(), i.e. trayPID) and the image-path check
// (the connecting process's own exe must match this agent's own exe path
// -- the tray is always "<this exe> --tray"); a connection failing either
// check is closed with no response, never reaching handler.
func startLocalMutateAPI(a *Agent, expectedClientPID func() int32, handler func(op, host string) (outcome, detail string, serverTime time.Time)) error {
	return startMutatePipeListener(mutatePipeName, expectedClientPID, handler)
}

// startMutatePipeListener is startLocalMutateAPI's real implementation,
// taking the pipe path as a parameter so tests can use an isolated path
// per test instead of the shared mutatePipeName -- this listener never
// closes (it runs for the agent's whole lifetime), so a shared path across
// tests in the same process would let an earlier test's listener
// intercept a later test's dial.
func startMutatePipeListener(pipePath string, expectedClientPID func() int32, handler func(op, host string) (outcome, detail string, serverTime time.Time)) error {
	sddl, err := resolvePipeSDDL()
	if err != nil {
		return fmt.Errorf("resolve user SID for mutate pipe ACL: %w", err)
	}

	l, err := winio.ListenPipe(pipePath, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		return fmt.Errorf("listen on mutate pipe: %w", err)
	}

	expectedImagePath, err := os.Executable()
	if err != nil {
		l.Close()
		return fmt.Errorf("resolve own executable path: %w", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveMutateConn(conn, expectedClientPID(), expectedImagePath, handler)
		}
	}()
	return nil
}

// serveMutateConn's identity check is against the connecting process's
// PARENT, not the connecting process itself: Settings and Troubleshoot
// are spawned by the tray as their own child processes ("<exe>
// --settings-window" / "--troubleshoot-window", tray_windows.go), so the
// process that actually dials this pipe is never the tray process whose
// PID expectedClientPID() returns -- it's a direct child of it. The
// image-path check still applies to the connecting process itself (both
// the tray and its spawned windows are the same bas_agent.exe binary).
func serveMutateConn(conn net.Conn, wantParentPID int32, wantImagePath string, handler func(op, host string) (outcome, detail string, serverTime time.Time)) {
	defer conn.Close()

	if wantParentPID <= 0 {
		return
	}
	pid, err := clientPIDOf(conn)
	if err != nil {
		return
	}
	parentPID, err := parentPIDOf(pid)
	if err != nil || parentPID != uint32(wantParentPID) {
		return
	}
	imgPath, err := imagePathForPID(pid)
	if err != nil || imgPath != wantImagePath {
		return
	}

	var req mutateRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	outcome, detail, serverTime := handler(req.Op, req.Host)
	_ = json.NewEncoder(conn).Encode(mutateResponse{Outcome: outcome, Detail: detail, ServerTime: serverTime})
}

// resolvePipeSDDL is the real production SID source for the mutate pipe's
// ACL -- a package-level var (like imagePathForPID) so tests can override
// it: activeUserToken() calls WTSQueryUserToken, which requires
// SeTcbPrivilege (SYSTEM only, per privileges.go's own comment), so no
// admin-but-not-SYSTEM test process can ever resolve it. Tests substitute
// a real SID a test process CAN resolve without special privilege (its
// own current-process token) rather than skipping ACL enforcement
// entirely.
var resolvePipeSDDL = currentUserPipeSDDL

// currentUserPipeSDDL builds a security descriptor restricted to the
// exact logged-in interactive user's SID: D:(A;;GA;;;<SID>) grants that
// SID generic-all access and nothing to anyone else, so no other
// same-machine account (even another interactive user) can open this pipe.
func currentUserPipeSDDL() (string, error) {
	tok, ok := activeUserToken()
	if !ok {
		return "", fmt.Errorf("no active interactive user session")
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("get token user: %w", err)
	}
	return fmt.Sprintf("D:(A;;GA;;;%s)", tu.User.Sid.String()), nil
}
