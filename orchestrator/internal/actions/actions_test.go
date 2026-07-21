package actions

import (
	"context"
	"errors"
	"testing"
)

// fakeVendorClient is a lightweight in-package double — Execute's own
// logic (validation, status transitions, parameter extraction) doesn't
// need a real HTTP round trip to test; vendor-specific behavior is already
// covered by internal/vendors/crowdstrike and internal/vendors/defender's
// own tests from Plans 1-3.
type fakeVendorClient struct {
	resolveDeviceFunc  func(ctx context.Context, hostname string) (string, error)
	isolateFunc        func(ctx context.Context, deviceID string) (string, error)
	releaseFunc        func(ctx context.Context, deviceID string) (string, error)
	killProcessFunc    func(ctx context.Context, deviceID string, pid int) (string, error)
	quarantineFileFunc func(ctx context.Context, deviceID, param string) (string, error)
}

func (f *fakeVendorClient) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	return f.resolveDeviceFunc(ctx, hostname)
}
func (f *fakeVendorClient) Isolate(ctx context.Context, deviceID string) (string, error) {
	return f.isolateFunc(ctx, deviceID)
}
func (f *fakeVendorClient) Release(ctx context.Context, deviceID string) (string, error) {
	return f.releaseFunc(ctx, deviceID)
}
func (f *fakeVendorClient) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return f.killProcessFunc(ctx, deviceID, pid)
}
func (f *fakeVendorClient) QuarantineFile(ctx context.Context, deviceID, param string) (string, error) {
	return f.quarantineFileFunc(ctx, deviceID, param)
}

func baseRequest() Request {
	return Request{
		Type:        TypeIsolate,
		Target:      Target{Type: "hostname", Identifier: "WIN-01"},
		ConnectorID: "conn-1",
		RequestedBy: "user-1",
		Reason:      "confirmed ransomware simulation success",
	}
}

func TestExecute_Isolate_Success(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) {
			if hostname != "WIN-01" {
				t.Errorf("hostname = %q, want WIN-01", hostname)
			}
			return "device-abc", nil
		},
		isolateFunc: func(ctx context.Context, deviceID string) (string, error) {
			if deviceID != "device-abc" {
				t.Errorf("deviceID = %q, want device-abc", deviceID)
			}
			return "trace-1", nil
		},
	}
	a := Execute(context.Background(), client, baseRequest())
	if a.Status != StatusCompleted {
		t.Fatalf("Status = %q, want %q (err=%q)", a.Status, StatusCompleted, a.Error)
	}
	if a.ResolvedDeviceID != "device-abc" {
		t.Fatalf("ResolvedDeviceID = %q, want device-abc", a.ResolvedDeviceID)
	}
	if a.VendorRequestID != "trace-1" {
		t.Fatalf("VendorRequestID = %q, want trace-1", a.VendorRequestID)
	}
	if a.DispatchedAt == nil || a.CompletedAt == nil {
		t.Fatal("expected DispatchedAt and CompletedAt to both be set on success")
	}
}

func TestExecute_Release_Success(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		releaseFunc:       func(ctx context.Context, deviceID string) (string, error) { return "trace-2", nil },
	}
	req := baseRequest()
	req.Type = TypeRelease
	a := Execute(context.Background(), client, req)
	if a.Status != StatusCompleted || a.VendorRequestID != "trace-2" {
		t.Fatalf("a = %+v, want Completed/trace-2", a)
	}
}

func TestExecute_KillProcess_ExtractsPIDFromParameters(t *testing.T) {
	var gotPID int
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		killProcessFunc: func(ctx context.Context, deviceID string, pid int) (string, error) {
			gotPID = pid
			return "trace-3", nil
		},
	}
	req := baseRequest()
	req.Type = TypeKillProcess
	req.Parameters = map[string]any{"pid": float64(4821)} // JSON numbers decode as float64
	a := Execute(context.Background(), client, req)
	if a.Status != StatusCompleted {
		t.Fatalf("Status = %q, want Completed (err=%q)", a.Status, a.Error)
	}
	if gotPID != 4821 {
		t.Fatalf("gotPID = %d, want 4821", gotPID)
	}
}

func TestExecute_KillProcess_MissingPID_Fails(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
	}
	req := baseRequest()
	req.Type = TypeKillProcess
	a := Execute(context.Background(), client, req)
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.Error == "" {
		t.Fatal("expected a non-empty Error explaining the missing pid parameter")
	}
}

func TestExecute_QuarantineFile_ExtractsQuarantineTarget(t *testing.T) {
	var gotParam string
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		quarantineFileFunc: func(ctx context.Context, deviceID, param string) (string, error) {
			gotParam = param
			return "trace-4", nil
		},
	}
	req := baseRequest()
	req.Type = TypeQuarantineFile
	req.Parameters = map[string]any{"quarantineTarget": `C:\evil.exe`}
	a := Execute(context.Background(), client, req)
	if a.Status != StatusCompleted {
		t.Fatalf("Status = %q, want Completed (err=%q)", a.Status, a.Error)
	}
	if gotParam != `C:\evil.exe` {
		t.Fatalf("gotParam = %q, want C:\\evil.exe", gotParam)
	}
}

func TestExecute_ResolveDeviceFails_StatusFailedWithVendorError(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) {
			return "", errors.New("crowdstrike: no device found for hostname \"WIN-01\"")
		},
	}
	a := Execute(context.Background(), client, baseRequest())
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.Error != `crowdstrike: no device found for hostname "WIN-01"` {
		t.Fatalf("Error = %q, want the vendor's exact message", a.Error)
	}
	if a.ResolvedDeviceID != "" {
		t.Fatalf("ResolvedDeviceID = %q, want empty on resolution failure", a.ResolvedDeviceID)
	}
}

func TestExecute_VendorActionFails_StatusFailed(t *testing.T) {
	client := &fakeVendorClient{
		resolveDeviceFunc: func(ctx context.Context, hostname string) (string, error) { return "device-abc", nil },
		isolateFunc: func(ctx context.Context, deviceID string) (string, error) {
			return "", errors.New("crowdstrike device action contain: HTTP 500")
		},
	}
	a := Execute(context.Background(), client, baseRequest())
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.ResolvedDeviceID != "device-abc" {
		t.Fatalf("ResolvedDeviceID = %q, want device-abc (resolution succeeded before the isolate call failed)", a.ResolvedDeviceID)
	}
}

func TestExecute_MissingReason_Fails(t *testing.T) {
	client := &fakeVendorClient{}
	req := baseRequest()
	req.Reason = ""
	a := Execute(context.Background(), client, req)
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
	if a.Error == "" {
		t.Fatal("expected a non-empty Error explaining the missing reason")
	}
}

func TestExecute_UnsupportedTargetType_Fails(t *testing.T) {
	client := &fakeVendorClient{}
	req := baseRequest()
	req.Target.Type = "aws-instance-id"
	a := Execute(context.Background(), client, req)
	if a.Status != StatusFailed {
		t.Fatalf("Status = %q, want Failed", a.Status)
	}
}

func TestNewVendorClient_UnsupportedProvider_ReturnsError(t *testing.T) {
	if _, err := NewVendorClient(ConnectorConfig{Provider: "sentinelone"}); err == nil {
		t.Fatal("expected an error for a provider not implemented in this feature")
	}
}

func TestNewVendorClient_KnownProviders_Succeed(t *testing.T) {
	if _, err := NewVendorClient(ConnectorConfig{Provider: "crowdstrike", BaseURL: "https://api.crowdstrike.com"}); err != nil {
		t.Errorf("crowdstrike: %v", err)
	}
	if _, err := NewVendorClient(ConnectorConfig{Provider: "microsoft_defender", TenantID: "t1"}); err != nil {
		t.Errorf("microsoft_defender: %v", err)
	}
}
