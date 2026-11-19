package rwcontain

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/rwdetect"
	"github.com/audspect/bas/internal/rwevidence"
)

type fakeDevices struct {
	status     string
	statusErr  error
	resolveErr error
	resolves   int
	statusReqs int
}

func (f *fakeDevices) ResolveDevice(_ context.Context, _ string) (string, error) {
	f.resolves++
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	return "device-1", nil
}

func (f *fakeDevices) DeviceContainmentStatus(_ context.Context, _ string) (string, error) {
	f.statusReqs++
	return f.status, f.statusErr
}

type fixedContext struct {
	host string
	err  error
}

func (f fixedContext) AttemptContextFor(context.Context, rwevidence.AttemptKey) (rwdetect.AttemptContext, error) {
	return rwdetect.AttemptContext{HostName: f.host}, f.err
}

var key = rwevidence.AttemptKey{RunID: "run-1", TechniqueID: "T1486", Action: "t1486:enc"}

func observe(t *testing.T, devices *fakeDevices, ctx rwdetect.ContextSource) rwevidence.ContainmentResult {
	t.Helper()
	res, err := Observer{Devices: devices, Context: ctx}.ObserveContainment(context.Background(), key)
	if err != nil {
		t.Fatalf("ObserveContainment: %v", err)
	}
	return res
}

func TestContainedStatusConfirmsContainment(t *testing.T) {
	d := &fakeDevices{status: "contained"}
	if got := observe(t, d, fixedContext{host: "WS-1"}); got != rwevidence.ContainmentConfirmed {
		t.Fatalf("got %q, want confirmed", got)
	}
}

func TestNormalStatusIsVerifiedNotContained(t *testing.T) {
	d := &fakeDevices{status: "normal"}
	if got := observe(t, d, fixedContext{host: "WS-1"}); got != rwevidence.ContainmentFailed {
		t.Fatalf("got %q, want failed", got)
	}
}

func TestPendingOrUnknownStatusIsIndeterminate(t *testing.T) {
	for _, status := range []string{"containment_pending", "lift_containment_pending", "something_new", ""} {
		d := &fakeDevices{status: status}
		if got := observe(t, d, fixedContext{host: "WS-1"}); got != rwevidence.ContainmentIndeterminate {
			t.Fatalf("status %q: got %q, want indeterminate", status, got)
		}
	}
}

func TestDeviceNotFoundIsIndeterminateNotAnError(t *testing.T) {
	d := &fakeDevices{resolveErr: ErrDeviceNotFound}
	if got := observe(t, d, fixedContext{host: "WS-1"}); got != rwevidence.ContainmentIndeterminate {
		t.Fatalf("got %q, want indeterminate", got)
	}
	if d.statusReqs != 0 {
		t.Fatal("no status read when the device cannot be resolved")
	}
}

func TestMissingHostIsIndeterminateAndNeverQueriesVendor(t *testing.T) {
	d := &fakeDevices{status: "contained"}
	if got := observe(t, d, fixedContext{host: ""}); got != rwevidence.ContainmentIndeterminate {
		t.Fatalf("got %q, want indeterminate", got)
	}
	if d.resolves != 0 || d.statusReqs != 0 {
		t.Fatal("no vendor query without a host")
	}
}

func TestVendorTransportErrorIsReturned(t *testing.T) {
	boom := errors.New("vendor unreachable")
	d := &fakeDevices{statusErr: boom}
	_, err := Observer{Devices: d, Context: fixedContext{host: "WS-1"}}.ObserveContainment(context.Background(), key)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the vendor error", err)
	}
}

func TestContextErrorIsReturned(t *testing.T) {
	boom := errors.New("registry unavailable")
	d := &fakeDevices{status: "contained"}
	_, err := Observer{Devices: d, Context: fixedContext{err: boom}}.ObserveContainment(context.Background(), key)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the context error", err)
	}
}
