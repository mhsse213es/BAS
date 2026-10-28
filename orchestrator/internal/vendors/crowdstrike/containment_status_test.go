package crowdstrike

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeviceContainmentStatus_ReadsVendorStatus(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	detailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("ids"); got != "device-123" {
			t.Errorf("ids = %q, want device-123", got)
		}
		json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{"device_id": "device-123", "status": "contained"}}})
	}))
	defer detailSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", "")
	c.DeviceDetailsURL = detailSrv.URL
	status, err := c.DeviceContainmentStatus(context.Background(), "device-123")
	if err != nil {
		t.Fatalf("DeviceContainmentStatus: %v", err)
	}
	if status != "contained" {
		t.Fatalf("status = %q, want contained", status)
	}
}

func TestDeviceContainmentStatus_UnknownDeviceIsErrDeviceNotFound(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	detailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []any{}})
	}))
	defer detailSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", "")
	c.DeviceDetailsURL = detailSrv.URL
	_, err := c.DeviceContainmentStatus(context.Background(), "gone")
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("err = %v, want ErrDeviceNotFound", err)
	}
}

func TestResolveDevice_NoMatchIsErrDeviceNotFound(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	deviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer deviceSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, deviceSrv.URL, "")
	if _, err := c.ResolveDevice(context.Background(), "NOHOST"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("err = %v, want ErrDeviceNotFound", err)
	}
}
