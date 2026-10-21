package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/audspect/bas/internal/apibas/detect"
	"github.com/audspect/bas/internal/apibas/reporting"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ErrUnreachable marks a transport-level failure: connection refused, DNS
// failure, timeout. The runner grades it as ERROR, never as a block.
var ErrUnreachable = errors.New("runner: target unreachable")

// LabAdmin is the ground-truth state adapter for the Audspect lab. It also
// performs run-tagged cleanup. The admin token is held in memory only.
type LabAdmin struct {
	BaseURL    string
	AdminToken string
	HTTP       *http.Client
}

// NewLabAdmin returns an adapter with a bounded HTTP timeout.
func NewLabAdmin(baseURL, adminToken string) LabAdmin {
	return LabAdmin{
		BaseURL:    baseURL,
		AdminToken: adminToken,
		HTTP:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Snapshot returns the current state of every object, keyed by ID.
// It implements StateReader.
// ActiveFaults returns the faults the lab was started with (see lab -fault).
func (a LabAdmin) ActiveFaults(ctx context.Context) ([]string, error) {
	var faults []string
	if err := a.do(ctx, http.MethodGet, "/lab/faults", &faults); err != nil {
		return nil, err
	}
	return faults, nil
}

func (a LabAdmin) Snapshot(ctx context.Context) (map[string]StateRecord, error) {
	var rows []struct {
		ID       string `json:"id"`
		OwnerID  string `json:"owner_id"`
		Quantity string `json:"quantity"`
		Status   string `json:"status"`
		Tag      string `json:"tag"`
		// BeneficiaryRef is the payout beneficiary reference the order carries.
		BeneficiaryRef string `json:"beneficiary_ref"`
	}
	if err := a.do(ctx, http.MethodGet, "/lab/state", &rows); err != nil {
		return nil, err
	}
	out := make(map[string]StateRecord, len(rows))
	for _, r := range rows {
		out[r.ID] = StateRecord{ID: r.ID, OwnerID: r.OwnerID, Status: r.Status, Tag: r.Tag, Quantity: r.Quantity, BeneficiaryRef: r.BeneficiaryRef}
	}
	return out, nil
}

// Cleanup removes only records tagged with runTag and returns how many were
// removed. The lab never removes seed data or audit entries.
func (a LabAdmin) Cleanup(ctx context.Context, runTag string) (int, error) {
	if runTag == "" {
		return 0, errors.New("runner: cleanup requires a run tag")
	}
	var res struct {
		Removed int `json:"removed"`
	}
	if err := a.do(ctx, http.MethodDelete, "/lab/runs/"+url.PathEscape(runTag), &res); err != nil {
		return 0, err
	}
	return res.Removed, nil
}

// SetReportingFaults sets the reporting receiver's faults for the next run. The lab reset clears them.
func (a LabAdmin) SetReportingFaults(ctx context.Context, faults map[string]any) error {
	return a.send(ctx, http.MethodPost, "/lab/reporting/faults", faults, nil)
}

// ReportingEvidence returns the reporting adapter's record of every incident and dispatch in the run.
func (a LabAdmin) ReportingEvidence(ctx context.Context) (reporting.Evidence, error) {
	var ev reporting.Evidence
	err := a.do(ctx, http.MethodGet, "/lab/reporting", &ev)
	return ev, err
}

// Reset restores the lab to its fixture seed. The audit log is kept. It
// implements Resetter.
func (a LabAdmin) Reset(ctx context.Context) error {
	return a.send(ctx, http.MethodPost, "/lab/reset", nil, nil)
}

// CreateTagged seeds one run-tagged record. Used by tests to prove cleanup
// touches only tagged records.
func (a LabAdmin) CreateTagged(ctx context.Context, id, ownerID, status, runTag string) error {
	body := map[string]string{"id": id, "owner_id": ownerID, "status": status, "tag": runTag}
	return a.send(ctx, http.MethodPost, "/lab/orders", body, nil)
}

// Audit returns the lab's append-only audit log.
func (a LabAdmin) Audit(ctx context.Context) ([]map[string]any, error) {
	var entries []map[string]any
	if err := a.do(ctx, http.MethodGet, "/lab/audit", &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (a LabAdmin) do(ctx context.Context, method, path string, out any) error {
	return a.send(ctx, method, path, nil, out)
}

func (a LabAdmin) send(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-Lab-Admin", a.AdminToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("runner: lab admin %s %s returned HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// TokenStatus reports whether the lab knows a token and whether it is revoked.
// It implements RevocationChecker. The token is sent only to the lab admin API.
func (a LabAdmin) TokenStatus(ctx context.Context, token string) (bool, bool, error) {
	var res struct {
		Known   bool `json:"known"`
		Revoked bool `json:"revoked"`
	}
	if err := a.send(ctx, http.MethodPost, "/lab/token-status", map[string]string{"token": token}, &res); err != nil {
		return false, false, err
	}
	return res.Known, res.Revoked, nil
}

// AccessEvents returns the lab's access events for one run tag. The lab filters by
// tag, so one run never reads another run's events.
func (a LabAdmin) AccessEvents(ctx context.Context, correlationID string) ([]detect.Event, error) {
	var events []detect.Event
	if err := a.do(ctx, http.MethodGet, "/lab/access-events?correlation_id="+url.QueryEscape(correlationID), &events); err != nil {
		return nil, err
	}
	return events, nil
}
