package phishbridge

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

func collabTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func TestPHCHN002_EndToEnd_KnownGood_SharingInviteCreatedAndVerified(t *testing.T) {
	tokenSrv := collabTokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "perm-1"}}})
			return
		}
		w.WriteHeader(http.StatusOK) // the independent verify read-back
	}))
	defer graphSrv.Close()

	client := phishidentity.New(phishidentity.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	invite, dispatchErr := client.CreateSharingInvite(t.Context(), "drive-1", "item-1", []string{"victim@example-lab.test"}, "shared doc")
	verified := client.VerifySharingInviteExists(t.Context(), "drive-1", "item-1", invite.PermissionID)

	obs := FromCreatedLure("sharing-invite", dispatchErr, verified, time.Now())
	outcome := phishval.Evaluate("run-ph-chn-002", "known-good", catalogExpectation(t, "PH-CHN-002"), obs)
	if outcome.Delivery.Verdict != phishval.VerdictPass {
		t.Errorf("Delivery.Verdict = %q (%s), want %q", outcome.Delivery.Verdict, outcome.Delivery.Reason, phishval.VerdictPass)
	}
}

func TestPHCHN002_EndToEnd_KnownBad_CreationRejected(t *testing.T) {
	obs := FromCreatedLure("sharing-invite", errors.New("graph: invite rejected"), phishidentity.CreatedUnknown, time.Now())
	outcome := phishval.Evaluate("run-ph-chn-002", "known-bad", catalogExpectation(t, "PH-CHN-002"), obs)
	if outcome.Delivery.Verdict != phishval.VerdictFail {
		t.Errorf("Delivery.Verdict = %q, want %q", outcome.Delivery.Verdict, phishval.VerdictFail)
	}
}

func TestPHCHN002_CreationSucceededButReadBackMissing_NeverFabricatesDelivered(t *testing.T) {
	obs := FromCreatedLure("sharing-invite", nil, phishidentity.CreatedMissing, time.Now())
	outcome := phishval.Evaluate("run-ph-chn-002", "missing", catalogExpectation(t, "PH-CHN-002"), obs)
	if outcome.Delivery.Verdict != phishval.VerdictFail {
		t.Errorf("Delivery.Verdict = %q, want %q (a confirmed-missing read-back must never be read as delivered)", outcome.Delivery.Verdict, phishval.VerdictFail)
	}
}

func TestPHCHN004_EndToEnd_KnownGood_CalendarLureCreatedAndVerified(t *testing.T) {
	tokenSrv := collabTokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]any{"id": "event-1"})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer graphSrv.Close()

	client := phishidentity.New(phishidentity.Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	lure, dispatchErr := client.CreateCalendarEventLure(t.Context(), "user-1", "Urgent: plan review", "please review", []string{"victim@example-lab.test"})
	verified := client.VerifyCalendarEventExists(t.Context(), "user-1", lure.EventID)

	obs := FromCreatedLure("calendar-event", dispatchErr, verified, time.Now())
	outcome := phishval.Evaluate("run-ph-chn-004", "known-good", catalogExpectation(t, "PH-CHN-004"), obs)
	if outcome.Delivery.Verdict != phishval.VerdictPass {
		t.Errorf("Delivery.Verdict = %q (%s), want %q", outcome.Delivery.Verdict, outcome.Delivery.Reason, phishval.VerdictPass)
	}
}

func TestPHCHN004_InconclusiveReadBack_NeverFabricatesDeliveredOrRejected(t *testing.T) {
	obs := FromCreatedLure("calendar-event", nil, phishidentity.CreatedUnknown, time.Now())
	outcome := phishval.Evaluate("run-ph-chn-004", "unknown", catalogExpectation(t, "PH-CHN-004"), obs)
	if outcome.Delivery.Verdict != phishval.VerdictNotTested {
		t.Errorf("Delivery.Verdict = %q, want %q (an inconclusive read-back must never be read as success or failure)", outcome.Delivery.Verdict, phishval.VerdictNotTested)
	}
}
