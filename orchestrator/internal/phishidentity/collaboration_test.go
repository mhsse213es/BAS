package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateSharingInvite_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotPath, gotAuthHeader string
	var gotBody map[string]any
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuthHeader = r.URL.Path, r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "perm-1"}}})
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	invite, err := client.CreateSharingInvite(t.Context(), "drive-1", "item-1", []string{"victim@example-lab.test"}, "shared doc")
	if err != nil {
		t.Fatalf("CreateSharingInvite() error = %v", err)
	}
	if invite.PermissionID != "perm-1" {
		t.Errorf("PermissionID = %q, want %q", invite.PermissionID, "perm-1")
	}
	if gotPath != "/drives/drive-1/items/item-1/invite" {
		t.Errorf("path = %q, want %q", gotPath, "/drives/drive-1/items/item-1/invite")
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer tok")
	}
	if gotBody["requireSignIn"] != true || gotBody["sendInvitation"] != true {
		t.Errorf("body = %+v, want requireSignIn=true and sendInvitation=true (never an anonymous link)", gotBody)
	}
}

func TestCreateSharingInvite_UnscopedDriveOrItem_Rejected(t *testing.T) {
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	if _, err := client.CreateSharingInvite(t.Context(), "", "item-1", []string{"a@b.test"}, ""); err == nil {
		t.Error("CreateSharingInvite() with an empty driveID = nil error, want an error (never a tenant-wide share)")
	}
}

func TestCreateSharingInvite_NoRecipients_Rejected(t *testing.T) {
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	if _, err := client.CreateSharingInvite(t.Context(), "drive-1", "item-1", nil, ""); err == nil {
		t.Error("CreateSharingInvite() with no recipients = nil error, want an error")
	}
}

func TestVerifySharingInviteExists_Confirmed(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer graphSrv.Close()
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if got := client.VerifySharingInviteExists(t.Context(), "drive-1", "item-1", "perm-1"); got != CreatedConfirmed {
		t.Errorf("VerifySharingInviteExists() = %q, want %q", got, CreatedConfirmed)
	}
}

func TestVerifySharingInviteExists_Missing(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer graphSrv.Close()
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if got := client.VerifySharingInviteExists(t.Context(), "drive-1", "item-1", "perm-1"); got != CreatedMissing {
		t.Errorf("VerifySharingInviteExists() = %q, want %q (a 404 is a real negative, not unknown)", got, CreatedMissing)
	}
}

func TestVerifySharingInviteExists_ServerError_Unknown(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer graphSrv.Close()
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if got := client.VerifySharingInviteExists(t.Context(), "drive-1", "item-1", "perm-1"); got != CreatedUnknown {
		t.Errorf("VerifySharingInviteExists() = %q, want %q (a 503 must never be read as confirmed or missing)", got, CreatedUnknown)
	}
}

func TestDeleteSharingInvite_HTTPTestServer_RealDelete(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	var gotMethod, gotPath string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer graphSrv.Close()
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if err := client.DeleteSharingInvite(t.Context(), "drive-1", "item-1", "perm-1"); err != nil {
		t.Fatalf("DeleteSharingInvite() error = %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/drives/drive-1/items/item-1/permissions/perm-1" {
		t.Errorf("got %s %s, want DELETE /drives/drive-1/items/item-1/permissions/perm-1", gotMethod, gotPath)
	}
}

func TestCreateCalendarEventLure_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	var gotPath string
	var gotBody map[string]any
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "event-1"})
	}))
	defer graphSrv.Close()
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	lure, err := client.CreateCalendarEventLure(t.Context(), "user-1", "Urgent: plan review", "please review", []string{"victim@example-lab.test"})
	if err != nil {
		t.Fatalf("CreateCalendarEventLure() error = %v", err)
	}
	if lure.EventID != "event-1" {
		t.Errorf("EventID = %q, want %q", lure.EventID, "event-1")
	}
	if gotPath != "/users/user-1/events" {
		t.Errorf("path = %q, want %q", gotPath, "/users/user-1/events")
	}
	if gotBody["subject"] != "Urgent: plan review" {
		t.Errorf("body subject = %v, want %q", gotBody["subject"], "Urgent: plan review")
	}
}

func TestCreateCalendarEventLure_NoAttendees_Rejected(t *testing.T) {
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	if _, err := client.CreateCalendarEventLure(t.Context(), "user-1", "subj", "body", nil); err == nil {
		t.Error("CreateCalendarEventLure() with no attendees = nil error, want an error")
	}
}

func TestCreateCalendarEventLure_EmptyUserID_Rejected(t *testing.T) {
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	if _, err := client.CreateCalendarEventLure(t.Context(), "", "subj", "body", []string{"a@b.test"}); err == nil {
		t.Error("CreateCalendarEventLure() with an empty userID = nil error, want an error (never an unscoped organizer mailbox)")
	}
}

func TestVerifyCalendarEventExists_ConfirmedAndMissing(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	status := http.StatusOK
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer graphSrv.Close()
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if got := client.VerifyCalendarEventExists(t.Context(), "user-1", "event-1"); got != CreatedConfirmed {
		t.Errorf("VerifyCalendarEventExists() = %q, want %q", got, CreatedConfirmed)
	}
	status = http.StatusNotFound
	if got := client.VerifyCalendarEventExists(t.Context(), "user-1", "event-1"); got != CreatedMissing {
		t.Errorf("VerifyCalendarEventExists() = %q, want %q", got, CreatedMissing)
	}
}

func TestDeleteCalendarEvent_HTTPTestServer_RealDelete(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	var gotMethod, gotPath string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer graphSrv.Close()
	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if err := client.DeleteCalendarEvent(t.Context(), "user-1", "event-1"); err != nil {
		t.Fatalf("DeleteCalendarEvent() error = %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/users/user-1/events/event-1" {
		t.Errorf("got %s %s, want DELETE /users/user-1/events/event-1", gotMethod, gotPath)
	}
}
