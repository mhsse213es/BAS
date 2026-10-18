package phishidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CreatedState is whether a dispatched creation (a sharing invite, a
// calendar event) was independently confirmed to exist via a separate
// read-back, never just inferred from the creation call's own success
// status -- the same "dispatch acceptance is not proof" discipline as
// RevokeAndVerifySignInSessions, applied to creation instead of
// revocation.
type CreatedState string

const (
	CreatedConfirmed CreatedState = "confirmed" // independently read back and found present
	CreatedMissing   CreatedState = "missing"   // independently read back and NOT found -- a real negative
	CreatedUnknown   CreatedState = "unknown"   // the read-back itself failed; never read as either of the above
)

// --- PH-CHN-002: malicious cloud-sharing invitation -----------------------

// SharingInvite is one created OneDrive/SharePoint sharing invitation
// (a Graph driveItem permission). Delivery-only evidence: creating the
// invite proves the lure reached the sharing API, never that the
// recipient saw, opened, or acted on it -- that would need separate
// user-interaction evidence this adapter does not have.
type SharingInvite struct {
	PermissionID string
	CreatedAt    time.Time
}

type permissionResponse struct {
	ID string `json:"id"`
}

// CreateSharingInvite calls the real, stable Graph v1.0 action
// POST {BaseURL}/drives/{driveID}/items/{itemID}/invite, scoped to one
// explicitly-named drive item and one explicit recipient list --
// never a tenant-wide or unscoped share. requireSignIn=true and
// sendInvitation are always set so the created permission is traceable
// to a specific, authorized recipient, never an anonymous link.
func (c *Client) CreateSharingInvite(ctx context.Context, driveID, itemID string, recipientEmails []string, message string) (SharingInvite, error) {
	if driveID == "" || itemID == "" {
		return SharingInvite{}, fmt.Errorf("phishidentity: driveID and itemID must both be explicit (never a tenant-wide share)")
	}
	if len(recipientEmails) == 0 {
		return SharingInvite{}, fmt.Errorf("phishidentity: recipientEmails must name at least one explicit, authorized recipient")
	}
	recipients := make([]map[string]string, 0, len(recipientEmails))
	for _, email := range recipientEmails {
		recipients = append(recipients, map[string]string{"email": email})
	}
	payload, _ := json.Marshal(map[string]any{
		"requireSignIn": true, "sendInvitation": true, "roles": []string{"read"},
		"recipients": recipients, "message": message,
	})

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return SharingInvite{}, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/drives/"+driveID+"/items/"+itemID+"/invite", bytes.NewReader(payload))
	if err != nil {
		return SharingInvite{}, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return SharingInvite{}, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		Value []permissionResponse `json:"value"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SharingInvite{}, fmt.Errorf("phishidentity: invite returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return SharingInvite{}, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}
	if len(body.Value) == 0 || body.Value[0].ID == "" {
		return SharingInvite{}, fmt.Errorf("phishidentity: invite response carried no permission ID")
	}
	return SharingInvite{PermissionID: body.Value[0].ID, CreatedAt: time.Now()}, nil
}

// VerifySharingInviteExists independently re-reads
// GET {BaseURL}/drives/{driveID}/items/{itemID}/permissions/{permissionID}
// -- a separate call from CreateSharingInvite's own response, so a
// permission ID the invite call merely echoed back is never confused
// with one a second, independent read confirms is actually present.
func (c *Client) VerifySharingInviteExists(ctx context.Context, driveID, itemID, permissionID string) CreatedState {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return CreatedUnknown
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/drives/"+driveID+"/items/"+itemID+"/permissions/"+permissionID, nil)
	if err != nil {
		return CreatedUnknown
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CreatedUnknown
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		return CreatedConfirmed
	case resp.StatusCode == http.StatusNotFound:
		return CreatedMissing
	default:
		return CreatedUnknown
	}
}

// DeleteSharingInvite cleans up an authorized-lab sharing invite via
// DELETE {BaseURL}/drives/{driveID}/items/{itemID}/permissions/{permissionID}
// -- every invite this adapter creates is explicitly scoped (one drive
// item, one permission ID) so cleanup never risks touching a
// permission this run did not itself create.
func (c *Client) DeleteSharingInvite(ctx context.Context, driveID, itemID, permissionID string) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.BaseURL+"/drives/"+driveID+"/items/"+itemID+"/permissions/"+permissionID, nil)
	if err != nil {
		return fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("phishidentity: delete permission returned status %d", resp.StatusCode)
	}
	return nil
}

// --- PH-CHN-004: calendar invitation lure ---------------------------------

// CalendarEventLure is one created calendar-invite lure (a Graph
// event). Delivery-only, same boundary as SharingInvite: creation
// proves the lure reached the calendaring API, never that the invited
// user saw it, accepted it, or clicked anything inside it.
type CalendarEventLure struct {
	EventID   string
	CreatedAt time.Time
}

type eventResponse struct {
	ID string `json:"id"`
}

// CreateCalendarEventLure calls the real, stable Graph v1.0 action
// POST {BaseURL}/users/{userID}/events, scoped to one explicitly-named
// organizer mailbox and an explicit attendee list -- never a
// tenant-wide broadcast.
func (c *Client) CreateCalendarEventLure(ctx context.Context, userID, subject, body string, attendeeEmails []string) (CalendarEventLure, error) {
	if userID == "" {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: userID (organizer mailbox) must be explicit")
	}
	if len(attendeeEmails) == 0 {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: attendeeEmails must name at least one explicit, authorized recipient")
	}
	attendees := make([]map[string]any, 0, len(attendeeEmails))
	for _, email := range attendeeEmails {
		attendees = append(attendees, map[string]any{
			"emailAddress": map[string]string{"address": email}, "type": "required",
		})
	}
	start := time.Now().Add(24 * time.Hour)
	payload, _ := json.Marshal(map[string]any{
		"subject":   subject,
		"body":      map[string]string{"contentType": "text", "content": body},
		"start":     map[string]string{"dateTime": start.Format(time.RFC3339), "timeZone": "UTC"},
		"end":       map[string]string{"dateTime": start.Add(30 * time.Minute).Format(time.RFC3339), "timeZone": "UTC"},
		"attendees": attendees,
	})

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/users/"+userID+"/events", bytes.NewReader(payload))
	if err != nil {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	var body2 eventResponse
	decodeErr := json.NewDecoder(resp.Body).Decode(&body2)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: creating event returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}
	if body2.ID == "" {
		return CalendarEventLure{}, fmt.Errorf("phishidentity: event response carried no event ID")
	}
	return CalendarEventLure{EventID: body2.ID, CreatedAt: time.Now()}, nil
}

// VerifyCalendarEventExists independently re-reads
// GET {BaseURL}/users/{userID}/events/{eventID} -- a separate call from
// CreateCalendarEventLure's own response.
func (c *Client) VerifyCalendarEventExists(ctx context.Context, userID, eventID string) CreatedState {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return CreatedUnknown
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/users/"+userID+"/events/"+eventID, nil)
	if err != nil {
		return CreatedUnknown
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CreatedUnknown
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		return CreatedConfirmed
	case resp.StatusCode == http.StatusNotFound:
		return CreatedMissing
	default:
		return CreatedUnknown
	}
}

// DeleteCalendarEvent cleans up an authorized-lab calendar lure via
// DELETE {BaseURL}/users/{userID}/events/{eventID}.
func (c *Client) DeleteCalendarEvent(ctx context.Context, userID, eventID string) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/users/"+userID+"/events/"+eventID, nil)
	if err != nil {
		return fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("phishidentity: delete event returned status %d", resp.StatusCode)
	}
	return nil
}
