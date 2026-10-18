package phishidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// MFADenialErrorCode is the real, Microsoft-documented signIn
// status.errorCode value for "authentication failed during strong
// authentication request" -- a denied or unanswered MFA challenge.
// Confirmed against public vendor/community detection guides
// (Datadog's "Azure AD MFA push fatigue" rule, ManageEngine,
// Northwave) that all key their own MFA-fatigue detections off this
// exact code plus authenticationRequirement == "multiFactorAuthentication".
const MFADenialErrorCode = 500121

// MFADenialEvent is one normalized signIn record representing an MFA
// challenge the user explicitly denied or never answered -- real,
// Microsoft-documented fields (status.errorCode, status.additionalDetails),
// never a Microsoft-defined "MFA fatigue" detection type, because no
// such riskDetections.riskEventType value exists (confirmed by
// research; see this initiative's own PH-ID-004 catalog entry).
type MFADenialEvent struct {
	ID                string
	UserID            string
	CreatedDateTime   time.Time
	ErrorCode         int
	AdditionalDetails string
}

type mfaDenialEventPage struct {
	Value []struct {
		ID              string    `json:"id"`
		UserID          string    `json:"userId"`
		CreatedDateTime time.Time `json:"createdDateTime"`
		Status          struct {
			ErrorCode         int    `json:"errorCode"`
			AdditionalDetails string `json:"additionalDetails"`
		} `json:"status"`
	} `json:"value"`
}

// MFADenialEventsForUser calls
// GET {BaseURL}/auditLogs/signIns?$filter=userId eq '<userID>' and status/errorCode eq 500121
// and normalizes every record returned. Server-side $filter support
// for a nested status/errorCode comparison is not confirmed by
// Microsoft's own published filterable-properties list, so this
// method defensively re-filters the returned page client-side on both
// UserID and ErrorCode == MFADenialErrorCode -- the same client-side-
// fallback discipline SignInsByAuthenticationProtocol already uses.
func (c *Client) MFADenialEventsForUser(ctx context.Context, userID string) ([]MFADenialEvent, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	filter := fmt.Sprintf("userId eq '%s' and status/errorCode eq %d", userID, MFADenialErrorCode)
	reqURL := c.BaseURL + "/auditLogs/signIns?$filter=" + url.QueryEscape(filter)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	var page mfaDenialEventPage
	decodeErr := json.NewDecoder(resp.Body).Decode(&page)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phishidentity: auditLogs/signIns returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}

	events := make([]MFADenialEvent, 0, len(page.Value))
	for _, v := range page.Value {
		if v.UserID != userID || v.Status.ErrorCode != MFADenialErrorCode {
			continue // defensive client-side re-filter, see doc comment above
		}
		events = append(events, MFADenialEvent{
			ID: v.ID, UserID: v.UserID, CreatedDateTime: v.CreatedDateTime,
			ErrorCode: v.Status.ErrorCode, AdditionalDetails: v.Status.AdditionalDetails,
		})
	}
	return events, nil
}

// MFAFatigueHeuristicVerdict is this heuristic's own 3-way outcome --
// EXPERIMENTAL, not a Microsoft-documented verdict type.
type MFAFatigueHeuristicVerdict string

const (
	MFAFatigueSuspected   MFAFatigueHeuristicVerdict = "suspected"
	MFAFatigueNotObserved MFAFatigueHeuristicVerdict = "not_observed"
	MFAFatigueUnknown     MFAFatigueHeuristicVerdict = "unknown"
)

// DetectMFAFatigueHeuristic is a labeled, best-effort heuristic --
// EXPLICITLY NOT a Microsoft-documented detection. Microsoft Graph's
// riskDetections.riskEventType enum has no member for repeated-push/
// MFA-fatigue activity (confirmed by research); this function instead
// applies the same burst-counting approach published by independent
// vendor/community detections (Datadog's "Azure AD MFA push fatigue"
// rule, ManageEngine, Northwave) over real MFADenialEvent records:
// flag a burst of >= threshold denials for one user within a sliding
// window. threshold/within are left as caller-supplied parameters
// rather than a hardcoded "correct" value, since no official Microsoft
// number exists -- a widely cited community rule uses 15 within 30
// minutes, but that is a third-party tuning choice, not a vendor-
// verified signal, and callers (and any report built on this verdict)
// must be told so rather than presented a bare pass/fail.
func DetectMFAFatigueHeuristic(events []MFADenialEvent, threshold int, within time.Duration) (MFAFatigueHeuristicVerdict, string) {
	if len(events) == 0 {
		return MFAFatigueUnknown, "no MFA denial events observed in this window"
	}
	sorted := make([]MFADenialEvent, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CreatedDateTime.Before(sorted[j].CreatedDateTime) })

	for i := range sorted {
		count := 1
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].CreatedDateTime.Sub(sorted[i].CreatedDateTime) > within {
				break
			}
			count++
		}
		if count >= threshold {
			return MFAFatigueSuspected, fmt.Sprintf(
				"heuristic only, not a Microsoft-documented detection: %d MFA denial events within %s (threshold %d), starting at %s",
				count, within, threshold, sorted[i].CreatedDateTime.Format(time.RFC3339))
		}
	}
	return MFAFatigueNotObserved, fmt.Sprintf("%d MFA denial event(s) observed, none met the %d-within-%s burst threshold", len(sorted), threshold, within)
}
