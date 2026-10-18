package phishidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// RiskySignInEvent is one normalized signIn record carrying its real,
// Microsoft-documented v1.0 riskState property ("atRisk",
// "confirmedCompromised", "confirmedSafe", "remediated", "dismissed",
// "none", "unknownFutureValue") -- genuine per-event risk evidence,
// never configuration.
type RiskySignInEvent struct {
	ID              string
	CreatedDateTime time.Time
	RiskState       string
}

// riskySignInRiskyStates are the riskState values this heuristic
// treats as an active, unresolved risk signal -- "remediated" and
// "dismissed" are deliberately excluded, since those mean the risk
// was already addressed through Entra's own workflow, not something
// still open for a theft-response heuristic to react to.
var riskySignInRiskyStates = map[string]bool{"atRisk": true, "confirmedCompromised": true}

type riskySignInEventPage struct {
	Value []struct {
		ID              string    `json:"id"`
		UserID          string    `json:"userId"`
		CreatedDateTime time.Time `json:"createdDateTime"`
		RiskState       string    `json:"riskState"`
	} `json:"value"`
}

// RiskySignInsForUser calls
// GET {BaseURL}/auditLogs/signIns?$filter=userId eq '<userID>'
// and returns only the records whose riskState is one of
// riskySignInRiskyStates -- client-side filtering, the same defensive
// discipline SignInsByAuthenticationProtocol and
// MFADenialEventsForUser already use for unconfirmed server-side
// $filter support.
func (c *Client) RiskySignInsForUser(ctx context.Context, userID string) ([]RiskySignInEvent, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	filter := fmt.Sprintf("userId eq '%s'", userID)
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

	var page riskySignInEventPage
	decodeErr := json.NewDecoder(resp.Body).Decode(&page)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phishidentity: auditLogs/signIns returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}

	events := make([]RiskySignInEvent, 0, len(page.Value))
	for _, v := range page.Value {
		if v.UserID != userID || !riskySignInRiskyStates[v.RiskState] {
			continue
		}
		events = append(events, RiskySignInEvent{ID: v.ID, CreatedDateTime: v.CreatedDateTime, RiskState: v.RiskState})
	}
	return events, nil
}

// SessionTheftHeuristicVerdict is this heuristic's own 3-way outcome
// -- EXPERIMENTAL, not a Microsoft-documented verdict type.
type SessionTheftHeuristicVerdict string

const (
	SessionTheftRevokedAfterRiskyEvent SessionTheftHeuristicVerdict = "revoked_after_risky_event"
	SessionTheftNotRevoked             SessionTheftHeuristicVerdict = "not_revoked"
	SessionTheftUnknown                SessionTheftHeuristicVerdict = "unknown"
)

// DetectSessionTheftResponseHeuristic is a labeled, best-effort
// heuristic -- EXPLICITLY NOT a Microsoft-documented detection of
// session theft itself. No Microsoft-documented sign-in log field
// records a revocation-rejection event for user identities (only
// workload identities get that treatment, a different object class;
// confirmed by research, see this initiative's own PH-ID-005 catalog
// entry). This function instead checks whether sessionsValidFrom
// (SignInSessionsValidFromDateTime's own real, documented field --
// the same baseline RevokeAndVerifySignInSessions already reads)
// advanced to AFTER a risky/compromised sign-in's own
// CreatedDateTime, within a bounded window. That is suggestive that a
// response action followed the risky event -- it is never proof of
// causality, since Microsoft documents no field linking the two.
func DetectSessionTheftResponseHeuristic(riskySignIns []RiskySignInEvent, sessionsValidFrom time.Time, within time.Duration) (SessionTheftHeuristicVerdict, string) {
	if len(riskySignIns) == 0 {
		return SessionTheftUnknown, "no risky/compromised sign-in observed in this window"
	}
	if sessionsValidFrom.IsZero() {
		return SessionTheftUnknown, "signInSessionsValidFromDateTime unavailable"
	}
	for _, s := range riskySignIns {
		if sessionsValidFrom.After(s.CreatedDateTime) && sessionsValidFrom.Sub(s.CreatedDateTime) <= within {
			return SessionTheftRevokedAfterRiskyEvent, fmt.Sprintf(
				"heuristic only, not proof of causality: sessions revoked at %s, %s after risky sign-in %s (riskState=%s) at %s",
				sessionsValidFrom.Format(time.RFC3339), sessionsValidFrom.Sub(s.CreatedDateTime), s.ID, s.RiskState, s.CreatedDateTime.Format(time.RFC3339))
		}
	}
	return SessionTheftNotRevoked, fmt.Sprintf("%d risky sign-in(s) observed, sessions not revoked within %s of any of them", len(riskySignIns), within)
}
