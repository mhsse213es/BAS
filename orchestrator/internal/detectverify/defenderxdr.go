package detectverify

import (
	"context"
	"strings"

	"github.com/audspect/bas/internal/vendors/defender"
)

// defenderXDRConnector adapts internal/vendors/defender's alert query to
// detectverify's Connector interface, applying host-filtering (a
// verification-specific concern the vendor client doesn't know about).
// Response actions (isolate/kill/quarantine) live on defender.Client
// directly and are consumed by internal/actions (a later plan), never by
// this package.
type defenderXDRConnector struct {
	client *defender.Client
}

func newDefenderXDRConnector(cfg Config) *defenderXDRConnector {
	return &defenderXDRConnector{
		client: defender.New(defender.Config{
			TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		}),
	}
}

func (d *defenderXDRConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	alerts, err := d.client.QueryAlerts(ctx, req.WindowStart, req.WindowEnd)
	if err != nil {
		return VerifyResult{}, err
	}
	normalized := make([]normalizedAlert, 0, len(alerts))
	for _, a := range alerts {
		if !alertMentionsHost(a.DeviceDNSName, req.HostName) {
			continue
		}
		normalized = append(normalized, normalizedAlert{
			AlertID: a.ID, RuleName: a.RuleName, Timestamp: a.Timestamp,
			Severity: a.Severity, Techniques: a.Techniques,
			InvestigationURL: "https://security.microsoft.com/alerts/" + a.ID,
			RawJSON:          a.RawJSON,
		})
	}
	return matchAlerts(req, normalized), nil
}

// alertMentionsHost reports whether deviceDNSName matches hostName. When
// hostName is empty (agent has no known hostname) every alert is accepted —
// better to over-match at medium confidence than silently verify nothing.
func alertMentionsHost(deviceDNSName, hostName string) bool {
	if hostName == "" {
		return true
	}
	return strings.EqualFold(deviceDNSName, hostName)
}

func (d *defenderXDRConnector) TestConnection(ctx context.Context) error {
	return d.client.TestConnection(ctx)
}
