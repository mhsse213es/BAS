package detectverify

import (
	"context"

	"github.com/audspect/bas/internal/vendors/crowdstrike"
)

// crowdstrikeConnector adapts internal/vendors/crowdstrike's alert query to
// detectverify's Connector interface. Response actions (isolate/kill/
// quarantine) live on crowdstrike.Client directly and are consumed by
// internal/actions (a later plan), never by this package.
type crowdstrikeConnector struct {
	client *crowdstrike.Client
}

func newCrowdStrikeConnector(cfg Config) *crowdstrikeConnector {
	return &crowdstrikeConnector{
		client: crowdstrike.New(crowdstrike.Config{
			BaseURL: cfg.BaseURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		}),
	}
}

func (c *crowdstrikeConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	alerts, err := c.client.QueryAlerts(ctx, crowdstrike.AlertQuery{
		Hostname: req.HostName, WindowStart: req.WindowStart, WindowEnd: req.WindowEnd,
	})
	if err != nil {
		return VerifyResult{}, err
	}
	normalized := make([]normalizedAlert, 0, len(alerts))
	for _, a := range alerts {
		normalized = append(normalized, normalizedAlert{
			AlertID: a.AlertID, RuleName: a.RuleName, Timestamp: a.Timestamp,
			Severity: a.Severity, Techniques: a.Techniques, RawJSON: a.RawJSON,
		})
	}
	return matchAlerts(req, normalized), nil
}

func (c *crowdstrikeConnector) TestConnection(ctx context.Context) error {
	return c.client.TestConnection(ctx)
}
