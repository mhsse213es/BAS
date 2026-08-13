package taxii

import (
	"context"
)

// Poller runs one full discover-if-needed + paginated-poll + normalize
// cycle for a single ConnectorConfig. Unlike vexsweep/emsweep's Dispatcher
// (which advances a long-running dispatched task one step per tick across
// many ticks), a TAXII sync is a single self-contained round trip -- there
// is no external in-flight task to babysit across ticks, so Sync does
// everything in one call.
type Poller struct {
	cfg        ConnectorConfig
	client     *Client
	store      *Store
	normalizer *Normalizer
}

func NewPoller(cfg ConnectorConfig, store *Store, normalizer *Normalizer) *Poller {
	return &Poller{cfg: cfg, client: NewClient(cfg), store: store, normalizer: normalizer}
}

// Sync discovers the API root (if not already configured), polls every
// page of the configured collection since the last successful poll, feeds
// each page to the Normalizer, and records the aggregate result on the
// config row.
func (p *Poller) Sync(ctx context.Context) error {
	apiRoot := p.cfg.APIRoot
	if apiRoot == "" {
		disc, err := p.client.Discover(ctx)
		if err != nil {
			p.store.RecordPollResult(ctx, p.cfg.ID, "error", PollSummary{}, err.Error())
			return err
		}
		apiRoot = disc.DefaultAPIRoot
	}

	var total PollSummary
	next := ""
	for {
		page, err := p.client.PollObjects(ctx, apiRoot, p.cfg.CollectionID, p.cfg.LastPollAt, next)
		if err != nil {
			p.store.RecordPollResult(ctx, p.cfg.ID, "error", total, err.Error())
			return err
		}
		sum, err := p.normalizer.Ingest(ctx, p.cfg.ID, p.cfg.Name, page.Objects)
		if err != nil {
			p.store.RecordPollResult(ctx, p.cfg.ID, "error", total, err.Error())
			return err
		}
		total.Processed += sum.Processed
		total.Skipped += sum.Skipped
		total.Malformed += sum.Malformed
		if !page.More || page.Next == "" {
			break
		}
		next = page.Next
	}
	return p.store.RecordPollResult(ctx, p.cfg.ID, "ok", total, "")
}
