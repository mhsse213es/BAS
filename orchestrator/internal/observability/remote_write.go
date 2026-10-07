package observability

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	snappy "github.com/klauspost/compress/snappy"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/encoding/protowire"
)

// RemoteWriter pushes the registry to a Prometheus remote-write receiver
// (Prometheus, Mimir, VictoriaMetrics, Thanos Receive). Pull-based /metrics
// stays as it is; this is an additional push path.
type RemoteWriter struct {
	endpoint string
	client   *http.Client
	gather   func() ([]*dto.MetricFamily, error)
}

// NewRemoteWriter returns nil and no error when endpoint is empty: with no
// endpoint configured there is no push and no attempt at all.
func NewRemoteWriter(endpoint string, gather func() ([]*dto.MetricFamily, error)) (*RemoteWriter, error) {
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("remote-write endpoint must be an http(s) URL, got %q", endpoint)
	}
	return &RemoteWriter{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
		gather:   gather,
	}, nil
}

// Push gathers the registry and sends one WriteRequest stamped with now. Any
// transport error or non-2xx response is returned.
func (w *RemoteWriter) Push(ctx context.Context, now time.Time) error {
	families, err := w.gather()
	if err != nil {
		return fmt.Errorf("gather: %w", err)
	}
	body := snappy.Encode(nil, encodeWriteRequest(families, now.UnixMilli()))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	req.Header.Set("User-Agent", "audspect-orchestrator")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("remote-write send: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("remote-write receiver returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// RunRemoteWrite pushes every interval until ctx is done. A failed push is
// logged and dropped: the next interval sends current values, so a short
// receiver outage leaves a gap in the history but nothing is replayed.
func RunRemoteWrite(ctx context.Context, w *RemoteWriter, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := w.Push(ctx, now); err != nil {
				log.Printf("[observability] remote-write: %v", err)
			}
		}
	}
}

// Families returns the registry's metric families for the remote writer.
func (m *MetricsRegistry) Families() ([]*dto.MetricFamily, error) {
	raw, err := m.Gather()
	if err != nil {
		return nil, err
	}
	families, _ := raw.([]*dto.MetricFamily)
	return families, nil
}

type promSeries struct {
	labels []labelPair
	value  float64
}

type labelPair struct{ name, value string }

// encodeWriteRequest turns metric families into a Prometheus WriteRequest.
// Counters, gauges and histograms are exported (histograms as _bucket, _sum,
// _count); summaries are not used by this registry and are skipped.
func encodeWriteRequest(families []*dto.MetricFamily, tsMillis int64) []byte {
	var series []promSeries
	for _, f := range families {
		name := f.GetName()
		for _, m := range f.GetMetric() {
			base := make([]labelPair, 0, len(m.GetLabel())+1)
			for _, lp := range m.GetLabel() {
				base = append(base, labelPair{lp.GetName(), lp.GetValue()})
			}
			switch {
			case m.GetCounter() != nil:
				series = append(series, promSeries{withName(base, name), m.GetCounter().GetValue()})
			case m.GetGauge() != nil:
				series = append(series, promSeries{withName(base, name), m.GetGauge().GetValue()})
			case m.GetHistogram() != nil:
				h := m.GetHistogram()
				for _, b := range h.GetBucket() {
					le := formatFloat(b.GetUpperBound())
					series = append(series, promSeries{withName(append(append([]labelPair{}, base...), labelPair{"le", le}), name+"_bucket"), float64(b.GetCumulativeCount())})
				}
				series = append(series, promSeries{withName(append(append([]labelPair{}, base...), labelPair{"le", "+Inf"}), name+"_bucket"), float64(h.GetSampleCount())})
				series = append(series, promSeries{withName(base, name+"_sum"), h.GetSampleSum()})
				series = append(series, promSeries{withName(base, name+"_count"), float64(h.GetSampleCount())})
			}
		}
	}

	var req []byte
	for _, s := range series {
		ts := encodeTimeSeries(s, tsMillis)
		req = protowire.AppendTag(req, 1, protowire.BytesType)
		req = protowire.AppendBytes(req, ts)
	}
	return req
}

func withName(labels []labelPair, name string) []labelPair {
	out := append(append([]labelPair{}, labels...), labelPair{"__name__", name})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func encodeTimeSeries(s promSeries, tsMillis int64) []byte {
	var b []byte
	for _, lp := range s.labels {
		var lb []byte
		lb = protowire.AppendTag(lb, 1, protowire.BytesType)
		lb = protowire.AppendString(lb, lp.name)
		lb = protowire.AppendTag(lb, 2, protowire.BytesType)
		lb = protowire.AppendString(lb, lp.value)
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, lb)
	}
	var sb []byte
	sb = protowire.AppendTag(sb, 1, protowire.Fixed64Type)
	sb = protowire.AppendFixed64(sb, math.Float64bits(s.value))
	sb = protowire.AppendTag(sb, 2, protowire.VarintType)
	sb = protowire.AppendVarint(sb, uint64(tsMillis))
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendBytes(b, sb)
	return b
}

func formatFloat(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
