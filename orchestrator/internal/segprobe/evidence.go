package segprobe

import "time"

// ProbeRequest describes one controlled connection attempt. Zone fields are
// plain strings here; the Zone type lives with the scenario model.
type ProbeRequest struct {
	SrcZone string
	DstZone string
	SrcIP   string
	DstIP   string
	DstPort int
	Proto   string
	Timeout time.Duration
	Expect  Expect
}

// MatchEvidence returns the firewall events that belong to this probe: the
// same source and destination IP, destination port and protocol, with a
// timestamp inside the probe window widened by slack on both sides. Other
// tuples and other time windows are excluded so one probe is never credited
// with another probe's block.
func MatchEvidence(req ProbeRequest, res ProbeResult, events []FirewallEvent, slack time.Duration) []FirewallEvent {
	from := res.Start.Add(-slack)
	to := res.End.Add(slack)
	var out []FirewallEvent
	for _, e := range events {
		if e.SrcIP != req.SrcIP || e.DstIP != req.DstIP || e.DstPort != req.DstPort || e.Proto != req.Proto {
			continue
		}
		if e.Time.Before(from) || e.Time.After(to) {
			continue
		}
		out = append(out, e)
	}
	return out
}
