package segprobe

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// fwRecordBoundary separates records in ulogd's OPRINT output.
const fwRecordBoundary = "===>PACKET BOUNDARY"

// ParseFirewallLog parses ulogd OPRINT records written by seg-fw. Each record
// is a block of key=value lines. A record missing a required field, or with a
// protocol this lab does not use, is an error for the whole log: the evidence
// cannot be trusted if any part of it cannot be read.
func ParseFirewallLog(data []byte) ([]FirewallEvent, error) {
	var out []FirewallEvent
	for i, block := range strings.Split(string(data), fwRecordBoundary) {
		fields := parseRecordFields(block)
		if len(fields) == 0 {
			continue
		}
		// Only TCP and UDP carry probe tuples. Other packets (ICMP, say) that
		// reach the catch-all are not evidence for any probe, so skip them
		// rather than failing the whole log.
		if p := fields["ip.protocol"]; p != "6" && p != "17" {
			continue
		}
		ev, err := eventFromFields(fields)
		if err != nil {
			return nil, fmt.Errorf("firewall log record %d: %w", i, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

func parseRecordFields(block string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[k] = v
	}
	return fields
}

func eventFromFields(f map[string]string) (FirewallEvent, error) {
	prefix, ok := f["oob.prefix"]
	if !ok || prefix == "" {
		return FirewallEvent{}, fmt.Errorf("missing oob.prefix")
	}
	ruleID, action, ok := strings.Cut(prefix, "|")
	if !ok || ruleID == "" || action == "" {
		return FirewallEvent{}, fmt.Errorf("prefix %q is not RULEID|ACTION", prefix)
	}

	sec, err := strconv.ParseInt(f["oob.time.sec"], 10, 64)
	if err != nil {
		return FirewallEvent{}, fmt.Errorf("oob.time.sec: %w", err)
	}
	var usec int64
	if raw, ok := f["oob.time.usec"]; ok {
		usec, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return FirewallEvent{}, fmt.Errorf("oob.time.usec: %w", err)
		}
	}

	src := f["ip.saddr.str"]
	dst := f["ip.daddr.str"]
	if src == "" || dst == "" {
		return FirewallEvent{}, fmt.Errorf("missing ip.saddr.str or ip.daddr.str")
	}

	var proto, portKey string
	switch f["ip.protocol"] {
	case "6":
		proto, portKey = "tcp", "tcp.dport"
	case "17":
		proto, portKey = "udp", "udp.dport"
	default:
		return FirewallEvent{}, fmt.Errorf("unsupported ip.protocol %q", f["ip.protocol"])
	}
	port, err := strconv.Atoi(f[portKey])
	if err != nil {
		return FirewallEvent{}, fmt.Errorf("%s: %w", portKey, err)
	}

	return FirewallEvent{
		Time:    time.Unix(sec, usec*1000).UTC(),
		RuleID:  ruleID,
		Action:  action,
		SrcIP:   src,
		DstIP:   dst,
		DstPort: port,
		Proto:   proto,
	}, nil
}
