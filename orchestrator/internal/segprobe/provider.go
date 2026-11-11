package segprobe

import (
	"context"
	"time"
)

// TimeWindow bounds the firewall events considered for one probe.
type TimeWindow struct {
	From time.Time
	To   time.Time
}

// Provider is the lab-agnostic boundary: Docker labs, Linux VMs and customer
// agents each implement it, and the executor never talks to one directly.
type Provider interface {
	// Healthy reports whether the zone's probe runner or target is usable.
	Healthy(ctx context.Context, zone Zone) error
	// Lookup returns the IP address of a zone's probe runner or target.
	Lookup(zone Zone) (string, error)
	// Probe performs one controlled connection attempt from the source zone.
	Probe(ctx context.Context, req ProbeRequest) (ProbeResult, error)
	// FirewallEvents returns firewall decisions inside the window. The bool is
	// false when the firewall log cannot be read; the caller must then never
	// treat a block as PASS.
	FirewallEvents(ctx context.Context, w TimeWindow) ([]FirewallEvent, bool, error)
}
