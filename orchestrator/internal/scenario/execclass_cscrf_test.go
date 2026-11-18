package scenario

import "testing"

// Each CSCRF-MII network step resolves to an explicit class. Unlisted pairs fail closed to destructive.
func TestCSCRFNetworkStepsHaveExplicitClassification(t *testing.T) {
	cases := []struct {
		tid, action string
		want        ExecutionClass
	}{
		{"T1046", "cscrf_net_subnet_reachability", ClassNonDestructive},
		{"T1046", "cscrf_net_listener_inventory", ClassNonDestructive},
		{"T1046", "cscrf_net_segmentation_probe", ClassNonDestructive},
		{"T1016", "cscrf_net_firewall_inventory", ClassNonDestructive},
		{"T1016", "cscrf_net_dns_config", ClassNonDestructive},
		{"T1562.004", "cscrf_net_firewall_policy_state", ClassNonDestructive},
		{"T1571", "cscrf_net_inbound_probe", ClassNonDestructive},
		{"T1571", "cscrf_net_outbound_probe", ClassNonDestructive},
	}
	for _, c := range cases {
		got := ResolveExecutionClass(c.tid, c.action)
		if got.DestructiveAction == "unclassified" {
			t.Errorf("%s / %s: no catalog entry (fails closed to destructive)", c.tid, c.action)
			continue
		}
		if got.Class != c.want {
			t.Errorf("%s / %s: class %s, want %s", c.tid, c.action, got.Class, c.want)
		}
	}
}
