package cloudgraph

import (
	"fmt"
	"strings"
	"testing"
)

// The client secret must not appear in any formatted form of the config.
func TestAzureDiscoveryConfig_FormattingRedactsSecret(t *testing.T) {
	const secret = "s3cr3t-value-xyz"
	cfg := AzureDiscoveryConfig{TenantID: "t", ClientID: "c", ClientSecret: secret, SubscriptionID: "sub"}
	for _, form := range []string{
		fmt.Sprintf("%v", cfg),
		fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%#v", cfg),
		fmt.Sprintf("%s", cfg),
	} {
		if strings.Contains(form, secret) {
			t.Errorf("formatted config leaks the secret: %q", form)
		}
		if !strings.Contains(form, "[REDACTED]") {
			t.Errorf("formatted config does not mark the secret as redacted: %q", form)
		}
	}
}
