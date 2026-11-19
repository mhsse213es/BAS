package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/observability"
)

// cloudTestSettings builds settings directly from an allow-list spec, without
// touching the process environment or any secrets file.
func cloudTestSettings(t *testing.T, spec string) *CloudSettings {
	t.Helper()
	allow, err := cloudgraph.ParseAccountAllowList(spec)
	if err != nil {
		t.Fatalf("parse allow-list: %v", err)
	}
	return &CloudSettings{allow: allow, gate: newCloudDiscoveryGate(4, 8, time.Second)}
}

func acct(id string) cloudgraph.AccountScope {
	return cloudgraph.AccountScope{Provider: "aws", AccountID: id}
}

func TestPermitAccount_FailsClosed(t *testing.T) {
	var nilSettings *CloudSettings
	if err := nilSettings.permitAccount(acct("111111111111")); !errors.Is(err, errCloudAccountNotAllowed) {
		t.Errorf("nil settings must refuse, got %v", err)
	}
	s := cloudTestSettings(t, "aws:111111111111")
	if err := s.permitAccount(acct("111111111111")); err != nil {
		t.Errorf("listed account refused: %v", err)
	}
	if err := s.permitAccount(acct("222222222222")); !errors.Is(err, errCloudAccountNotAllowed) {
		t.Errorf("unlisted account permitted: %v", err)
	}
}

func TestLoadCloudSettings_RefusesAzureSecretInEnvironment(t *testing.T) {
	const canary = "leak-canary-9f3"
	t.Setenv("AZURE_CLIENT_SECRET", canary)
	_, err := LoadCloudSettings(nil)
	if err == nil {
		t.Fatal("a client secret in the process environment must stop startup")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error leaks the secret value: %v", err)
	}
}

func writeSecretsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "azure.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validAzureSecrets = `# service principal for the lab subscription
AZURE_TENANT_ID=tenant-1
AZURE_CLIENT_ID=client-1
AZURE_CLIENT_SECRET=secret-value-abc
AZURE_SUBSCRIPTION_ID=sub-1
`

func TestLoadAzureSecrets_ValidFileLoads(t *testing.T) {
	cfg, err := loadAzureSecrets(writeSecretsFile(t, validAzureSecrets))
	if err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if cfg.TenantID != "tenant-1" || cfg.ClientID != "client-1" || cfg.ClientSecret != "secret-value-abc" || cfg.SubscriptionID != "sub-1" {
		t.Errorf("parsed config wrong: %+v", cfg)
	}
}

func TestLoadAzureSecrets_ParserRejectsBadFiles(t *testing.T) {
	cases := map[string]struct{ body, wantMention string }{
		"missing key":    {"AZURE_TENANT_ID=t\nAZURE_CLIENT_ID=c\nAZURE_CLIENT_SECRET=s\n", "AZURE_SUBSCRIPTION_ID"},
		"unknown key":    {validAzureSecrets + "AZURE_CLIENT_SECRETS=x\n", "not one of the Azure keys"},
		"duplicate key":  {validAzureSecrets + "AZURE_TENANT_ID=other\n", "AZURE_TENANT_ID is defined more than once"},
		"empty value":    {strings.Replace(validAzureSecrets, "secret-value-abc", "", 1), "AZURE_CLIENT_SECRET has an empty value"},
		"quoted value":   {strings.Replace(validAzureSecrets, "secret-value-abc", `"quoted"`, 1), "AZURE_CLIENT_SECRET has an empty value or characters"},
		"malformed line": {validAzureSecrets + "no-equals-here\n", "is not one of the Azure keys"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadAzureSecrets(writeSecretsFile(t, tc.body))
			if err == nil {
				t.Fatal("bad file accepted")
			}
			if !strings.Contains(err.Error(), tc.wantMention) {
				t.Errorf("error %q does not name %q", err, tc.wantMention)
			}
			if strings.Contains(err.Error(), "secret-value-abc") {
				t.Errorf("error leaks a secret value: %v", err)
			}
		})
	}
}

func TestLoadAzureSecrets_MissingFileNamesSetting(t *testing.T) {
	_, err := loadAzureSecrets(filepath.Join(t.TempDir(), "absent.env"))
	if err == nil || !strings.Contains(err.Error(), cloudAzureSecretsFileEnv) {
		t.Fatalf("err = %v, want one naming %s", err, cloudAzureSecretsFileEnv)
	}
}

func TestCloudDiscoveryGate_OnePassPerAccount(t *testing.T) {
	g := newCloudDiscoveryGate(4, 8, time.Second)
	release, err := g.Acquire(context.Background(), acct("111111111111"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Acquire(context.Background(), acct("111111111111")); !errors.Is(err, errCloudAccountBusy) {
		t.Fatalf("second pass for the same account: err = %v, want busy", err)
	}
	if discoveryStatusCode(errCloudAccountBusy) != http.StatusConflict {
		t.Errorf("busy must map to 409")
	}
	release()
	if _, err := g.Acquire(context.Background(), acct("111111111111")); err != nil {
		t.Errorf("account not released after release(): %v", err)
	}
}

func TestCloudDiscoveryGate_ServerLimitAndQueueBound(t *testing.T) {
	g := newCloudDiscoveryGate(1, 0, time.Second)
	release, err := g.Acquire(context.Background(), acct("111111111111"))
	if err != nil {
		t.Fatal(err)
	}
	// One slot, zero queue: a second account is refused at once, not queued.
	start := time.Now()
	if _, err := g.Acquire(context.Background(), acct("222222222222")); !errors.Is(err, errCloudServerSaturated) {
		t.Fatalf("err = %v, want saturated", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Error("a full queue must refuse immediately")
	}
	if discoveryStatusCode(errCloudServerSaturated) != http.StatusServiceUnavailable {
		t.Errorf("saturated must map to 503")
	}
	release()
}

func TestCloudDiscoveryGate_QueuedWaitTimesOut(t *testing.T) {
	g := newCloudDiscoveryGate(1, 4, 50*time.Millisecond)
	release, err := g.Acquire(context.Background(), acct("111111111111"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := g.Acquire(context.Background(), acct("222222222222")); !errors.Is(err, errCloudServerSaturated) {
		t.Fatalf("err = %v, want saturated after the queue wait", err)
	}
	// The timed-out request must not stay counted as queued.
	g.mu.Lock()
	queued := g.queued
	g.mu.Unlock()
	if queued != 0 {
		t.Errorf("queued = %d after timeout, want 0", queued)
	}
}

func TestCloudDiscoveryGate_QueuedRequestHonoursCancel(t *testing.T) {
	g := newCloudDiscoveryGate(1, 4, time.Minute)
	release, err := g.Acquire(context.Background(), acct("111111111111"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Acquire(ctx, acct("222222222222")); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestCloudMetrics_LabelsStayBounded(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := observability.NewCloudMetrics(reg)
	m.DiscoveryFailures.WithLabelValues("aws", "permission").Inc()
	m.Refusals.WithLabelValues("allow-list").Inc()

	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) == 0 {
		t.Fatal("no metric families registered")
	}
	for _, fam := range families {
		for _, metric := range fam.GetMetric() {
			for _, lp := range metric.GetLabel() {
				name := lp.GetName()
				if strings.Contains(name, "account") || strings.Contains(name, "identity") || strings.Contains(name, "resource") {
					t.Errorf("%s has an identifier label %q", fam.GetName(), name)
				}
			}
		}
	}
}

func TestCloudFailureCategory_IsBounded(t *testing.T) {
	cases := map[string]string{
		"access denied to bucket":                       "permission",
		"credentials resolve to account 999, run names": "account-mismatch",
		"HTTP 429 Too Many Requests":                    "throttled",
		"something unexpected":                          "other",
	}
	for msg, want := range cases {
		if got := cloudFailureCategory(errors.New(msg)); got != want {
			t.Errorf("category(%q) = %q, want %q", msg, got, want)
		}
	}
	if got := cloudFailureCategory(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("deadline = %q, want timeout", got)
	}
}
