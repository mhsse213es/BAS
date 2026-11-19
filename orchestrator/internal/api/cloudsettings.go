package api

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/observability"
)

// Environment names for the cloud settings. They are read once, at startup.
// Credentials are not read from the environment at all; see loadAzureSecrets.
const (
	cloudAllowedAccountsEnv        = "CLOUD_ALLOWED_ACCOUNTS"
	cloudAzureSecretsFileEnv       = "CLOUD_AZURE_SECRETS_FILE"
	cloudDiscoveryMaxConcurrentEnv = "CLOUD_DISCOVERY_MAX_CONCURRENT"
	cloudDiscoveryMaxQueuedEnv     = "CLOUD_DISCOVERY_MAX_QUEUED"
	cloudDiscoveryQueueWaitEnv     = "CLOUD_DISCOVERY_QUEUE_WAIT"
)

// errCloudAccountNotAllowed refuses a request that names an account the server
// has not allow-listed. It is returned before any provider is contacted.
var errCloudAccountNotAllowed = errors.New("account is not on the server's cloud allow-list")

// azureSecretKeys are the only keys the Azure secrets file may define. Any other
// key is an error, so a misspelt name cannot silently fail to load.
var azureSecretKeys = []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID"}

// CloudSettings is the server's cloud configuration. LoadCloudSettings builds it
// once at startup and validates it, so a misconfiguration stops the server with a
// named cause. The zero value permits nothing and refuses all cloud work.
type CloudSettings struct {
	allow   cloudgraph.AccountAllowList
	azure   *cloudgraph.AzureDiscoveryConfig // nil unless Azure accounts are allow-listed
	gate    *cloudDiscoveryGate
	metrics *observability.CloudMetrics
}

// LoadCloudSettings reads and validates the cloud settings. Any error should stop
// startup. Error text names the setting or key at fault, never a value.
func LoadCloudSettings(metrics *observability.CloudMetrics) (*CloudSettings, error) {
	if os.Getenv("AZURE_CLIENT_SECRET") != "" {
		return nil, errors.New("AZURE_CLIENT_SECRET is set in the process environment; secrets are not accepted there. Move the Azure credentials to the file named by " + cloudAzureSecretsFileEnv)
	}
	allow, err := cloudgraph.ParseAccountAllowList(os.Getenv(cloudAllowedAccountsEnv))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cloudAllowedAccountsEnv, err)
	}
	maxConcurrent, err := intEnv(cloudDiscoveryMaxConcurrentEnv, 4, 1, 64)
	if err != nil {
		return nil, err
	}
	maxQueued, err := intEnv(cloudDiscoveryMaxQueuedEnv, 8, 0, 256)
	if err != nil {
		return nil, err
	}
	queueWait, err := durationEnv(cloudDiscoveryQueueWaitEnv, 10*time.Second)
	if err != nil {
		return nil, err
	}

	s := &CloudSettings{
		allow:   allow,
		gate:    newCloudDiscoveryGate(maxConcurrent, maxQueued, queueWait),
		metrics: metrics,
	}
	if azureAccounts := allow.Accounts("azure"); len(azureAccounts) > 0 {
		cfg, err := loadAzureSecrets(os.Getenv(cloudAzureSecretsFileEnv))
		if err != nil {
			return nil, fmt.Errorf("azure accounts are allow-listed but their credentials did not load: %w", err)
		}
		for _, acct := range azureAccounts {
			if acct != cfg.SubscriptionID {
				return nil, fmt.Errorf("%s lists azure account %s, but the Azure credentials are for subscription %s", cloudAllowedAccountsEnv, acct, cfg.SubscriptionID)
			}
		}
		s.azure = &cfg
	}
	return s, nil
}

// loadAzureSecrets reads the Azure service principal from a file. The file holds
// KEY=VALUE lines for the four keys in azureSecretKeys and nothing else. It must
// not be readable by group or others (checked on Unix; Windows ACLs are not
// checked here). Values are never included in errors.
func loadAzureSecrets(path string) (cloudgraph.AzureDiscoveryConfig, error) {
	var zero cloudgraph.AzureDiscoveryConfig
	if path == "" {
		return zero, fmt.Errorf("%s is not set", cloudAzureSecretsFileEnv)
	}
	info, err := os.Stat(path)
	if err != nil {
		return zero, fmt.Errorf("%s: cannot read the secrets file", cloudAzureSecretsFileEnv)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return zero, fmt.Errorf("%s: the secrets file must not be readable by group or others (mode 0600)", cloudAzureSecretsFileEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("%s: cannot read the secrets file", cloudAzureSecretsFileEnv)
	}

	values := map[string]string{}
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !containsString(azureSecretKeys, key) {
			return zero, fmt.Errorf("%s: line %d is not one of the Azure keys", cloudAzureSecretsFileEnv, n+1)
		}
		if _, dup := values[key]; dup {
			return zero, fmt.Errorf("%s: %s is defined more than once", cloudAzureSecretsFileEnv, key)
		}
		if value == "" || strings.ContainsAny(value, "\"'\\") || value != strings.TrimSpace(value) {
			return zero, fmt.Errorf("%s: %s has an empty value or characters that are not allowed", cloudAzureSecretsFileEnv, key)
		}
		values[key] = value
	}
	for _, key := range azureSecretKeys {
		if values[key] == "" {
			return zero, fmt.Errorf("%s: %s is missing", cloudAzureSecretsFileEnv, key)
		}
	}
	return cloudgraph.AzureDiscoveryConfig{
		TenantID:       values["AZURE_TENANT_ID"],
		ClientID:       values["AZURE_CLIENT_ID"],
		ClientSecret:   values["AZURE_CLIENT_SECRET"],
		SubscriptionID: values["AZURE_SUBSCRIPTION_ID"],
	}, nil
}

// permitAccount is the allow-list check every cloud request makes before it
// contacts a provider. It fails closed: a nil or zero settings value permits nothing.
func (s *CloudSettings) permitAccount(account cloudgraph.AccountScope) error {
	if s == nil || !s.allow.Permits(account.Provider, account.AccountID) {
		return errCloudAccountNotAllowed
	}
	return nil
}

// recordRefusal counts a refusal. It is telemetry; the audit record is separate.
func (s *CloudSettings) recordRefusal(reason string) {
	if s != nil && s.metrics != nil {
		s.metrics.Refusals.WithLabelValues(reason).Inc()
	}
}

// cloudSettings returns the handler's settings, or the fail-closed zero value.
func (h *Handler) cloudSettings() *CloudSettings {
	if h.cloud == nil {
		return &CloudSettings{}
	}
	return h.cloud
}

// WithCloudSettings installs validated settings. cmd/server calls it once at startup.
func (h *Handler) WithCloudSettings(s *CloudSettings) *Handler {
	h.cloud = s
	return h
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func intEnv(name string, def, min, max int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < min || v > max {
		return 0, fmt.Errorf("%s must be an integer from %d to %d", name, min, max)
	}
	return v, nil
}

func durationEnv(name string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > 5*time.Minute {
		return 0, fmt.Errorf("%s must be a duration above 0 and at most 5m", name)
	}
	return d, nil
}
