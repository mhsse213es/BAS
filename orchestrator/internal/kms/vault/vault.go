// Package vault implements kms.Provider over HashiCorp Vault's transit secrets engine. The KEK is a transit key
// created with exportable=false; Vault performs every wrap and unwrap, so the key never leaves Vault.
//
// The provider refuses a transit key that is exportable: an exportable KEK would break the rule that a KEK never
// leaves the customer's provider.
package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/kms"
)

var keyNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Config is the provider's connection. Token is the Vault token; load it with LoadToken from a root-only file.
type Config struct {
	// Address is the Vault base URL, for example https://vault.customer.example:8200.
	Address string
	// Token authenticates to Vault. It is a secret: it is never logged and never returned by this package.
	Token string
	// MountPath is the transit mount. Default "transit".
	MountPath string
	// AllowPlainHTTP permits an http:// address. For tests and local development only; production must use https.
	AllowPlainHTTP bool
	// HTTPClient is optional. The default has a 10 second timeout.
	HTTPClient *http.Client
}

// Provider is a kms.Provider backed by Vault transit.
type Provider struct {
	base   string
	token  string
	mount  string
	client *http.Client
}

// LoadToken reads a Vault token from a file. The file holds the token on one line.
func LoadToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("vault: token file is not readable")
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("vault: token file is empty")
	}
	return t, nil
}

// New validates the configuration and returns a provider.
func New(cfg Config) (*Provider, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil || u.Host == "" {
		return nil, errors.New("vault: address must be an absolute URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !cfg.AllowPlainHTTP {
			return nil, errors.New("vault: plain http is refused; use https")
		}
	default:
		return nil, errors.New("vault: address must use https")
	}
	if cfg.Token == "" {
		return nil, errors.New("vault: a token is required")
	}
	mount := cfg.MountPath
	if mount == "" {
		mount = "transit"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Provider{base: strings.TrimRight(cfg.Address, "/"), token: cfg.Token, mount: mount, client: client}, nil
}

// Name implements kms.Provider.
func (p *Provider) Name() string { return "vault-transit" }

// WrapDEK implements kms.Provider.
func (p *Provider) WrapDEK(ctx context.Context, ref kms.KeyRef, dek []byte) ([]byte, error) {
	if err := checkRef(ref); err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}
	if err := p.post(ctx, "encrypt", ref, body, &out); err != nil {
		return nil, err
	}
	if out.Data.Ciphertext == "" {
		return nil, errors.New("vault: encrypt returned no ciphertext")
	}
	return []byte(out.Data.Ciphertext), nil
}

// UnwrapDEK implements kms.Provider.
func (p *Provider) UnwrapDEK(ctx context.Context, ref kms.KeyRef, wrapped []byte) ([]byte, error) {
	if err := checkRef(ref); err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	body := map[string]string{"ciphertext": string(wrapped)}
	if err := p.post(ctx, "decrypt", ref, body, &out); err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, errors.New("vault: decrypt returned malformed plaintext")
	}
	return dek, nil
}

// Status implements kms.Provider. A missing key is reported as revoked: a key that has been deleted is the
// customer's withdrawal of access. An exportable key is refused with an error, never reported as active.
func (p *Provider) Status(ctx context.Context, ref kms.KeyRef) (kms.Status, error) {
	if err := checkRef(ref); err != nil {
		return "", err
	}
	var out struct {
		Data struct {
			Exportable bool `json:"exportable"`
		} `json:"data"`
	}
	code, err := p.do(ctx, http.MethodGet, p.keyURL(ref), nil, &out)
	if err != nil {
		return "", fmt.Errorf("%w: %v", kms.ErrStatusUnknown, err)
	}
	switch {
	case code == http.StatusNotFound:
		return kms.StatusRevoked, nil
	case code != http.StatusOK:
		return "", fmt.Errorf("%w: vault returned status %d", kms.ErrStatusUnknown, code)
	case out.Data.Exportable:
		return "", errors.New("vault: transit key is exportable; refusing to use it as a KEK")
	}
	return kms.StatusActive, nil
}

func (p *Provider) keyURL(ref kms.KeyRef) string {
	return fmt.Sprintf("%s/v1/%s/keys/%s", p.base, url.PathEscape(p.mount), url.PathEscape(string(ref)))
}

func (p *Provider) post(ctx context.Context, op string, ref kms.KeyRef, body any, out any) error {
	u := fmt.Sprintf("%s/v1/%s/%s/%s", p.base, url.PathEscape(p.mount), op, url.PathEscape(string(ref)))
	code, err := p.do(ctx, http.MethodPost, u, body, out)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("vault: %s returned status %d", op, code)
	}
	return nil
}

func (p *Provider) do(ctx context.Context, method, u string, body any, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Vault-Token", p.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, errors.New("vault: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
			return resp.StatusCode, errors.New("vault: malformed response")
		}
	}
	return resp.StatusCode, nil
}

func checkRef(ref kms.KeyRef) error {
	if !keyNameRE.MatchString(string(ref)) {
		return errors.New("vault: key name must be 1 to 128 letters, digits, underscores or hyphens")
	}
	return nil
}
