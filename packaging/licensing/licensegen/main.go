package main

// BAS Platform — License Generator
//
// Generates a cryptographically signed per-customer license file.
// Requires the RSA private key from packaging/licensing/keygen.sh.
//
// Usage (from repo root):
//   go run packaging/licensing/licensegen/main.go \
//     -customer "HDFC Bank" -id hdfc-001 -days 365 \
//     -key packaging/licensing/keys/private.pem [-tier Core] [-addons aleef]
//
// Output: hdfc-001.lic  (send this to the customer along with the platform package)

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type License struct {
	Customer   string   `json:"customer"`
	CustomerID string   `json:"customer_id"`
	IssuedAt   string   `json:"issued_at"`
	ExpiresAt  string   `json:"expires_at"`
	Features   []string `json:"features"`
	Tier       string   `json:"tier,omitempty"`
	Signature  string   `json:"signature"`
}

func (l *License) payload() string {
	p := fmt.Sprintf("%s|%s|%s|%s",
		l.CustomerID,
		l.IssuedAt,
		l.ExpiresAt,
		strings.Join(l.Features, ","),
	)
	if l.Tier != "" {
		p += "|tier=" + l.Tier
	}
	return p
}

func main() {
	customer := flag.String("customer", "", "Customer display name (e.g. 'HDFC Bank')")
	customerID := flag.String("id", "", "Customer ID slug (e.g. 'hdfc-001') — used in signature")
	days := flag.Int("days", 365, "License validity in days from today")
	features := flag.String("features", "full", "Comma-separated feature list (e.g. 'full')")
	addons := flag.String("addons", "", "Comma-separated add-on products sold outside the tiers (recognised: aleef). Appends addon:<name> tokens to the signed features")
	tier := flag.String("tier", "", "Licence tier: Core, Advanced or Enterprise. Empty issues a pre-tier licence, which keeps everything (Enterprise)")
	keyFile := flag.String("key", "packaging/licensing/keys/private.pem", "Path to RSA private key PEM")
	outFile := flag.String("out", "", "Output file path (default: <customer>-<tier>-<number>.lic, e.g. hdfc-enterprise-001.lic)")
	nameOnly := flag.Bool("name-only", false, "Print the default licence file name for -id and -tier and exit (no key needed)")
	flag.Parse()

	if *nameOnly {
		if *customerID == "" {
			fmt.Fprintln(os.Stderr, "Error: -id is required")
			os.Exit(1)
		}
		fmt.Println(licenseFileName(*customerID, *tier))
		return
	}

	if *customer == "" || *customerID == "" {
		fmt.Fprintln(os.Stderr, "Error: -customer and -id are required")
		flag.Usage()
		os.Exit(1)
	}

	rsaKey, err := loadPrivateKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
		os.Exit(1)
	}

	switch *tier {
	case "", "Core", "Advanced", "Enterprise":
	default:
		fmt.Fprintf(os.Stderr, "unknown tier %q: use Core, Advanced or Enterprise\n", *tier)
		os.Exit(1)
	}
	feats, err := buildFeatures(*features, *addons)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	now := time.Now().UTC()
	lic := License{
		Customer:   *customer,
		CustomerID: *customerID,
		IssuedAt:   now.Format("2006-01-02"),
		ExpiresAt:  now.AddDate(0, 0, *days).Format("2006-01-02"),
		Features:   feats,
		Tier:       *tier,
	}

	hash := sha256.Sum256([]byte(lic.payload()))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
		os.Exit(1)
	}
	lic.Signature = base64.StdEncoding.EncodeToString(sigBytes)

	out, _ := json.MarshalIndent(lic, "", "  ")

	outPath := *outFile
	if outPath == "" {
		outPath = licenseFileName(*customerID, *tier)
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing license: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] License: %s\n", outPath)
	fmt.Printf("    Customer:  %s (%s)\n", lic.Customer, lic.CustomerID)
	fmt.Printf("    Issued:    %s\n", lic.IssuedAt)
	fmt.Printf("    Expires:   %s\n", lic.ExpiresAt)
	fmt.Printf("    Features:  %s\n", strings.Join(lic.Features, ", "))
	fmt.Printf("\n    Delivery instructions for client:\n")
	fmt.Printf("    1. Send %s as-is -- do not rename it\n", outPath)
	fmt.Printf("    2. Install: set LIC_PATH=/path/to/%s in setup.conf\n", outPath)
	fmt.Printf("       (install.sh derives LICENSE_FILE=%s in .env automatically --\n", outPath)
	fmt.Printf("       no bas.lic rename anywhere in the stack)\n")
}

// recognisedAddons must match the add-on allowlist in orchestrator/internal/license (addonProducts).
var recognisedAddons = map[string]bool{"aleef": true}

// buildFeatures returns the feature list to sign: the base features in the order given, then one
// "addon:<name>" token per requested add-on, sorted and de-duplicated. An unrecognised add-on is an
// error. The payload format is unchanged: add-ons are ordinary entries of the signed Features list.
func buildFeatures(features, addons string) ([]string, error) {
	out := strings.Split(features, ",")
	seen := map[string]bool{}
	var tokens []string
	for _, a := range strings.Split(addons, ",") {
		if a == "" {
			continue
		}
		if !recognisedAddons[a] {
			return nil, fmt.Errorf("unknown add-on %q (recognised: aleef)", a)
		}
		if !seen[a] {
			seen[a] = true
			tokens = append(tokens, "addon:"+a)
		}
	}
	sort.Strings(tokens)
	return append(out, tokens...), nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in %s", path)
	}
	// Try PKCS8 first (openssl genrsa default output), then PKCS1
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("key in %s is not RSA", path)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// environmentWords are dropped from a customer ID when it is turned into a file name, so "hdfc-prod-001" becomes
// "hdfc-<tier>-001": the tier replaces the environment word.
var environmentWords = map[string]bool{"prod": true, "production": true, "dev": true, "test": true, "uat": true, "qa": true, "stage": true, "staging": true, "demo": true, "poc": true}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// licenseFileName is the default file name of an issued licence: <customer>-<tier>-<number>.lic, for example
// hdfc-enterprise-001.lic. The customer and number come from the customer ID (the signed ID inside the licence is
// unchanged), the tier from the licence tier. The name is only a label for people: nothing reads it back.
func licenseFileName(customerID, tier string) string {
	words := strings.Split(strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(customerID), "-"), "-"), "-")
	number := ""
	if n := len(words); n > 0 && words[n-1] != "" && strings.Trim(words[n-1], "0123456789") == "" {
		number, words = words[n-1], words[:n-1]
	}
	var org []string
	for _, w := range words {
		if w != "" && !environmentWords[w] {
			org = append(org, w)
		}
	}
	if len(org) == 0 { // only environment words (or nothing): keep what there is
		for _, w := range words {
			if w != "" {
				org = append(org, w)
			}
		}
	}
	if len(org) == 0 {
		org = []string{"license"}
	}
	parts := org
	if t := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(tier), "-"), "-"); t != "" {
		parts = append(parts, t)
	}
	if number != "" {
		parts = append(parts, number)
	}
	return strings.Join(parts, "-") + ".lic"
}
