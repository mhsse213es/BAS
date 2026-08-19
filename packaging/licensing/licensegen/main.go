package main

// BAS Platform — License Generator
//
// Generates a cryptographically signed per-customer license file.
// Requires the RSA private key from packaging/licensing/keygen.sh.
//
// Usage (from repo root):
//   go run packaging/licensing/licensegen/main.go \
//     -customer "HDFC Bank" -id hdfc-001 -days 365 \
//     -key packaging/licensing/keys/private.pem
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
	"strings"
	"time"
)

type License struct {
	Customer   string   `json:"customer"`
	CustomerID string   `json:"customer_id"`
	IssuedAt   string   `json:"issued_at"`
	ExpiresAt  string   `json:"expires_at"`
	Features   []string `json:"features"`
	Signature  string   `json:"signature"`
}

func (l *License) payload() string {
	return fmt.Sprintf("%s|%s|%s|%s",
		l.CustomerID,
		l.IssuedAt,
		l.ExpiresAt,
		strings.Join(l.Features, ","),
	)
}

func main() {
	customer := flag.String("customer", "", "Customer display name (e.g. 'HDFC Bank')")
	customerID := flag.String("id", "", "Customer ID slug (e.g. 'hdfc-001') — used in signature")
	days := flag.Int("days", 365, "License validity in days from today")
	features := flag.String("features", "full", "Comma-separated feature list (e.g. 'full')")
	keyFile := flag.String("key", "packaging/licensing/keys/private.pem", "Path to RSA private key PEM")
	outFile := flag.String("out", "", "Output file path (default: <customer_id>.lic)")
	flag.Parse()

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

	now := time.Now().UTC()
	lic := License{
		Customer:   *customer,
		CustomerID: *customerID,
		IssuedAt:   now.Format("2006-01-02"),
		ExpiresAt:  now.AddDate(0, 0, *days).Format("2006-01-02"),
		Features:   strings.Split(*features, ","),
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
		outPath = *customerID + ".lic"
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
