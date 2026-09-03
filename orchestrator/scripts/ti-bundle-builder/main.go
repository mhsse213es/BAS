// Command ti-bundle-builder builds and writes a signed-ready ti-bundle.json
// for air-gapped delivery: an operator runs this on an internet-connected box
// against a live MISP and/or OpenCTI instance, then signs the output with
// scripts/signer.go and hand-carries both files into the client's
// TI_BUNDLE_DIR. See specs/2026-07-17-sp5-ti-bundle-builder-and-ui-design.md.
//
// Usage:
//
//	go run ./scripts/ti-bundle-builder -misp-url=https://misp.example -misp-key=... -version=2026.07.17
//	go run scripts/signer.go sign private_key.pem ti-bundle.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/audspect/bas/internal/connector"
)

func main() {
	mispURL := flag.String("misp-url", "", "MISP base URL")
	mispKey := flag.String("misp-key", "", "MISP API key")
	mispInsecureTLS := flag.Bool("misp-insecure-tls", false, "skip TLS verification against MISP (self-signed certs on air-gapped instances)")
	openctiURL := flag.String("opencti-url", "", "OpenCTI base URL")
	openctiKey := flag.String("opencti-key", "", "OpenCTI API key")
	sectors := flag.String("sectors", "", "comma-separated target sectors, e.g. financial-services,banking")
	regions := flag.String("regions", "", "comma-separated target regions (MISP only), e.g. Asia,India")
	version := flag.String("version", time.Now().UTC().Format("2006.01.02"), "bundle version string")
	out := flag.String("out", connector.BundleFileName, "output path")
	flag.Parse()

	var sources []connector.Source
	if *mispURL != "" && *mispKey != "" {
		sources = append(sources, connector.NewMISPClient(*mispURL, *mispKey, splitCSV(*sectors), splitCSV(*regions), *mispInsecureTLS))
		fmt.Printf("[+] MISP source: %s\n", *mispURL)
	}
	if *openctiURL != "" && *openctiKey != "" {
		sources = append(sources, connector.NewOpenCTIClient(*openctiURL, *openctiKey, splitCSV(*sectors)))
		fmt.Printf("[+] OpenCTI source: %s\n", *openctiURL)
	}
	if len(sources) == 0 {
		fmt.Println("no threat-intel source configured — set -misp-url/-misp-key or -opencti-url/-opencti-key")
		os.Exit(1)
	}

	bundle, err := connector.BuildBundle(sources, *version)
	if err != nil {
		fmt.Printf("build failed: %v\n", err)
		os.Exit(1)
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fmt.Printf("marshal failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0644); err != nil {
		fmt.Printf("write failed: %v\n", err)
		os.Exit(1)
	}

	techniques := 0
	for _, a := range bundle.Actors {
		techniques += len(a.Techniques)
	}
	fmt.Printf("[+] Wrote %s — %d actors, %d techniques, version %s\n", *out, len(bundle.Actors), techniques, bundle.Version)
	fmt.Printf("[+] Next: go run scripts/signer.go sign private_key.pem %s\n", *out)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
