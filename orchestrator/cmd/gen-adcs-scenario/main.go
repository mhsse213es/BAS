// Command gen-adcs-scenario writes scenarios/adcs-esc-template-exposure-audit.yaml from internal/adcsaudit.
// Usage (from orchestrator/): go run ./cmd/gen-adcs-scenario ../scenarios/adcs-esc-template-exposure-audit.yaml
// Re-sign the file afterwards with scripts/signer.go.
package main

import (
	"fmt"
	"os"

	"github.com/audspect/bas/internal/adcsaudit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-adcs-scenario <output.yaml>")
		os.Exit(2)
	}
	b, err := adcsaudit.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
}
